package poller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/snmp"
)

const (
	icmpTimeout   = time.Second
	oidSysUpTime  = "1.3.6.1.2.1.1.3.0"
	oidSysObjID   = "1.3.6.1.2.1.1.2.0"
	oidSysDescr   = "1.3.6.1.2.1.1.1.0"
	noProfileText = "no usable SNMP credential"
)

// Pinger sends one ICMP echo request and reports the round trip.
type Pinger interface {
	Ping(ctx context.Context, addr netip.Addr) (rtt time.Duration, ok bool)
}

/*
ICMPPinger pings with unprivileged ICMP sockets (Linux: the process group must
be within net.ipv4.ping_group_range): one packet, 1 s timeout.
*/
type ICMPPinger struct{}

// Ping implements Pinger.
func (ICMPPinger) Ping(ctx context.Context, addr netip.Addr) (time.Duration, bool) {
	pg := probing.New("")
	pg.SetIPAddr(&net.IPAddr{IP: addr.Unmap().AsSlice()}) /* no name resolution */
	pg.SetPrivileged(false)
	pg.Count = 1
	pg.Timeout = icmpTimeout
	if err := pg.RunWithContext(ctx); err != nil {
		return 0, false
	}
	st := pg.Statistics()
	if st.PacketsRecv == 0 {
		return 0, false
	}
	return st.AvgRtt, true
}

/* availState: SNMP answering means up (ICMP may be filtered); ICMP alone is partial. */
func availState(icmp, snmpOK bool) string {
	switch {
	case snmpOK:
		return inventory.StateUp
	case icmp:
		return inventory.StatePartial
	default:
		return inventory.StateDown
	}
}

/* snmpBudget bounds one SNMP request including retries. */
func (p *Poller) snmpBudget() time.Duration {
	return p.cfg.SNMPTimeout*time.Duration(max(*p.cfg.SNMPRetries, 0)+1) + time.Second
}

/*
availability probes ICMP and SNMP sysUpTime and records the point and the
device state. It fails only when the result cannot be stored: an unreachable
device is a result, not an error.
*/
func (p *Poller) availability(ctx context.Context, d device, cache *devCache) error {
	at := p.now()
	rtt, icmpOK := p.pinger.Ping(ctx, d.Addr.Addr())
	snmpOK, reason, err := p.snmpAlive(ctx, d, cache)
	if err != nil {
		return err
	}
	state := availState(icmpOK, snmpOK)
	pt := metrics.AvailPoint{DeviceID: d.ID, TS: at, ICMPOk: icmpOK, SNMPOk: snmpOK, State: state}
	if icmpOK {
		ms := float64(rtt) / float64(time.Millisecond)
		pt.RTTms = &ms
	}
	return errors.Join(
		p.metrics.WriteAvailability(ctx, []metrics.AvailPoint{pt}),
		p.inv.SetStatus(ctx, d.ID, state, at, reason),
	)
}

/* snmpAlive reads sysUpTime; reason explains a failure. err is a database failure only. */
func (p *Poller) snmpAlive(ctx context.Context, d device, cache *devCache) (ok bool, reason string, err error) {
	r, closer, err := p.session(ctx, d, cache)
	if errors.Is(err, errNoProfile) {
		return false, noProfileText, nil
	}
	if err != nil {
		if isDBErr(err) {
			return false, "", err
		}
		return false, err.Error(), nil
	}
	defer func() { _ = closer.Close() }()
	gctx, cancel := context.WithTimeout(ctx, p.snmpBudget())
	defer cancel()
	vars, err := r.Get(gctx, oidSysUpTime)
	if err != nil {
		return false, err.Error(), nil
	}
	if len(vars) != 1 {
		return false, "sysUpTime missing", nil
	}
	if _, ok := snmp.AsUint64(vars[0]); !ok {
		return false, "sysUpTime missing", nil
	}
	return true, "", nil
}
