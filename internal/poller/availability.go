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
	icmpTimeout    = time.Second
	oidSysUpTime   = "1.3.6.1.2.1.1.3.0"
	oidSysObjID    = "1.3.6.1.2.1.1.2.0"
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	noProfileText  = "no usable SNMP credential"
	v2FallbackText = "snmpv3 profile rejected, using v2c"
	/* busyNoAnswerText: the session of the poll in progress has not answered within the interval. */
	busyNoAnswerText = "no SNMP answer during the poll in progress"
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
availability probes ICMP and SNMP and records the point and the device state.
ICMP runs without the device lock. For SNMP it takes the lock only if it is
free (lk nil: the caller holds it) and reads sysUpTime over its own session;
while another poll holds the device it opens no second session and counts
SNMP as answering when that poll's session answered within one availability
interval. Without the lock it reads only the atomic stamp of the cache. It
fails only when the result cannot be stored: an unreachable device is a
result, not an error.
*/
func (p *Poller) availability(ctx context.Context, d device, cache *devCache, lk *deviceLock) error {
	at := p.now()
	rtt, icmpOK := p.pinger.Ping(ctx, d.Addr.Addr())
	var (
		snmpOK bool
		reason string
	)
	if lk == nil || lk.TryLock() {
		if lk != nil {
			defer lk.Unlock()
		}
		p.refresh(d, cache)
		var err error
		if snmpOK, reason, err = p.snmpAlive(ctx, d, cache); err != nil {
			return err
		}
	} else {
		last := cache.lastSNMP.Load()
		snmpOK = last != 0 && p.now().Sub(time.Unix(0, last)) <= d.Intervals[classAvail]
		if !snmpOK {
			reason = busyNoAnswerText
		}
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
	if cache.v3Rejected {
		return true, v2FallbackText, nil
	}
	return true, "", nil
}
