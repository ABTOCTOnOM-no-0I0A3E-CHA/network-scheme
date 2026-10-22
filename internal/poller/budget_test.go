package poller

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/events/trap"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* fakeReader answers the system group only; the fake driver needs nothing else. */
type fakeReader struct{}

func (fakeReader) Get(_ context.Context, oids ...string) ([]snmp.Var, error) {
	var out []snmp.Var
	for _, o := range oids {
		switch o {
		case oidSysObjID:
			out = append(out, snmp.Var{OID: o, Type: snmp.TypeOID, Value: "1.3.6.1.4.1.32473.7"})
		case oidSysDescr:
			out = append(out, snmp.Var{OID: o, Type: snmp.TypeOctetString, Value: []byte("fake")})
		default:
			out = append(out, snmp.Var{OID: o, Type: snmp.TypeTimeTicks, Value: uint64(100)})
		}
	}
	return out, nil
}
func (fakeReader) Walk(context.Context, string, func(snmp.Var) error) error { return nil }
func (fakeReader) BulkGet(ctx context.Context, oids []string) ([]snmp.Var, error) {
	return fakeReader{}.Get(ctx, oids...)
}

/* budgetDriver reports a configurable CPU load and records the inventory budget it was given. */
type budgetDriver struct {
	cpu       *float64
	skipHeavy *bool
}

func (budgetDriver) Name() string                          { return drivers.GenericName }
func (budgetDriver) Match(string, string) bool             { return true }
func (budgetDriver) Dialect() ssh.Dialect                  { return ssh.Dialect{} }
func (budgetDriver) MapTrap(trap.Trap) (trap.Mapped, bool) { return trap.Mapped{}, false }
func (budgetDriver) Identify(context.Context, snmp.Reader) (drivers.Identity, error) {
	return drivers.Identity{SysObjectID: "1.3.6.1.4.1.32473.7", Model: "fake"}, nil
}
func (b budgetDriver) Collect(context.Context, snmp.Reader) (drivers.Sample, error) {
	c := *b.cpu
	return drivers.Sample{SysUpTime: time.Hour, System: drivers.SysMetrics{CPUPct: &c}}, nil
}
func (b budgetDriver) Inventory(ctx context.Context, _ snmp.Reader, sh drivers.ShowRunner) (drivers.Inventory, error) {
	*b.skipHeavy = drivers.BudgetFrom(ctx).SkipHeavy
	if sh != nil {
		panic("no SSH profile, no dialect: no SSH session expected")
	}
	return drivers.NewInventory(), nil
}

func TestHeavyTablesSkippedWhenCPUHigh(t *testing.T) {
	h := newHarness(t, "")
	cpu, skip := 0.0, false
	p := New(h.config(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour}), Deps{
		Pool: h.env.Pool("nms_poller"), Priv: h.priv, Pub: h.pub, Pinger: fakePinger{ok: true},
		DialSNMP: func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			return fakeReader{}, io.NopCloser(nil), nil
		},
		Registry: drivers.NewRegistry(budgetDriver{cpu: &cpu, skipHeavy: &skip}),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	id := h.device(netip.MustParseAddrPort("198.51.100.150:161"))
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	h.profile(id, "snmp2c", credstest.Seal(h.pub, owner, "snmp2c", map[string]string{"community": "0123456789abcdef"}, time.Now()))
	ctx := context.Background()
	devs, err := p.loadDevices(ctx)
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices = %v, %v", devs, err)
	}
	cache := newDevCache()
	for _, c := range []struct {
		cpu  float64
		skip bool
	}{{95, true}, {80, false}, {81, true}, {10, false}} {
		cpu = c.cpu
		if err := p.run(ctx, devs[0], cache, classMetrics, nil); err != nil {
			t.Fatal(err)
		}
		if err := p.run(ctx, devs[0], cache, classInventory, nil); err != nil {
			t.Fatal(err)
		}
		if skip != c.skip {
			t.Fatalf("cpu %v%%: SkipHeavy = %v, want %v", c.cpu, skip, c.skip)
		}
	}
}
