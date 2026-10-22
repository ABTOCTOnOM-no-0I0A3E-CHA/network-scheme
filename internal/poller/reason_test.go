package poller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/snmp"
)

const (
	leakCommunity = "s3cr3t-community-0123456789"
	leakDevice    = "device says: enable password hunter2"
)

/* fixedReasons is every text availability may store as last_error. */
var fixedReasons = map[string]bool{
	"": true, noProfileText: true, v2FallbackText: true, busyNoAnswerText: true,
	timeoutText: true, authFailedText: true, canceledText: true, snmpFailedText: true, noUpTimeText: true,
}

func TestReasonTextIsFixed(t *testing.T) {
	leaky := []error{
		errors.New(leakCommunity + " " + leakDevice),
		fmt.Errorf("snmp: %w", errors.New(leakDevice)),
		fmt.Errorf("%w: %s", snmp.ErrAuth, leakCommunity+leakDevice),
		fmt.Errorf("%w: %v", snmp.ErrTimeout, leakDevice),
		fmt.Errorf("%w: %s", snmp.ErrNoSuchObject, leakDevice),
		fmt.Errorf("wrap: %w: %s", context.Canceled, leakDevice),
		fmt.Errorf("wrap: %w: %s", context.DeadlineExceeded, leakDevice),
		fmt.Errorf("snmp: unsupported auth protocol %q", leakCommunity),
	}
	for _, err := range leaky {
		got := reasonText(err)
		if !fixedReasons[got] {
			t.Errorf("reasonText(%q) = %q, not a fixed text", err, got)
		}
		if strings.Contains(got, leakCommunity) || strings.Contains(got, leakDevice) {
			t.Errorf("reasonText leaks error text: %q", got)
		}
	}
	want := map[error]string{
		snmp.ErrAuth: authFailedText, snmp.ErrTimeout: timeoutText, context.DeadlineExceeded: timeoutText,
		context.Canceled: canceledText, snmp.ErrNoSuchObject: noUpTimeText,
	}
	for err, text := range want {
		if got := reasonText(err); got != text {
			t.Errorf("reasonText(%v) = %q, want %q", err, got, text)
		}
	}
}

/* getErrReader answers Get with err. */
type getErrReader struct {
	stubReader
	err error
}

func (r getErrReader) Get(context.Context, ...string) ([]snmp.Var, error) { return nil, r.err }

/* TestAvailabilityStoresFixedReasons drives every failure path of snmpAlive and checks the stored last_error. */
func TestAvailabilityStoresFixedReasons(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Minute, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	id := h.device(netip.MustParseAddrPort("198.51.100.185:161"))
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	h.profile(id, "snmp2c", credstest.Seal(h.pub, owner, "snmp2c", map[string]string{"community": leakCommunity}, time.Now().Add(-time.Minute)))
	devs, err := p.loadDevices(ctx)
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices = %v, %v", devs, err)
	}
	leak := errors.New(leakCommunity + " " + leakDevice)
	cases := []struct {
		name string
		dial DialFunc
		want string
	}{
		{"dial error", func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			return nil, nil, leak
		}, snmpFailedText},
		{"dial timeout", func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			return nil, nil, fmt.Errorf("%w: %v", snmp.ErrTimeout, leak)
		}, timeoutText},
		{"get error", func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			return getErrReader{err: leak}, nopCloser{}, nil
		}, snmpFailedText},
		{"get auth error", func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			return getErrReader{err: fmt.Errorf("%w: %v", snmp.ErrAuth, leak)}, nopCloser{}, nil
		}, authFailedText},
		{"get timeout", func(context.Context, netip.AddrPort, creds.Credential, snmp.Options) (snmp.Reader, io.Closer, error) {
			return getErrReader{err: fmt.Errorf("%w: %v", snmp.ErrTimeout, leak)}, nopCloser{}, nil
		}, timeoutText},
	}
	for _, tc := range cases {
		p.dial = tc.dial
		if err := p.run(ctx, devs[0], newDevCache(), classAvail, nil); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := h.str(`SELECT last_error FROM inventory.device_status WHERE device_id = $1`, id)
		if got != tc.want {
			t.Errorf("%s: last_error = %q, want %q", tc.name, got, tc.want)
		}
		if strings.Contains(got, leakCommunity) || strings.Contains(got, leakDevice) {
			t.Errorf("%s: last_error leaks: %q", tc.name, got)
		}
	}
}
