package eventd

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
)

func (h *harness) sources() *sources {
	return newSources(h.priv, h.pub, drivers.Default(), time.Now, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func (h *harness) reload(s *sources) {
	h.t.Helper()
	if err := s.reload(context.Background(), h.pool); err != nil {
		h.t.Fatal(err)
	}
}

func TestSourcesIdentifyByAddressOnly(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	h.community(a, goodCommunity)
	s := h.sources()
	h.reload(s)

	d, rel, ok := s.acquire(netip.MustParseAddr("127.0.0.2"))
	if !ok || d.id != a || !d.matchCommunity(goodCommunity) || d.matchCommunity("community-WRONG-0123") || d.matchCommunity("") {
		t.Fatalf("lookup/community check wrong: ok=%v", ok)
	}
	rel()
	for _, other := range []string{"127.0.0.3", "::ffff:127.0.0.3", "::1"} {
		if _, _, ok := s.acquire(netip.MustParseAddr(other)); ok {
			t.Errorf("%s resolved to a device", other)
		}
	}
	/* an IPv4-mapped peer address is the same device once unmapped (peerIP does that) */
	if ip := peerIP(&netAddr{"[::ffff:127.0.0.2]:1234"}); ip != netip.MustParseAddr("127.0.0.2") {
		t.Errorf("peerIP = %v", ip)
	}
}

type netAddr struct{ s string }

func (a *netAddr) Network() string { return "tcp" }
func (a *netAddr) String() string  { return a.s }

func TestSourcesRefuseSharedAddress(t *testing.T) {
	h := newHarness(t)
	h.device("127.0.0.2")
	if _, err := h.pg.Exec(context.Background(), `INSERT INTO core.device (name, address, snmp_port, group_id) VALUES ('twin', '127.0.0.2', 1161, $1)`, h.group); err != nil {
		t.Fatal(err)
	}
	solo := h.device("127.0.0.3")
	s := h.sources()
	h.reload(s)
	if _, _, ok := s.acquire(netip.MustParseAddr("127.0.0.2")); ok {
		t.Error("an address shared by two devices identifies one of them")
	}
	if d, rel, ok := s.acquire(netip.MustParseAddr("127.0.0.3")); !ok || d.id != solo {
		t.Error("the unambiguous device is lost")
	} else {
		rel()
	}
}

func TestSourcesRejectBadProfiles(t *testing.T) {
	h := newHarness(t)
	a, b, c, e := h.device("127.0.0.2"), h.device("127.0.0.3"), h.device("127.0.0.4"), h.device("127.0.0.5")
	/* a ciphertext sealed for another device, stored under a */
	foreign := credstest.Seal(h.pub, devices.Owner{Kind: devices.OwnerDevice, ID: b}, "snmp2c", map[string]string{"community": goodCommunity}, time.Now().Add(-time.Minute))
	h.rawProfile(a, "snmp2c", foreign, "pending")
	/* the poller refused this one */
	h.rawProfile(b, "snmp2c", credstest.Seal(h.pub, devices.Owner{Kind: devices.OwnerDevice, ID: b}, "snmp2c", map[string]string{"community": goodCommunity}, time.Now().Add(-time.Minute)), "mismatch")
	/* a weak community and garbage */
	h.community(c, "short")
	h.rawProfile(e, "snmp2c", []byte("not a sealed box"), "pending")
	s := h.sources()
	h.reload(s)
	for _, ip := range []string{"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"} {
		d, rel, ok := s.acquire(netip.MustParseAddr(ip))
		if !ok {
			t.Fatalf("%s: device missing", ip)
		}
		if d.matchCommunity(goodCommunity) || d.matchCommunity("short") || !d.community.IsZero() || d.v3 != nil {
			t.Errorf("%s: a rejected profile is usable", ip)
		}
		rel()
	}
}

func TestSourcesWipeReplacedAndRemovedSecrets(t *testing.T) {
	h := newHarness(t)
	a, b := h.device("127.0.0.2"), h.device("127.0.0.3")
	h.community(a, goodCommunity)
	h.v3(b, "user-b")
	s := h.sources()
	h.reload(s)
	da, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2"))
	rel()
	db, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.3"))
	rel()
	keep := db.v3
	if keep == nil {
		t.Fatal("no v3 state")
	}

	/* an unchanged reread keeps the same objects and their secrets */
	h.reload(s)
	if d, rel, _ := s.acquire(netip.MustParseAddr("127.0.0.2")); d != da {
		t.Error("unchanged device was rebuilt")
	} else {
		rel()
	}
	if da.wiped {
		t.Error("unchanged device was wiped")
	}

	/* a changed ciphertext replaces the device and wipes the old secret; a removed device is wiped */
	h.community(a, "another-community-0123")
	if _, err := h.pg.Exec(context.Background(), `DELETE FROM core.device WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	h.reload(s)
	if !da.wiped || !da.community.IsZero() {
		t.Error("replaced device kept its secret")
	}
	if !db.wiped || db.v3 != nil || keep.fullSP.AuthenticationPassphrase != "" || keep.fullSP.PrivacyPassphrase != "" || keep.full != nil {
		t.Error("removed device kept its USM secrets")
	}
	if d, rel, ok := s.acquire(netip.MustParseAddr("127.0.0.2")); !ok || d == da || !d.matchCommunity("another-community-0123") || d.matchCommunity(goodCommunity) {
		t.Error("new ciphertext not in force")
	} else {
		rel()
	}
	if _, _, ok := s.acquire(netip.MustParseAddr("127.0.0.3")); ok {
		t.Error("removed device still resolves")
	}
}

/* A ciphertext older than one this process accepted is refused (api could restore an old row). */
func TestSourcesRefuseRollbackOfCiphertext(t *testing.T) {
	h := newHarness(t)
	a := h.device("127.0.0.2")
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: a}
	seal := func(community string, age time.Duration) []byte {
		return credstest.Seal(h.pub, owner, "snmp2c", map[string]string{"community": community}, time.Now().Add(-age))
	}
	s := h.sources()
	check := func(step, want string) {
		t.Helper()
		h.reload(s)
		d, rel, ok := s.acquire(netip.MustParseAddr("127.0.0.2"))
		if !ok {
			t.Fatalf("%s: device missing", step)
		}
		defer rel()
		if want == "" {
			if !d.community.IsZero() {
				t.Errorf("%s: a credential is in force", step)
			}
		} else if !d.matchCommunity(want) {
			t.Errorf("%s: %q is not in force", step, want)
		}
	}
	h.rawProfile(a, "snmp2c", seal("community-v2-0123456", time.Hour), "pending")
	check("first", "community-v2-0123456")
	h.rawProfile(a, "snmp2c", seal("community-v1-0123456", 2*time.Hour), "ok") /* older, status reset to ok */
	check("rolled back", "")
	if s.rollbacks.Load() != 1 {
		t.Errorf("rollbacks = %d", s.rollbacks.Load())
	}
	h.rawProfile(a, "snmp2c", seal("community-v3-0123456", time.Minute), "pending")
	check("newer again", "community-v3-0123456")
}
