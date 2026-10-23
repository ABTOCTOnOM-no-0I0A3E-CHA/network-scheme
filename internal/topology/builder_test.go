package topology_test

import (
	"testing"
)

func TestMutualConfirmation(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	res := h.build()
	if res.Appeared != 1 {
		t.Fatalf("result %+v", res)
	}
	l := h.one(a, b)
	if ai, bi := l.ports(a); l.conf != 100 || l.source != "lldp" || ai != 1 || bi != 2 {
		t.Errorf("link %+v", l)
	}
	/* a second build changes nothing */
	if res := h.build(); res.Appeared != 0 || res.Disappeared != 0 || res.Links != 1 {
		t.Errorf("second build %+v", res)
	}
	if ap, di := h.changes(a, b); ap != 1 || di != 0 {
		t.Errorf("changes %d %d", ap, di)
	}
}

func TestManagementAddressResolution(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	b, bIP := h.dev("b")
	/* one side, neighbour announces a management address of a known device and a port that is one of its interfaces */
	h.nb(a, 1, "02:00:00:00:00:0b", "g3", "whatever-the-box-calls-itself", bIP)
	h.build()
	l := h.one(a, b)
	if ai, bi := l.ports(a); l.conf != 80 || ai != 1 || bi != 3 {
		t.Errorf("link %+v", l)
	}
	/* an address of no known device matches nothing */
	c, _ := h.dev("c")
	h.nb(c, 1, "02:00:00:00:00:ff", "g1", "zzz", "192.0.2.77")
	h.build()
	if got := len(h.links()); got != 1 {
		t.Errorf("links %+v", h.links())
	}
}

func TestSysNameOnlyIsWeakAndAmbiguousNamesMatchNothing(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	b, _ := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g1", "b", "")
	h.build()
	if l := h.one(a, b); l.conf != 50 {
		t.Errorf("name-only confidence %d", l.conf)
	}
	h2 := newHarness(t)
	x, _ := h2.dev("x")
	h2.dev("dup")
	h2.dev("dup")
	h2.nb(x, 1, "02:00:00:00:00:01", "g1", "dup", "")
	h2.build()
	if got := len(h2.links()); got != 0 {
		t.Errorf("ambiguous name linked: %+v", h2.links())
	}
}

/* Chassis ids are learned only from what other devices report, matched by address. */
func TestChassisLearnedFromOthers(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	b, bIP := h.dev("b")
	c, _ := h.dev("c")
	/* c sees b by its address and chassis X */
	h.nb(c, 1, "02:00:00:00:0b:0b", "g1", "b", bIP)
	/* a sees only chassis X, under a name that matches nothing */
	h.nb(a, 1, "02:00:00:00:0B:0B", "g1", "something", "")
	h.build()
	l := h.one(a, b)
	if l.conf != 50 {
		t.Errorf("chassis-only confidence %d", l.conf)
	}
	if got := h.one(b, c); got.conf != 80 {
		t.Errorf("c-b %+v", got)
	}
	/* an unknown chassis matches nothing */
	h.nb(a, 2, "02:00:00:00:99:99", "g1", "other", "")
	h.build()
	if got := len(h.links()); got != 2 {
		t.Errorf("links %+v", h.links())
	}
}

/* A device cannot make itself known by claiming an identity: its own rows teach nothing about its chassis. */
func TestSelfClaimIsNotEvidence(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	b, _ := h.dev("b")
	s, sIP := h.dev("s")
	_ = s
	/* s tells a: I am chassis X with b's name. Nobody else ever reports X by address. */
	h.nb(a, 1, "02:00:00:00:0b:0b", "g1", "s-the-impostor", sIP)
	h.nb(s, 1, "02:00:00:00:0b:0b", "g1", "a", "") /* s claims the same chassis from its side */
	h.build()
	for _, l := range h.links() {
		if l.a == b || l.b == b {
			t.Fatalf("link to b from an impostor's claims: %+v", l)
		}
	}
}

/* Review Focus 1: a spoofer claiming another device's identity gets no strong link and no link to the wrong device. */
func TestSpoofedIdentity(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	c, _ := h.dev("c")
	/* a:1 is really b (mutual, ports agree); a:2 is an impostor calling itself b without an address */
	h.nb(a, 1, "02:00:00:00:0b:0b", "g3", "b", bIP)
	h.nb(b, 3, "02:00:00:00:0a:0a", "g1", "a", aIP)
	h.nb(a, 2, "02:00:00:00:66:66", "g9", "b", "")
	h.build()
	l := h.one(a, b)
	if ai, bi := l.ports(a); l.conf != 100 || ai != 1 || bi != 3 {
		t.Errorf("real link %+v", l)
	}
	if got := len(h.links()); got != 1 {
		t.Errorf("the impostor on a:2 produced a link: %+v", h.links())
	}

	/* The impostor on a device where the real b is not seen at all: capped at 0.5, never mutual, never to c. */
	h2 := newHarness(t)
	a2, _ := h2.dev("a")
	b2, _ := h2.dev("b")
	c2, _ := h2.dev("c")
	h2.nb(a2, 2, "02:00:00:00:66:66", "g9", "b", "")
	h2.nb(c2, 1, "02:00:00:00:66:66", "g9", "b", "") /* a second box with the same claims */
	h2.build()
	for _, l := range h2.links() {
		if l.conf > 50 {
			t.Errorf("spoofed link above 0.5: %+v", l)
		}
		if l.a == c2 && l.b == a2 || l.a == a2 && l.b == c2 {
			t.Errorf("link between the two reporters: %+v", l)
		}
	}
	_, _ = b2, c

	/* A chassis claimed for two devices by address is contested: it matches nobody by chassis. */
	h3 := newHarness(t)
	p, pIP := h3.dev("p")
	q, qIP := h3.dev("q")
	r, _ := h3.dev("r")
	z, _ := h3.dev("z")
	h3.nb(r, 1, "02:00:00:00:77:77", "g1", "p", pIP)
	h3.nb(r, 2, "02:00:00:00:77:77", "g1", "q", qIP) /* same chassis, other address: contested */
	h3.nb(z, 1, "02:00:00:00:77:77", "g1", "n/a", "")
	h3.build()
	for _, l := range h3.links() {
		if l.a == z || l.b == z {
			t.Errorf("contested chassis matched: %+v", l)
		}
	}
	_, _ = p, q
}

/* A row whose address and name point at different devices is dropped. */
func TestContradictoryRowIsDropped(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	h.dev("b")
	_, cIP := h.dev("c")
	h.nb(a, 1, "02:00:00:00:00:01", "g1", "b", cIP)
	h.build()
	if got := len(h.links()); got != 0 {
		t.Errorf("links %+v", h.links())
	}
}

/* Review Focus 2: a link survives two builds without confirmation and goes on the third; a confirmation resets the count. */
func TestDisappearanceAfterThreeMisses(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	set := func() {
		h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
		h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	}
	wipe := func() { h.dropNb(a); h.dropNb(b) }
	set()
	h.build()
	wipe()
	h.build()
	h.build()
	if l := h.one(a, b); l.misses != 2 {
		t.Fatalf("after two misses %+v", l)
	}
	set()
	h.build()
	if l := h.one(a, b); l.misses != 0 {
		t.Fatalf("not reset: %+v", l)
	}
	wipe()
	h.build()
	h.build()
	if got := len(h.between(a, b)); got != 1 {
		t.Fatalf("gone after two misses")
	}
	res := h.build()
	if got := len(h.between(a, b)); got != 0 || res.Disappeared != 1 {
		t.Fatalf("still there after three misses: %+v %+v", h.links(), res)
	}
	if ap, di := h.changes(a, b); ap != 1 || di != 1 {
		t.Errorf("changes appeared=%d disappeared=%d", ap, di)
	}
	/* it comes back as a new link */
	set()
	h.build()
	if ap, di := h.changes(a, b); ap != 2 || di != 1 {
		t.Errorf("changes appeared=%d disappeared=%d", ap, di)
	}
}

/* While both ends are unreachable the missing evidence says nothing. */
func TestNoMissesWhileEndsAreDown(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	h.dropNb(a)
	h.dropNb(b)
	for i := 0; i < 5; i++ {
		h.build(a, b)
	}
	if l := h.one(a, b); l.misses != 0 {
		t.Errorf("%+v", l)
	}
	/* one end up: the miss counts */
	for i := 0; i < 3; i++ {
		h.build(a)
	}
	if got := len(h.between(a, b)); got != 0 {
		t.Errorf("link kept: %+v", h.links())
	}
}

func TestManualLinkSurvivesAndSuppresses(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	c, _ := h.dev("c")
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, 1, $2, NULL, 'manual', 1, true)`, a, b)
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, 3, $2, 3, 'manual', 1, true)`, a, c)
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	for i := 0; i < 4; i++ {
		h.build()
	}
	ls := h.links()
	if len(ls) != 2 {
		t.Fatalf("links %+v", ls)
	}
	for _, l := range ls {
		if !l.manual || l.conf != 100 || l.misses != 0 {
			t.Errorf("manual link changed: %+v", l)
		}
	}
	if l := h.one(a, b); l.bi != 0 {
		t.Errorf("manual ports changed: %+v", l)
	}
	/* a link on other ports of the same pair is not suppressed */
	h.nb(a, 4, "02:00:00:00:00:0b", "g4", "b", bIP)
	h.nb(b, 4, "02:00:00:00:00:0a", "g4", "a", aIP)
	h.build()
	if got := len(h.between(a, b)); got != 2 {
		t.Errorf("links %+v", h.links())
	}
	/* an empty inventory for many builds never touches manual links */
	h.dropNb(a)
	h.dropNb(b)
	for i := 0; i < 5; i++ {
		h.build()
	}
	if ls := h.links(); len(ls) != 2 || !ls[0].manual || !ls[1].manual {
		t.Errorf("links %+v", ls)
	}
	/* the manual link gone: the automatic one appears */
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.exec(`DELETE FROM core.link WHERE manual AND b_device_id = $1`, b)
	h.build()
	if l := h.one(a, b); l.manual || l.conf != 100 {
		t.Errorf("%+v", l)
	}
}

/* An automatic link that a person then draws by hand is replaced by the manual one without a disappearance record. */
func TestManualSupersedesExistingAutomatic(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	h.exec(`DELETE FROM core.link`)
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, 1, $2, 2, 'manual', 1, true)`, a, b)
	h.build()
	if l := h.one(a, b); !l.manual {
		t.Errorf("%+v", l)
	}
	if ap, di := h.changes(a, b); ap != 1 || di != 0 {
		t.Errorf("changes %d %d", ap, di)
	}
}

func TestDeviceDeletionRemovesLinks(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	h.exec(`DELETE FROM core.device WHERE id = $1`, b)
	if got := len(h.links()); got != 0 {
		t.Errorf("links %+v", h.links())
	}
	h.build() /* the build over the remaining data does not fail and does not resurrect the link */
	if got := len(h.links()); got != 0 {
		t.Errorf("links %+v", h.links())
	}
}

/* A switch with hosts and an uplink: the two infrastructure devices are linked by MAC, hosts and busy ports are not. */
func TestMACInference(t *testing.T) {
	h := newHarness(t)
	core, coreIP := h.dev("core")
	sw, swIP := h.dev("sw")
	other, otherIP := h.dev("other")
	mac := func(dev int64, ifx int, m string) {
		h.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, $2::macaddr, $3, $3, now())`, dev, m, ifx)
	}
	arp := func(dev int64, ip, m string) {
		h.exec(`INSERT INTO inventory.arp_entry (device_id, ip, mac, if_index, seen_at) VALUES ($1, $2::inet, $3::macaddr, 1, now())`, dev, ip, m)
	}
	/* ARP tables of the core and a host teach the device MACs */
	arp(core, swIP, "02:aa:00:00:00:02")
	arp(sw, coreIP, "02:aa:00:00:00:01")
	arp(sw, otherIP, "02:aa:00:00:00:03")
	/* sw: uplink g1 sees the core; hosts on g2 and g3 */
	mac(sw, 1, "02:aa:00:00:00:01")
	mac(sw, 2, "02:bb:00:00:00:01")
	mac(sw, 2, "02:bb:00:00:00:02")
	mac(sw, 3, "02:bb:00:00:00:03")
	/* core: g5 sees sw (and a host behind it); g6 sees sw and other (a hub-like port) */
	mac(core, 5, "02:aa:00:00:00:02")
	mac(core, 5, "02:bb:00:00:00:01")
	mac(core, 6, "02:aa:00:00:00:02")
	mac(core, 6, "02:aa:00:00:00:03")
	h.exec(`INSERT INTO inventory.interface SELECT $1, x, 'g' || x, '', 1000000000, true, now() FROM generate_series(5, 6) x`, core)
	h.build()
	l := h.one(core, sw)
	if ci, si := l.ports(core); l.source != "mac" || l.conf != 40 || ci != 5 || si != 1 {
		t.Errorf("link %+v", l)
	}
	if got := len(h.links()); got != 1 {
		t.Errorf("links %+v", h.links())
	}
	_ = other
	/* a port with LLDP rows is not inferred from MACs */
	h.nb(sw, 1, "02:aa:00:00:00:01", "g5", "unknown-box", "")
	h.build()
	if l := h.one(core, sw); l.misses != 1 {
		t.Errorf("mac link still confirmed on an LLDP port: %+v", l)
	}
}

/* Conflicting ARP evidence (one address, two MACs) disables MAC inference for that device. */
func TestMACInferenceIgnoresConflictingARP(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	b, bIP := h.dev("b")
	h.exec(`INSERT INTO inventory.arp_entry (device_id, ip, mac, if_index, seen_at) VALUES ($1, $2::inet, '02:cc:00:00:00:01', 1, now()), ($1, $2::inet, '02:cc:00:00:00:02', 2, now())`, a, bIP)
	h.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, '02:cc:00:00:00:01', 1, 1, now())`, a)
	h.build()
	if got := len(h.links()); got != 0 {
		t.Errorf("links %+v", h.links())
	}
	_ = b
}

/* One cable is one link: a stored link with an unknown port is updated in place when the data names the port. */
func TestNullPortRowsAreReconciled(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, 1, $2, NULL, 'mac', 0.4, false)`, a, b)
	var id int64
	_ = h.root.QueryRow(h.ctx, `SELECT id FROM core.link`).Scan(&id)
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	l := h.one(a, b)
	if ai, bi := l.ports(a); l.id != id || ai != 1 || bi != 2 || l.conf != 100 || l.source != "lldp" {
		t.Errorf("not updated in place: %+v (was %d)", l, id)
	}
	if ap, di := h.changes(a, b); ap != 0 || di != 0 {
		t.Errorf("changes %d %d", ap, di)
	}
	/* both stored: the unspecific one goes, silently */
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, 1, $2, NULL, 'mac', 0.4, false)`, a, b)
	h.build()
	if l := h.one(a, b); l.id != id {
		t.Errorf("%+v", l)
	}
	if ap, di := h.changes(a, b); ap != 0 || di != 0 {
		t.Errorf("changes %d %d", ap, di)
	}
}
