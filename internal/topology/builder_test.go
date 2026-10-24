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
	if ai, bi := l.ports(a); l.conf != 50 || ai != 1 || bi != 3 {
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

/* Chassis ids are learned only from rows the other side confirmed. */
func TestChassisLearnedFromConfirmedRows(t *testing.T) {
	h := newHarness(t)
	a, _ := h.dev("a")
	b, bIP := h.dev("b")
	c, cIP := h.dev("c")
	/* c and b confirm each other; c's row teaches chassis X = b */
	h.nb(c, 1, "02:00:00:00:0b:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:0c:0c", "g1", "c", cIP)
	/* a sees only chassis X, under a name that matches nothing */
	h.nb(a, 1, "02:00:00:00:0B:0B", "g1", "something", "")
	h.build()
	l := h.one(a, b)
	if l.conf != 50 {
		t.Errorf("chassis-only confidence %d", l.conf)
	}
	if got := h.one(b, c); got.conf != 100 {
		t.Errorf("c-b %+v", got)
	}
	/* an unknown chassis matches nothing */
	h.nb(a, 2, "02:00:00:00:99:99", "g1", "other", "")
	h.build()
	if got := len(h.links()); got != 2 {
		t.Errorf("links %+v", h.links())
	}
}

/* corrobSetup: a (port 1) is cabled to b (port 3); o reports both ARP entries, and the two MAC tables learn each other. */
func corrobSetup(h *harness) (a, b, o int64, bIP string) {
	var aIP string
	a, aIP = h.dev("a")
	b, bIP = h.dev("b")
	o, _ = h.dev("o")
	h.exec(`INSERT INTO inventory.arp_entry (device_id, ip, mac, if_index, seen_at) VALUES
		($1, $2::inet, '02:aa:00:00:00:0a', 1, now()), ($1, $3::inet, '02:aa:00:00:00:0b', 1, now())`, o, aIP, bIP)
	h.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, '02:aa:00:00:00:0a', 1, 3, now())`, b)
	h.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, '02:aa:00:00:00:0b', 1, 1, now())`, a)
	return
}

/* A one-sided address claim is 0.5 until both devices' own MAC tables confirm the cable. */
func TestAddressClaimCorroboratedByBothTables(t *testing.T) {
	h := newHarness(t)
	a, b, _, bIP := corrobSetup(h)
	h.nb(a, 1, "02:00:00:00:00:0b", "g3", "b", bIP)
	h.build()
	if l := h.one(a, b); l.conf != 80 {
		t.Errorf("corroborated %+v", l)
	}
	/* an impostor on a:2 names the same b port: a:2 is not where b's MAC is learned, and the claim on b:g3 is now contested */
	h.nb(a, 2, "02:00:00:00:66:66", "g3", "x", bIP)
	h.build()
	for _, l := range h.between(a, b) {
		if l.conf > 50 {
			t.Errorf("contested claim above 0.5: %+v", l)
		}
	}
	/* the impostor gone: the genuine row is trusted again */
	h.dropNb(a)
	h.nb(a, 1, "02:00:00:00:00:0b", "g3", "b", bIP)
	h.build()
	for _, l := range h.between(a, b) {
		if l.ai == 1 && l.conf != 80 {
			t.Errorf("genuine alone %+v", l)
		}
	}
}

/* Multi-hop: b's table learns a on its uplink port, and a's port 2 also learns another known device behind it: a claim naming that uplink gets nothing. */
func TestSharedSegmentDoesNotCorroborate(t *testing.T) {
	h := newHarness(t)
	a, b, o, bIP := corrobSetup(h)
	d, dIP := h.dev("d")
	h.exec(`INSERT INTO inventory.arp_entry (device_id, ip, mac, if_index, seen_at) VALUES ($1, $2::inet, '02:aa:00:00:00:0d', 1, now())`, o, dIP)
	h.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, '02:aa:00:00:00:0d', 1, 1, now())`, a)
	/* a's port 1 now learns b and d: a shared segment */
	h.nb(a, 1, "02:00:00:00:00:0b", "g3", "b", bIP)
	h.build()
	if l := h.one(a, b); l.conf != 50 {
		t.Errorf("shared segment %+v", l)
	}
	_ = d
}

/* An impostor announcing another device's address with b's chassis cannot poison or teach chassis ids. */
func TestUnconfirmedRowsDoNotPoisonChassis(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	d, dIP := h.dev("d")
	z, _ := h.dev("z")
	/* b and a confirm each other: chassis X belongs to b */
	h.nb(a, 1, "02:00:00:00:0b:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:0a:0a", "g1", "a", aIP)
	/* an impostor on a:3 announces d's address with chassis X */
	h.nb(a, 3, "02:00:00:00:0b:0b", "g1", "imp", dIP)
	/* z sees chassis X without an address */
	h.nb(z, 1, "02:00:00:00:0b:0b", "g1", "n/a", "")
	h.build()
	for _, l := range h.links() {
		if l.a == d || l.b == d {
			t.Errorf("impostor linked to d: %+v", l)
		}
	}
	if l := h.one(a, b); l.conf != 100 {
		t.Errorf("genuine link %+v", l)
	}
	if l := h.one(z, b); l.conf != 50 {
		t.Errorf("chassis still resolves to b: %+v", l)
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

/* An automatic link that a person then draws by hand is replaced by the manual one, with a disappearance record. */
func TestManualSupersedesExistingAutomatic(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, 1, $2, NULL, 'manual', 1, true)`, a, b)
	h.build()
	if l := h.one(a, b); !l.manual {
		t.Errorf("%+v", l)
	}
	if ap, di := h.changes(a, b); ap != 1 || di != 1 {
		t.Errorf("changes %d %d", ap, di)
	}
}

/* A manual link with unknown ports is a wildcard only for a pair with one automatic link; parallel cables are not hidden. */
func TestManualWildcardDoesNotHideParallelLinks(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.exec(`INSERT INTO core.link (a_device_id, a_if_index, b_device_id, b_if_index, source, confidence, manual) VALUES ($1, NULL, $2, NULL, 'manual', 1, true)`, a, b)
	h.nb(a, 1, "02:00:00:00:00:0b", "g1", "b", bIP)
	h.nb(b, 1, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	if got := len(h.between(a, b)); got != 1 {
		t.Fatalf("single cable not suppressed: %+v", h.links())
	}
	h.nb(a, 2, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g2", "a", aIP)
	h.build()
	if got := len(h.between(a, b)); got != 3 {
		t.Errorf("parallel cables hidden: %+v", h.links())
	}
}

/* Misses count inventory refreshes, not builds. */
func TestNoMissesWithoutNewInventory(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.nb(a, 1, "02:00:00:00:00:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.build()
	h.dropNb(a)
	h.dropNb(b)
	h.refresh()
	h.buildStale() /* the one refresh counts once */
	for i := 0; i < 6; i++ {
		h.buildStale()
	}
	if l := h.one(a, b); l.misses != 1 {
		t.Fatalf("misses %d after builds without a poll", l.misses)
	}
	h.build()
	h.build()
	if got := len(h.between(a, b)); got != 0 {
		t.Errorf("not gone after three refreshed inventories: %+v", h.links())
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
	arp(other, swIP, "02:aa:00:00:00:02")
	arp(other, coreIP, "02:aa:00:00:00:01")
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

/* A device's own ARP table cannot define the MAC another device is recognised by. */
func TestMACInferenceIgnoresEndsOwnARP(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	h.exec(`INSERT INTO inventory.arp_entry (device_id, ip, mac, if_index, seen_at) VALUES ($1, $2::inet, '02:dd:00:00:00:01', 1, now()), ($3, $4::inet, '02:dd:00:00:00:02', 1, now())`, a, bIP, b, aIP)
	h.exec(`INSERT INTO inventory.mac_entry (device_id, mac, vlan, if_index, seen_at) VALUES ($1, '02:dd:00:00:00:01', 1, 1, now()), ($2, '02:dd:00:00:00:02', 1, 1, now())`, a, b)
	h.build()
	if got := len(h.links()); got != 0 {
		t.Errorf("links %+v", h.links())
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

/* Two mutual pairs announcing one chassis make it contested: it matches nobody. */
func TestContestedChassisMatchesNobody(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	c, cIP := h.dev("c")
	d, dIP := h.dev("d")
	z, _ := h.dev("z")
	h.nb(a, 1, "02:00:00:00:0b:0b", "g2", "b", bIP)
	h.nb(b, 2, "02:00:00:00:0a:0a", "g1", "a", aIP)
	h.nb(c, 1, "02:00:00:00:0b:0b", "g2", "d", dIP)
	h.nb(d, 2, "02:00:00:00:0c:0c", "g1", "c", cIP)
	h.nb(z, 1, "02:00:00:00:0b:0b", "g1", "n/a", "")
	h.build()
	for _, l := range h.links() {
		if l.a == z || l.b == z {
			t.Errorf("contested chassis matched: %+v", l)
		}
	}
	if len(h.links()) != 2 {
		t.Errorf("links %+v", h.links())
	}
	_, _ = b, d
}

/* A flood on one port does not push out genuine rows on other ports. */
func TestFloodOnOnePortKeepsOtherPorts(t *testing.T) {
	h := newHarness(t)
	g, gIP := h.dev("g")
	h.exec(`INSERT INTO inventory.interface SELECT $1, i, 'g' || i, '', 1000000000, true, now() FROM generate_series(5, 12) i`, g)
	h.exec(`INSERT INTO inventory.lldp_neighbor (device_id, local_if_index, chassis_id, port_id, sys_name, mgmt_addr, seen_at)
		SELECT $1, 1, 'c' || i, 'p' || i, 'n/a', NULL, now() FROM generate_series(1, 500) i`, g)
	var peers []int64
	for p := 2; p <= 10; p++ {
		x, xIP := h.dev("peer")
		peers = append(peers, x)
		h.nb(g, p, "02:00:00:00:00:"+string(rune('a'+p)), "g1", "peer", xIP)
		h.nb(x, 1, "02:00:00:00:ff:"+string(rune('a'+p)), "g"+string(rune('0'+p%10)), "g", gIP)
	}
	h.build()
	for _, x := range peers {
		if len(h.between(g, x)) != 1 {
			t.Fatalf("link to %d lost: %+v", x, h.links())
		}
	}
	/* the flooded port is not used for MAC inference either */
	if len(h.links()) != len(peers) {
		t.Errorf("links %+v", h.links())
	}
}

/*
A reporter with a port table (some row resolved by name) is not trusted on a row
it could not resolve, even when the LLDP port number equals one of its ifIndexes;
a reporter without a port table keeps the number as the interface.
*/
func TestUnresolvedPortOfTabledReporterIsUnknown(t *testing.T) {
	h := newHarness(t)
	a, aIP := h.dev("a")
	b, bIP := h.dev("b")
	c, cIP := h.dev("c")
	d, dIP := h.dev("d")
	h.nb(a, 3, "02:00:00:00:00:0b", "g2", "b", bIP) /* unresolved; 3 is an interface of a only by coincidence */
	h.nb(b, 2, "02:00:00:00:00:0a", "port-99", "a", aIP)
	h.nb(a, 1, "02:00:00:00:00:0c", "g2", "c", cIP) /* resolved: a has a port table */
	h.nb(c, 2, "02:00:00:00:00:0a", "g1", "a", aIP)
	h.exec(`UPDATE inventory.lldp_neighbor SET local_port_resolved = true WHERE device_id = $1 AND local_if_index = 1`, a)
	/* control: d has no resolved row, its number 3 stays the interface */
	h.nb(d, 3, "02:00:00:00:00:0b", "g4", "b", bIP)
	h.nb(b, 4, "02:00:00:00:00:0d", "g3", "d", dIP)
	h.build()

	if ai, bi := h.one(a, b).ports(a); ai != 0 || bi != 2 {
		t.Errorf("a-b ports = %d, %d; want the unresolved end unknown (0) and 2", ai, bi)
	}
	if ai, ci := h.one(a, c).ports(a); ai != 1 || ci != 2 {
		t.Errorf("a-c ports = %d, %d; want 1, 2", ai, ci)
	}
	if di, bi := h.one(d, b).ports(d); di != 3 || bi != 4 {
		t.Errorf("d-b ports = %d, %d; want 3, 4", di, bi)
	}
}
