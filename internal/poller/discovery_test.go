package poller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

/* scanPinger answers ICMP for the addresses in ok, counts every probe and can hold probes of one address. */
type scanPinger struct {
	ok      map[netip.Addr]bool
	hold    netip.Addr
	release chan struct{}
	delay   time.Duration /* every probe takes this long (or until ctx ends) */
	panicAt netip.Addr
	mu      sync.Mutex
	pings   map[netip.Addr]int
	active  int
	peak    int
}

func newScanPinger(ok ...netip.Addr) *scanPinger {
	pg := &scanPinger{ok: map[netip.Addr]bool{}, pings: map[netip.Addr]int{}, release: make(chan struct{})}
	for _, a := range ok {
		pg.ok[a] = true
	}
	return pg
}

func (pg *scanPinger) Ping(ctx context.Context, a netip.Addr) (time.Duration, bool) {
	pg.mu.Lock()
	pg.pings[a]++
	pg.active++
	pg.peak = max(pg.peak, pg.active)
	pg.mu.Unlock()
	defer func() {
		pg.mu.Lock()
		pg.active--
		pg.mu.Unlock()
	}()
	if a == pg.panicAt {
		panic("hostile ping " + a.String())
	}
	if pg.delay > 0 {
		select {
		case <-time.After(pg.delay):
		case <-ctx.Done():
			return 0, false
		}
	}
	if a == pg.hold {
		select {
		case <-pg.release:
		case <-ctx.Done():
			return 0, false
		}
	}
	return time.Millisecond, pg.ok[a]
}

func (pg *scanPinger) count(a netip.Addr) int {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	return pg.pings[a]
}

/* scanDialer sends SNMP for scanned addresses to the simulator (others to a silent port) and records every credential used. */
type scanDialer struct {
	sim   map[netip.Addr]netip.AddrPort
	mu    sync.Mutex
	dials map[netip.Addr]int
	used  map[string]int
	ports map[uint16]bool
	fail  bool /* record, then fail without sending anything */
}

func newScanDialer(sim map[netip.Addr]netip.AddrPort) *scanDialer {
	return &scanDialer{sim: sim, dials: map[netip.Addr]int{}, used: map[string]int{}, ports: map[uint16]bool{}}
}

func (d *scanDialer) dial(ctx context.Context, a netip.AddrPort, c creds.Credential, o snmp.Options) (snmp.Reader, io.Closer, error) {
	d.mu.Lock()
	d.dials[a.Addr()]++
	d.ports[a.Port()] = true
	d.used[c.Kind+":"+c.User+":"+c.AuthKey.Reveal()+":"+c.Community.Reveal()]++
	d.mu.Unlock()
	if d.fail {
		return nil, nil, errors.New("test: no SNMP agent")
	}
	o.ContextName = "eltex-mes" /* simulator only: snmpsim picks the .snmprec by v3 context name */
	to, ok := d.sim[a.Addr()]
	if !ok {
		to = netip.MustParseAddrPort("127.0.0.1:9") /* nothing answers SNMP there */
	}
	return snmp.Dial(ctx, to, c, o)
}

func (d *scanDialer) count(a netip.Addr) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[a]
}

func (d *scanDialer) credentials() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]int{}
	for k, v := range d.used {
		out[k] = v
	}
	return out
}

var scanNet atomic.Int64

/* nextScanPrefix returns a fresh /29 so that tests never share inbox addresses. */
func nextScanPrefix() netip.Prefix {
	n := scanNet.Add(1)
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 250, byte(n), 0}), 29)
}

func host(p netip.Prefix, i byte) netip.Addr {
	b := p.Addr().As4()
	b[3] += i
	return netip.AddrFrom4(b)
}

/* scan creates a scan of this harness's poller as nms_api. */
func (h *harness) scan(p netip.Prefix, enabled bool) int64 {
	h.t.Helper()
	var id int64
	if err := h.env.Pool("nms_api").QueryRow(context.Background(), `INSERT INTO core.discovery_scan (cidr, group_id, enabled, poller_id)
		VALUES ($1, $2, $3, $4) RETURNING id`, p, h.group, enabled, h.pollerID).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return id
}

/* sealV3 stores an snmp3 profile for owner: the simulator's user and privacy key with authKey. */
func (h *harness) sealV3(owner devices.Owner, authKey string) {
	h.t.Helper()
	sec := v3Secret(authKey)
	sec["priv_key"] = simtest.V3PrivKey
	ct := credstest.Seal(h.pub, owner, creds.KindSNMP3, sec, time.Now().Add(-time.Minute))
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error {
		return st.PutProfile(ctx, tx, owner, creds.KindSNMP3, ct, 1)
	})
}

/* runScan starts scan id outside the schedule and waits for the run to end. */
func runScan(p *Poller, id int64) error {
	ctx := context.Background()
	if err := p.startScan(ctx, ctx, id); err != nil {
		return err
	}
	p.disc.wg.Wait()
	return nil
}

func (h *harness) scanPoller(pg Pinger, d *scanDialer) *Poller {
	return New(h.config(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour}), Deps{
		Pool: h.env.Pool("nms_poller"), Priv: h.priv, Pub: h.pub, Pinger: pg, DialSNMP: d.dial,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

type found struct {
	Address             netip.Addr
	SysOID, Descr, Name string
	ID                  int64
	Status              string
}

func (h *harness) inbox(scan int64) []found {
	h.t.Helper()
	rows, err := h.env.Pool("postgres").Query(context.Background(), `SELECT address, sys_object_id, sys_descr, sys_name, id, status
		FROM core.discovered WHERE scan_id = $1 ORDER BY address`, scan)
	if err != nil {
		h.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[found])
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

func TestScanHosts(t *testing.T) {
	for _, c := range []struct {
		prefix string
		want   []string
	}{
		{"10.1.2.0/29", []string{"10.1.2.1", "10.1.2.2", "10.1.2.3", "10.1.2.4", "10.1.2.5", "10.1.2.6"}},
		{"10.1.2.5/30", []string{"10.1.2.5", "10.1.2.6"}}, /* masked to .4/30 */
		{"10.1.2.4/31", []string{"10.1.2.4", "10.1.2.5"}},
		{"10.1.2.4/32", []string{"10.1.2.4"}},
		{"2001:db8::/126", []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"}},
		{"2001:db8::/127", []string{"2001:db8::", "2001:db8::1"}},
	} {
		var got []string
		for a := range scanHosts(netip.MustParsePrefix(c.prefix)) {
			got = append(got, a.String())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.prefix, got, c.want)
		}
	}
	n := 0
	for range scanHosts(netip.MustParsePrefix("10.9.0.0/16")) {
		n++
	}
	if n != 65534 {
		t.Errorf("/16 has %d hosts", n)
	}
}

/* TestSweepBoundedConcurrency: at most 32 addresses are probed at once, each once; a cancelled context stops the sweep. */
func TestSweepBoundedConcurrency(t *testing.T) {
	var mu sync.Mutex
	active, peak := 0, 0
	seen := map[netip.Addr]int{}
	probe := func(_ context.Context, a netip.Addr) {
		mu.Lock()
		active++
		peak = max(peak, active)
		seen[a]++
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		active--
		mu.Unlock()
	}
	sweep(context.Background(), scanHosts(netip.MustParsePrefix("10.9.0.0/24")), scanConcurrency, probe)
	if peak != scanConcurrency || len(seen) != 254 {
		t.Fatalf("peak %d, %d addresses", peak, len(seen))
	}
	for a, n := range seen {
		if n != 1 {
			t.Fatalf("%s probed %d times", a, n)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	seen = map[netip.Addr]int{}
	sweep(ctx, scanHosts(netip.MustParsePrefix("10.9.0.0/16")), scanConcurrency, probe)
	if len(seen) > 10*scanConcurrency {
		t.Fatalf("cancelled sweep probed %d addresses", len(seen))
	}
}

func TestScanFindsSimulatedDevices(t *testing.T) {
	sim := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "")
	pfx := nextScanPrefix()
	a2, a3, a5 := host(pfx, 2), host(pfx, 3), host(pfx, 5)
	pg := newScanPinger(a2, a3, a5) /* a3 answers ICMP but not SNMP */
	d := newScanDialer(map[netip.Addr]netip.AddrPort{a2: sim, a5: sim})
	scan := h.scan(pfx, true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: scan}, simtest.V3AuthKey)
	if err := runScan(h.scanPoller(pg, d), scan); err != nil {
		t.Fatal(err)
	}
	got := h.inbox(scan)
	if len(got) != 2 || got[0].Address != a2 || got[1].Address != a5 {
		t.Fatalf("inbox = %+v", got)
	}
	for _, f := range got {
		if f.SysOID != "1.3.6.1.4.1.35265.1.65535" || f.Descr != "24-port 10/100/1000 Ethernet Switch" || f.Name != "sim-mes1" || f.Status != "pending" {
			t.Errorf("find %+v", f)
		}
	}
	/* Network and broadcast addresses are never probed; every host once. */
	for i := range byte(8) {
		want := 1
		if i == 0 || i == 7 {
			want = 0
		}
		if n := pg.count(host(pfx, i)); n != want {
			t.Errorf("%s pinged %d times, want %d", host(pfx, i), n, want)
		}
	}
	/* SNMP only where ICMP answered, always on port 161. */
	if d.count(host(pfx, 1)) != 0 || d.count(a3) != 1 || !d.ports[161] || len(d.ports) != 1 {
		t.Errorf("dials: %v, ports %v", d.dials, d.ports)
	}
	if h.count(`SELECT count(*) FROM core.discovery_scan WHERE id = $1 AND last_run_at IS NOT NULL`, scan) != 1 {
		t.Error("last_run_at not set")
	}
}

/*
TestScanUsesOnlyAssignedProfile: with a wrong key on the scan's credential,
nothing is found, although the simulator answers to the credentials of a
device and of another scan; only the scan's credential is ever sent, once per
address.
*/
func TestScanUsesOnlyAssignedProfile(t *testing.T) {
	const wrongKey = "wrong-auth-key-0123456789" // #nosec G101 -- test value
	sim := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "")
	pfx := nextScanPrefix()
	a2, a3 := host(pfx, 2), host(pfx, 3)
	pg := newScanPinger(a2, a3)
	d := newScanDialer(map[netip.Addr]netip.AddrPort{a2: sim, a3: sim})
	scan := h.scan(pfx, true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: scan}, wrongKey)
	other := h.scan(nextScanPrefix(), true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: other}, simtest.V3AuthKey)
	dev := h.device(netip.AddrPortFrom(host(nextScanPrefix(), 1), 161)) /* outside the scanned prefix */
	h.simProfile(dev)
	if err := runScan(h.scanPoller(pg, d), scan); err != nil {
		t.Fatal(err)
	}
	if got := h.inbox(scan); len(got) != 0 {
		t.Fatalf("found with a wrong key: %+v", got)
	}
	if used := d.credentials(); len(used) != 1 || used["snmp3:"+simtest.V3User+":"+wrongKey+":"] != 2 {
		t.Fatalf("credentials sent: %v", used)
	}
	if d.count(a2) != 1 || d.count(a3) != 1 {
		t.Fatalf("sessions per address: %v", d.dials)
	}
}

func TestScanSkipsKnownDevices(t *testing.T) {
	sim := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "")
	pfx := nextScanPrefix()
	a2, a5 := host(pfx, 2), host(pfx, 5)
	pg := newScanPinger(a2, a5)
	d := newScanDialer(map[netip.Addr]netip.AddrPort{a2: sim, a5: sim})
	h.device(netip.AddrPortFrom(a2, 1161)) /* any port: the address is known */
	scan := h.scan(pfx, true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: scan}, simtest.V3AuthKey)
	if err := runScan(h.scanPoller(pg, d), scan); err != nil {
		t.Fatal(err)
	}
	if got := h.inbox(scan); len(got) != 1 || got[0].Address != a5 {
		t.Fatalf("inbox = %+v", got)
	}
	if pg.count(a2) != 0 || d.count(a2) != 0 {
		t.Fatalf("known device contacted: %d pings, %d sessions", pg.count(a2), d.count(a2))
	}
}

/* TestScanIdempotent: a second run leaves the same rows, including a status set meanwhile. */
func TestScanIdempotent(t *testing.T) {
	sim := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "")
	pfx := nextScanPrefix()
	a2, a5 := host(pfx, 2), host(pfx, 5)
	d := newScanDialer(map[netip.Addr]netip.AddrPort{a2: sim, a5: sim})
	scan := h.scan(pfx, true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: scan}, simtest.V3AuthKey)
	p := h.scanPoller(newScanPinger(a2, a5), d)
	if err := runScan(p, scan); err != nil {
		t.Fatal(err)
	}
	first := h.inbox(scan)
	if len(first) != 2 {
		t.Fatalf("first run: %+v", first)
	}
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error { return st.Ignore(ctx, tx, first[1].ID) })
	first[1].Status = "ignored"
	if err := runScan(p, scan); err != nil {
		t.Fatal(err)
	}
	if second := h.inbox(scan); !slices.Equal(first, second) {
		t.Fatalf("second run changed the inbox:\n%+v\n%+v", first, second)
	}
}

/*
TestDiscoveryJobValidatesArgs: jobs come from the untrusted api. A run of a
valid scan completes and finds devices; jobs for a missing, disabled,
foreign or credential-less scan are cancelled without any probe.
*/
func TestDiscoveryJobValidatesArgs(t *testing.T) {
	sim := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "")
	good := nextScanPrefix()
	pg := newScanPinger(host(good, 2))
	d := newScanDialer(map[netip.Addr]netip.AddrPort{host(good, 2): sim})
	p := h.scanPoller(pg, d)
	p.discEvery = time.Hour
	scan := h.scan(good, true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: scan}, simtest.V3AuthKey)
	/* Not due: only the job can start this run. */
	if _, err := h.env.Pool("nms_api").Exec(context.Background(), `UPDATE core.discovery_scan SET last_run_at = now() WHERE id = $1`, scan); err != nil {
		t.Fatal(err)
	}
	start(t, p)
	time.Sleep(time.Second) /* the schedule's first look has passed */
	if len(h.inbox(scan)) != 0 {
		t.Fatal("scan ran before the job")
	}
	enq, err := jobs.NewEnqueuer(h.env.Pool("nms_api"))
	if err != nil {
		t.Fatal(err)
	}
	h.api(func(ctx context.Context, tx pgx.Tx, _ *devices.Store) error {
		return enq.EnqueueDiscovery(ctx, tx, scan)
	})
	eventually(t, 30*time.Second, "scan found the device", func() bool { return len(h.inbox(scan)) == 1 })

	refused := map[string]int64{"missing": 1 << 40}
	var bad []netip.Prefix
	add := func(name string, enabled bool, profile bool, poller string) {
		pfx := nextScanPrefix()
		bad = append(bad, pfx)
		id := h.scan(pfx, enabled)
		if poller != "" {
			if _, err := h.env.Pool("nms_api").Exec(context.Background(), `UPDATE core.discovery_scan SET poller_id = $2 WHERE id = $1`, id, poller); err != nil {
				t.Fatal(err)
			}
		}
		if profile {
			h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: id}, simtest.V3AuthKey)
		}
		refused[name] = id
	}
	add("disabled", false, true, "")
	add("foreign", true, true, h.pollerID+"-other")
	add("no profile", true, false, "")
	queue, _ := jobs.Queue(h.pollerID)
	ins, err := river.NewClient(riverpgxv5.New(h.env.Pool("nms_poller")), &river.Config{Schema: store.JobsSchema})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range refused {
		if _, err := ins.Insert(context.Background(), jobs.DiscoveryScanArgs{ScanID: id}, &river.InsertOpts{Queue: queue}); err != nil {
			t.Fatal(err)
		}
	}
	for name, id := range refused {
		eventually(t, 30*time.Second, name+" scan job cancelled", func() bool {
			return h.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'discovery_scan' AND (args->>'scan_id')::bigint = $1 AND state = 'cancelled'`, id) == 1
		})
	}
	for _, pfx := range bad {
		for a := range scanHosts(pfx) {
			if pg.count(a)+d.count(a) != 0 {
				t.Fatalf("refused scan probed %s", a)
			}
		}
	}
	if n := h.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'discovery_scan' AND (args->>'scan_id')::bigint = $1 AND state = 'completed'`, scan); n != 1 {
		t.Fatalf("valid scan jobs completed: %d", n)
	}
}

/*
TestDiscoveryScheduledSkipsRunning: an enabled scan runs every interval_s
by the poller's own schedule, never twice at once; a disabled one never runs.
*/
func TestDiscoveryScheduledSkipsRunning(t *testing.T) {
	h := newHarness(t, "")
	pfx, off := nextScanPrefix(), nextScanPrefix()
	pg := newScanPinger()
	pg.hold = host(pfx, 1)
	p := h.scanPoller(pg, newScanDialer(nil))
	p.discEvery = 100 * time.Millisecond
	scan, disabled := h.scan(pfx, true), h.scan(off, false)
	for _, id := range []int64{scan, disabled} {
		h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: id}, simtest.V3AuthKey)
		if _, err := h.env.Pool("nms_api").Exec(context.Background(), `UPDATE core.discovery_scan SET interval_s = 1 WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
	}
	start(t, p)
	eventually(t, 10*time.Second, "scheduled run started", func() bool { return pg.count(host(pfx, 1)) == 1 })
	time.Sleep(1500 * time.Millisecond) /* longer than interval_s while the run is held */
	if n := pg.count(host(pfx, 1)); n != 1 {
		t.Fatalf("held scan started %d runs", n)
	}
	close(pg.release)
	eventually(t, 10*time.Second, "next scheduled run", func() bool { return pg.count(host(pfx, 1)) >= 2 })
	for a := range scanHosts(off) {
		if pg.count(a) != 0 {
			t.Fatalf("disabled scan probed %s", a)
		}
	}
}

func (d *scanDialer) total() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, v := range d.dials {
		n += v
	}
	return n
}

func (pg *scanPinger) total() int {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	n := 0
	for _, v := range pg.pings {
		n += v
	}
	return n
}

func (p *Poller) scanRunning(id int64) bool {
	p.disc.mu.Lock()
	defer p.disc.mu.Unlock()
	return p.disc.running[id]
}

/*
TestRunStopsWhenScanChanges: a run re-checks its scan and stops within one
re-check period when the scan is disabled, deleted, re-addressed, moved to
another poller or gets another credential; no session is opened afterwards.
A changed credential is used by the next run.
*/
func TestRunStopsWhenScanChanges(t *testing.T) {
	const newKey = "next-auth-key-0123456789" // #nosec G101 -- test value
	for name, change := range map[string]string{
		"disable": `UPDATE core.discovery_scan SET enabled = false WHERE id = $1`,
		"delete":  `DELETE FROM core.discovery_scan WHERE id = $1`,
		"cidr":    `UPDATE core.discovery_scan SET cidr = '10.252.255.0/24' WHERE id = $1`,
		"poller":  `UPDATE core.discovery_scan SET poller_id = poller_id || '-x' WHERE id = $1`,
		"profile": "",
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "")
			n := byte(scanNet.Add(1))
			pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 252, n, 0}), 24)
			pg := newScanPinger()
			pg.delay = 100 * time.Millisecond
			for a := range scanHosts(pfx) {
				pg.ok[a] = true
			}
			d := newScanDialer(nil)
			d.fail = true
			p := h.scanPoller(pg, d)
			p.scanRecheck = 100 * time.Millisecond
			scan := h.scan(pfx, true)
			owner := devices.Owner{Kind: devices.OwnerScan, ID: scan}
			h.sealV3(owner, simtest.V3AuthKey)
			ctx := context.Background()
			if err := p.startScan(ctx, ctx, scan); err != nil {
				t.Fatal(err)
			}
			eventually(t, 5*time.Second, "run probing", func() bool { return d.total() >= scanConcurrency })
			if change == "" {
				time.Sleep(10 * time.Millisecond) /* a distinct updated_at */
				h.sealV3(owner, newKey)
			} else if _, err := h.env.Pool("nms_api").Exec(ctx, change, scan); err != nil {
				t.Fatal(err)
			}
			changed := time.Now()
			eventually(t, 2*time.Second, "run cancelled", func() bool { return !p.scanRunning(scan) })
			p.disc.wg.Wait()
			if took := time.Since(changed); took > time.Second {
				t.Errorf("run stopped %v after the change", took)
			}
			dials := d.total()
			time.Sleep(300 * time.Millisecond)
			if d.total() != dials || dials >= 254 || pg.total() >= 254 {
				t.Fatalf("after the change: %d -> %d sessions, %d pings of 254 hosts", dials, d.total(), pg.total())
			}
			if used := d.credentials(); len(used) != 1 || used["snmp3:"+simtest.V3User+":"+simtest.V3AuthKey+":"] != dials {
				t.Fatalf("credentials: %v", used)
			}
			if change != "" {
				return
			}
			pg.delay = 0
			if err := runScan(p, scan); err != nil {
				t.Fatal(err)
			}
			if used := d.credentials(); used["snmp3:"+simtest.V3User+":"+newKey+":"] != 254 {
				t.Fatalf("next run credentials: %v", used)
			}
		})
	}
}

/* hostileReader answers the system group, or panics like a broken parser on hostile input. */
type hostileReader struct{ panics bool }

func (f hostileReader) Get(_ context.Context, _ ...string) ([]snmp.Var, error) {
	if f.panics {
		panic("hostile answer")
	}
	return []snmp.Var{
		{OID: oidSysObjID, Type: snmp.TypeOID, Value: "1.3.6.1.4.1.32473.9"},
		{OID: oidSysDescr, Type: snmp.TypeOctetString, Value: []byte("fake\x00 device")},
		{OID: oidSysName, Type: snmp.TypeOctetString, Value: []byte("fake1")},
	}, nil
}

func (hostileReader) Walk(context.Context, string, func(snmp.Var) error) error { return nil }

func (hostileReader) BulkGet(context.Context, []string) ([]snmp.Var, error) { return nil, nil }

/* TestScanRecoversPanics: a panic while probing one host is logged and counted; the run and the poller go on. */
func TestScanRecoversPanics(t *testing.T) {
	h := newHarness(t, "")
	pfx := nextScanPrefix()
	a2, a3, a4 := host(pfx, 2), host(pfx, 3), host(pfx, 4)
	pg := newScanPinger(a2, a3)
	pg.panicAt = a4
	dial := func(_ context.Context, a netip.AddrPort, _ creds.Credential, _ snmp.Options) (snmp.Reader, io.Closer, error) {
		return hostileReader{panics: a.Addr() == a3}, io.NopCloser(nil), nil
	}
	p := New(h.config(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour}), Deps{
		Pool: h.env.Pool("nms_poller"), Priv: h.priv, Pub: h.pub, Pinger: pg, DialSNMP: dial,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	scan := h.scan(pfx, true)
	h.sealV3(devices.Owner{Kind: devices.OwnerScan, ID: scan}, simtest.V3AuthKey)
	if err := runScan(p, scan); err != nil {
		t.Fatal(err)
	}
	got := h.inbox(scan)
	if len(got) != 1 || got[0].Address != a2 || got[0].Descr != "fake device" {
		t.Fatalf("inbox = %+v", got)
	}
	if n := p.scanPanics.Load(); n != 2 {
		t.Fatalf("recovered panics = %d, want 2", n)
	}
	if p.scanRunning(scan) {
		t.Fatal("run still claimed")
	}
}
