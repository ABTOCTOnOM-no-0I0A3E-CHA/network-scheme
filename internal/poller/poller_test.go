package poller

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	_ "github.com/beekamai/network-scheme/internal/drivers/all"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* fakePinger answers every ICMP probe with ok; real ICMP is exercised by the Linux e2e. */
type fakePinger struct{ ok bool }

func (f fakePinger) Ping(context.Context, netip.Addr) (time.Duration, bool) {
	return 3 * time.Millisecond, f.ok
}

/* dialer counts SNMP sessions per address and selects the simulator data file by v3 context. */
type dialer struct {
	mu      sync.Mutex
	dials   map[netip.AddrPort]int
	context string
}

func (d *dialer) dial(ctx context.Context, a netip.AddrPort, c creds.Credential, o snmp.Options) (snmp.Reader, io.Closer, error) {
	d.mu.Lock()
	d.dials[a]++
	d.mu.Unlock()
	o.ContextName = d.context /* simulator only: snmpsim picks the .snmprec by v3 context name */
	return snmp.Dial(ctx, a, c, o)
}

func (d *dialer) count(a netip.AddrPort) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[a]
}

type harness struct {
	t        *testing.T
	env      *testdb.Env
	pub      *[32]byte
	priv     *[32]byte
	pollerID string
	group    int64
	dialer   *dialer
}

var pollerSeq atomic.Int64

/* newHarness gives each test its own poller id, so pollers of other tests never see its devices. */
func newHarness(t *testing.T, simContext string) *harness {
	t.Helper()
	env := testdb.New(t)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, env: env, pub: pub, priv: priv,
		pollerID: fmt.Sprintf("t%d-%d", time.Now().UnixNano()%1_000_000, pollerSeq.Add(1)),
		dialer:   &dialer{dials: map[netip.AddrPort]int{}, context: simContext}}
	if err := env.Pool("nms_api").QueryRow(context.Background(),
		`INSERT INTO core.device_group (name) VALUES ('poller-'||gen_random_uuid()) RETURNING id`).Scan(&h.group); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) config(iv Intervals) Config {
	one := 1 /* production defaults: the simulator can be slow while other test containers run */
	return Config{PollerID: h.pollerID, Workers: 16, SNMPTimeout: 2 * time.Second, SNMPRetries: &one,
		DefaultIntervals: iv, HeavyCPUThreshold: 80}
}

func (h *harness) poller(iv Intervals) *Poller {
	return New(h.config(iv), Deps{
		Pool: h.env.Pool("nms_poller"), Priv: h.priv, Pub: h.pub,
		Pinger: fakePinger{ok: true}, DialSNMP: h.dialer.dial,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func (h *harness) api(fn func(ctx context.Context, tx pgx.Tx, st *devices.Store) error) {
	h.t.Helper()
	ctx := context.Background()
	pool := h.env.Pool("nms_api")
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error { return fn(ctx, tx, devices.NewStore(pool)) }); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) device(addr netip.AddrPort) int64 {
	h.t.Helper()
	var id int64
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) (err error) {
		id, err = st.Create(ctx, tx, devices.NewDevice{Name: "dev", Address: addr.Addr(), SNMPPort: int(addr.Port()),
			GroupID: h.group, PollerID: h.pollerID})
		return err
	})
	return id
}

func v3Secret(key string) map[string]string {
	return map[string]string{"user": simtest.V3User, "auth_proto": "SHA256", "auth_key": key, "priv_proto": "AES", "priv_key": key}
}

func (h *harness) profile(id int64, kind string, ct []byte) {
	h.t.Helper()
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error {
		return st.PutProfile(ctx, tx, devices.Owner{Kind: devices.OwnerDevice, ID: id}, kind, ct, 1)
	})
}

/* simProfile stores the simulator's real SNMPv3 credential for device id. */
func (h *harness) simProfile(id int64) {
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	s := v3Secret(simtest.V3AuthKey)
	s["priv_key"] = simtest.V3PrivKey
	h.profile(id, "snmp3", credstest.Seal(h.pub, owner, "snmp3", s, time.Now().Add(-time.Minute)))
}

func (h *harness) count(sql string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (h *harness) str(sql string, args ...any) string {
	h.t.Helper()
	var s string
	if err := h.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		h.t.Fatalf("%s: %v", sql, err)
	}
	return s
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, within)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

/* start runs p until the test ends. */
func start(t *testing.T, p *Poller) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("Run did not stop")
		}
	})
}

func TestPollerCollectsFromSimulator(t *testing.T) {
	addr := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "eltex-mes")
	id := h.device(addr)
	h.simProfile(id)
	iv := Intervals{Availability: time.Second, Metrics: 2 * time.Second, Inventory: 3 * time.Second}
	start(t, h.poller(iv))
	/* Two metric intervals give the first rate: everything is in within two of the longest interval (+3 s of work). */
	eventually(t, 2*iv.Inventory+3*time.Second, "availability, rates, inventory and driver", func() bool {
		return h.count(`SELECT count(*) FROM metrics.availability WHERE device_id = $1 AND state = 'up' AND snmp_ok`, id) > 0 &&
			h.count(`SELECT count(*) FROM metrics.if_metrics WHERE device_id = $1`, id) > 0 &&
			h.count(`SELECT count(*) FROM metrics.sys_metrics WHERE device_id = $1`, id) > 0 &&
			h.count(`SELECT count(*) FROM inventory.interface WHERE device_id = $1`, id) > 0 &&
			h.count(`SELECT count(*) FROM core.device WHERE id = $1 AND driver <> 'auto'`, id) > 0
	})
	if d := h.str(`SELECT driver FROM core.device WHERE id = $1`, id); d != "eltex-mes" {
		t.Fatalf("driver = %q", d)
	}
	if oid := h.str(`SELECT coalesce(sys_object_id, '') FROM core.device WHERE id = $1`, id); oid != "1.3.6.1.4.1.35265.1.65535" {
		t.Fatalf("sys_object_id = %q", oid)
	}
	if s := h.str(`SELECT status FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); s != "ok" {
		t.Fatalf("profile status = %q", s)
	}
	if s := h.str(`SELECT state FROM inventory.device_status WHERE device_id = $1`, id); s != "up" {
		t.Fatalf("device status = %q", s)
	}
	/* The accepted credential timestamp is recorded, so an older ciphertext is refused later. */
	if n := h.count(`SELECT count(*) FROM inventory.profile_seen WHERE owner_kind = 'device' AND owner_id = $1 AND kind = 'snmp3'`, id); n != 1 {
		t.Fatal("profile_seen not recorded")
	}
}

func TestBadProfileMarkedNotPolled(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	other := devices.Owner{Kind: devices.OwnerDevice, ID: 999_999_999}
	cases := map[string]func(id int64) []byte{
		"mismatch": func(int64) []byte { /* sealed for another device: replayed ciphertext */
			return credstest.Seal(h.pub, other, "snmp3", v3Secret("0123456789abcdef"), time.Now())
		},
		"weak": func(id int64) []byte {
			return credstest.Seal(h.pub, devices.Owner{Kind: devices.OwnerDevice, ID: id}, "snmp3", v3Secret("0123456789abcde"), time.Now())
		},
		"invalid": func(int64) []byte { return []byte("not a sealed box at all, just bytes") },
	}
	n := 0
	for want, seal := range cases {
		n++
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(100 + n)}), 161)
		id := h.device(addr)
		h.profile(id, "snmp3", seal(id))
		devs, err := p.loadDevices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var d device
		for _, x := range devs {
			if x.ID == id {
				d = x
			}
		}
		cache := newDevCache()
		_ = p.run(ctx, d, cache, classAvail, nil)
		if err := p.run(ctx, d, cache, classMetrics, nil); err == nil {
			t.Fatalf("%s: metrics without a usable profile succeeded", want)
		}
		_ = p.run(ctx, d, cache, classInventory, nil)
		if got := h.str(`SELECT status FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); got != want {
			t.Fatalf("profile status = %q, want %q", got, want)
		}
		if c := h.dialer.count(addr); c != 0 {
			t.Fatalf("%s: %d SNMP sessions to the device", want, c)
		}
		/* ICMP answers, SNMP is not possible: partial. */
		if s := h.str(`SELECT state FROM inventory.device_status WHERE device_id = $1`, id); s != "partial" {
			t.Fatalf("%s: device status = %q", want, s)
		}
	}
}

func TestStaleCiphertextRejected(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	addr := netip.MustParseAddrPort("198.51.100.120:161")
	id := h.device(addr)
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
	older := credstest.Seal(h.pub, owner, "snmp3", v3Secret("0123456789abcdef"), time.Now().Add(-time.Hour))
	if err := inventoryMark(ctx, h.env.Pool("nms_poller"), owner, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	h.profile(id, "snmp3", older)
	devs, _ := p.loadDevices(ctx)
	for _, d := range devs {
		_ = p.run(ctx, d, newDevCache(), classAvail, nil)
	}
	if s := h.str(`SELECT status FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); s != "mismatch" {
		t.Fatalf("rolled-back credential status = %q", s)
	}
	if h.dialer.count(addr) != 0 {
		t.Fatal("rolled-back credential was used")
	}
}

func inventoryMark(ctx context.Context, pool *pgxpool.Pool, o devices.Owner, at time.Time) error {
	_, err := pool.Exec(ctx, `INSERT INTO inventory.profile_seen (owner_kind, owner_id, kind, created_at) VALUES ($1, $2, 'snmp3', $3)`, o.Kind, o.ID, at)
	return err
}

/* silentUDP is a UDP port that never answers: every SNMP request times out. */
func silentUDP(t *testing.T) netip.AddrPort {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestStatusPartialWhenSNMPFails(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	zero := 0
	p.cfg.SNMPTimeout, p.cfg.SNMPRetries = 400*time.Millisecond, &zero
	ctx := context.Background()
	addr := silentUDP(t)
	id := h.device(addr)
	h.simProfile(id)
	devs, err := p.loadDevices(ctx)
	if err != nil || len(devs) != 1 {
		t.Fatalf("devices = %v, %v", devs, err)
	}
	began := time.Now()
	if err := p.run(ctx, devs[0], newDevCache(), classAvail, nil); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(began); took > 3*time.Second {
		t.Fatalf("availability took %v against a silent device", took)
	}
	if s := h.str(`SELECT state FROM inventory.device_status WHERE device_id = $1`, id); s != "partial" {
		t.Fatalf("status = %q", s)
	}
	if n := h.count(`SELECT count(*) FROM metrics.availability WHERE device_id = $1 AND icmp_ok AND NOT snmp_ok AND state = 'partial'`, id); n != 1 {
		t.Fatalf("availability rows = %d", n)
	}
	if h.dialer.count(addr) != 1 {
		t.Fatalf("SNMP sessions = %d", h.dialer.count(addr))
	}
	/* The credential was fine, the device just did not answer: the profile stays usable. */
	if s := h.str(`SELECT status FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); s != "ok" {
		t.Fatalf("profile status = %q", s)
	}
	/* Neither ICMP nor SNMP: down. */
	p.pinger = fakePinger{ok: false}
	if err := p.run(ctx, devs[0], newDevCache(), classAvail, nil); err != nil {
		t.Fatal(err)
	}
	if s := h.str(`SELECT state FROM inventory.device_status WHERE device_id = $1`, id); s != "down" {
		t.Fatalf("status = %q", s)
	}
}

func TestRescheduleOnDeviceChange(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	start(t, p)
	id := h.device(netip.MustParseAddrPort("198.51.100.130:161"))
	eventually(t, 10*time.Second, "new device scheduled", func() bool { return p.sched.interval(id, classAvail) == time.Hour })
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error {
		s := 77
		return st.Update(ctx, tx, id, devices.Patch{Intervals: &devices.Intervals{AvailS: &s}})
	})
	eventually(t, 10*time.Second, "device interval applied", func() bool { return p.sched.interval(id, classAvail) == 77*time.Second })
	if _, err := h.env.Pool("nms_api").Exec(context.Background(), `UPDATE core.device_group SET interval_metrics_s = 99 WHERE id = $1`, h.group); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "group interval applied", func() bool { return p.sched.interval(id, classMetrics) == 99*time.Second })
	/* Moving the device to another poller unschedules it and forgets its rate baseline. */
	ifs := func(in uint64) drivers.Sample {
		return drivers.Sample{SysUpTime: time.Hour, Interfaces: []drivers.IfCounters{{Index: 1, InOctets: in, OutOctets: in, HC: true}}}
	}
	at := time.Now()
	p.rates.Rates(id, ifs(0), at)
	other := "elsewhere"
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error {
		return st.Update(ctx, tx, id, devices.Patch{PollerID: &other})
	})
	eventually(t, 10*time.Second, "reassigned device unscheduled", func() bool { return !p.sched.known(id) })
	if pts := p.rates.Rates(id, ifs(600), at.Add(time.Minute)); len(pts) != 0 {
		t.Fatalf("rate baseline survived the reassignment: %+v", pts)
	}
	/* Deletion works the same way. */
	id2 := h.device(netip.MustParseAddrPort("198.51.100.131:161"))
	eventually(t, 10*time.Second, "second device scheduled", func() bool { return p.sched.known(id2) })
	h.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) error { return st.Delete(ctx, tx, id2) })
	eventually(t, 10*time.Second, "deleted device unscheduled", func() bool { return !p.sched.known(id2) })
}

func TestPollNowJob(t *testing.T) {
	addr := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "eltex-mes")
	id := h.device(addr)
	h.simProfile(id)
	/* Intervals far away: anything collected now comes from the job. */
	p := h.poller(Intervals{Availability: 24 * time.Hour, Metrics: 24 * time.Hour, Inventory: 24 * time.Hour})
	start(t, p)
	eventually(t, 10*time.Second, "device scheduled", func() bool { return p.sched.known(id) })
	enq, err := jobs.NewEnqueuer(h.env.Pool("nms_api"))
	if err != nil {
		t.Fatal(err)
	}
	h.api(func(ctx context.Context, tx pgx.Tx, _ *devices.Store) error { return enq.EnqueuePollNow(ctx, tx, id) })
	eventually(t, 30*time.Second, "poll_now job completed", func() bool {
		return h.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'poll_now' AND (args->>'device_id')::bigint = $1 AND state = 'completed'`, id) == 1
	})
	for what, sql := range map[string]string{
		"availability": `SELECT count(*) FROM metrics.availability WHERE device_id = $1 AND state = 'up'`,
		"inventory":    `SELECT count(*) FROM inventory.interface WHERE device_id = $1`,
		"metrics":      `SELECT count(*) FROM metrics.sys_metrics WHERE device_id = $1`,
	} {
		if h.count(sql, id) == 0 {
			t.Errorf("poll_now stored no %s", what)
		}
	}
	/* A job for a device this poller does not own is cancelled, not run. */
	foreign := newHarness(t, "")
	fid := foreign.device(netip.MustParseAddrPort("198.51.100.140:161"))
	queue, _ := jobs.Queue(h.pollerID)
	ins, err := river.NewClient(riverpgxv5.New(h.env.Pool("nms_poller")), &river.Config{Schema: store.JobsSchema})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ins.Insert(context.Background(), jobs.PollNowArgs{DeviceID: fid}, &river.InsertOpts{Queue: queue}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 30*time.Second, "foreign poll_now cancelled", func() bool {
		return h.count(`SELECT count(*) FROM jobs.river_job WHERE (args->>'device_id')::bigint = $1 AND state = 'cancelled'`, fid) == 1
	})
	if foreign.dialer.count(netip.MustParseAddrPort("198.51.100.140:161"))+h.dialer.count(netip.MustParseAddrPort("198.51.100.140:161")) != 0 {
		t.Fatal("foreign device was contacted")
	}
}

func TestHeartbeatAndHealthcheck(t *testing.T) {
	h := newHarness(t, "")
	ctx := context.Background()
	pool := h.env.Pool("nms_poller")
	if err := Healthy(ctx, pool, h.pollerID); err == nil {
		t.Fatal("healthy without a heartbeat")
	}
	start(t, h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour}))
	eventually(t, 10*time.Second, "heartbeat", func() bool { return Healthy(ctx, pool, h.pollerID) == nil })
	/* Another poller whose last heartbeat is 46 s old is unhealthy. */
	stale := h.pollerID + "-stale"
	if _, err := h.env.Pool("postgres").Exec(ctx, `INSERT INTO inventory.poller_heartbeat (poller_id, at) VALUES ($1, now() - interval '46 seconds')`, stale); err != nil {
		t.Fatal(err)
	}
	if err := Healthy(ctx, pool, stale); err == nil {
		t.Fatal("healthy with a 46 s old heartbeat")
	}
}

func TestOversizedCiphertextIsInvalidAndUnread(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	addr := netip.MustParseAddrPort("198.51.100.170:161")
	id := h.device(addr)
	/* The CHECK keeps the api from writing such a row; lift it to plant one as a superuser. */
	su := h.env.Pool("postgres")
	if _, err := su.Exec(ctx, `ALTER TABLE core.access_profile DROP CONSTRAINT access_profile_ciphertext_len`); err != nil {
		t.Fatal(err)
	}
	if _, err := su.Exec(ctx, `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version)
		VALUES ('device', $1, 'snmp3', repeat('x', $2)::bytea, 1)`, id, maxCiphertext+1); err != nil {
		t.Fatal(err)
	}
	var got []byte
	rows, err := p.pool.Query(ctx, `SELECT CASE WHEN octet_length(ciphertext) <= $1 THEN ciphertext END
		FROM core.access_profile WHERE owner_id = $2`, maxCiphertext, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgx.ForEachRow(rows, []any{&got}, func() error { return nil }); err != nil || got != nil {
		t.Fatalf("oversized ciphertext was read: %d bytes, err %v", len(got), err)
	}
	cache := newDevCache()
	_, err = p.credential(ctx, devices.Owner{Kind: devices.OwnerDevice, ID: id}, cache, snmpKinds...)
	if !errors.Is(err, errNoProfile) {
		t.Fatalf("credential err = %v, want errNoProfile", err)
	}
	if s := h.str(`SELECT status FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, id); s != "invalid" {
		t.Fatalf("oversized profile status = %q", s)
	}
	if len(cache.creds) != 0 || h.dialer.count(addr) != 0 {
		t.Fatal("oversized profile was opened or dialed")
	}
}

func TestLoadDevicesClampsIntervals(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	own := h.device(netip.MustParseAddrPort("198.51.100.180:161"))
	viaGroup := h.device(netip.MustParseAddrPort("198.51.100.181:161"))
	api := h.env.Pool("nms_api")
	/* The api can write any positive interval. */
	if _, err := api.Exec(ctx, `UPDATE core.device SET interval_avail_s = 1, interval_metrics_s = 1, interval_inventory_s = 1 WHERE id = $1`, own); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `INSERT INTO core.device_group (name, interval_avail_s, interval_metrics_s, interval_inventory_s)
		VALUES ('fast-'||gen_random_uuid(), 1, 1, 2000000000) RETURNING id`); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `UPDATE core.device SET group_id = (SELECT max(id) FROM core.device_group) WHERE id = $1`, viaGroup); err != nil {
		t.Fatal(err)
	}
	devs, err := p.loadDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64][numClasses]time.Duration{
		own:      {minAvailInterval, minMetricsInterval, minInventoryInterval},
		viaGroup: {minAvailInterval, minMetricsInterval, maxIntervalDuration},
	}
	for _, d := range devs {
		if w, ok := want[d.ID]; ok {
			if d.Intervals != w {
				t.Errorf("device %d intervals = %v, want %v", d.ID, d.Intervals, w)
			}
			delete(want, d.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("devices not loaded: %v", want)
	}
}

func TestUnknownPollNowJobsReloadOncePerGap(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	var mu sync.Mutex
	clock := time.Now()
	p.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	w := &pollNowWorker{p: p}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			err := w.Work(context.Background(), &river.Job[jobs.PollNowArgs]{Args: jobs.PollNowArgs{DeviceID: 1<<40 + int64(i)}})
			if err == nil || !errors.Is(err, errNotMine) {
				t.Errorf("job %d: err = %v, want a cancel for an unknown device", i, err)
			}
		})
	}
	wg.Wait()
	if n := p.jobReloads.Load(); n != 1 {
		t.Fatalf("%d rereads for 8 unknown-device jobs, want 1", n)
	}
	mu.Lock()
	clock = clock.Add(jobReloadGap + time.Second)
	mu.Unlock()
	_ = w.Work(context.Background(), &river.Job[jobs.PollNowArgs]{Args: jobs.PollNowArgs{DeviceID: 1 << 41}})
	if n := p.jobReloads.Load(); n != 2 {
		t.Fatalf("%d rereads after the gap, want 2", n)
	}
}
