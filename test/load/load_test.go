//go:build load

package load

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/creds/credstest"
	"github.com/beekamai/network-scheme/internal/devices"
	_ "github.com/beekamai/network-scheme/internal/drivers/all"
	"github.com/beekamai/network-scheme/internal/poller"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

/* runFor is how long the poller runs; CI uses the default, a local smoke may pass -args -load.duration=2m. */
var runFor = flag.Duration("load.duration", 10*time.Minute, "how long the poller polls the simulated devices")

const (
	numDevices = 1000
	firstPort  = 20000
	pollerID   = "load"
	/* p95Limit is the target: an availability run starts at most 30 s after it was due. */
	p95Limit = 30 * time.Second
	/* availEvery is the production default availability interval, which the test keeps. */
	availEvery = 30 * time.Second
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* okPinger answers every ICMP probe at once: ICMP to one container a thousand times measures nothing. */
type okPinger struct{}

func (okPinger) Ping(context.Context, netip.Addr) (time.Duration, bool) {
	return time.Millisecond, true
}

/* start is one availability run as the scheduler reported it. */
type start struct {
	device   int64
	due, at  time.Time
	censored bool /* due before the end but not started: at is the end, the delay a lower bound */
}

type recorder struct {
	mu     sync.Mutex
	starts []start
}

func (r *recorder) record(id int64, due, at time.Time) {
	r.mu.Lock()
	r.starts = append(r.starts, start{device: id, due: due, at: at})
	r.mu.Unlock()
}

/* usage is sampled once a second while the poller runs. */
type usage struct {
	heapPeak, sysPeak       uint64
	goroutinesPeak          int
	connsPeak, acquiredPeak int32
	maxConns                int32
	cpuStart, idleStart     float64
	cpuUsed                 float64 /* CPU seconds of the process (Go runtime estimate) */
	waits, acquires         int64
	acquireWait             time.Duration
	began                   time.Time
	windows                 []window /* one per availability interval, to see when delays and contention coincide */
}

type window struct {
	inUse      int32
	goroutines int
	waits      int64 /* pool acquires that waited, cumulative at the window's last sample */
}

var cpuSamples = []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}

func cpuNow() (total, idle float64) {
	metrics.Read(cpuSamples)
	return cpuSamples[0].Value.Float64(), cpuSamples[1].Value.Float64()
}

func (u *usage) sample(pool *pgxpool.Pool) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	u.heapPeak = max(u.heapPeak, ms.HeapInuse)
	u.sysPeak = max(u.sysPeak, ms.Sys)
	u.goroutinesPeak = max(u.goroutinesPeak, runtime.NumGoroutine())
	st := pool.Stat()
	u.connsPeak = max(u.connsPeak, st.TotalConns())
	u.acquiredPeak = max(u.acquiredPeak, st.AcquiredConns())
	u.maxConns = st.MaxConns()
	u.waits, u.acquires, u.acquireWait = st.EmptyAcquireCount(), st.AcquireCount(), st.AcquireDuration()
	i := int(time.Since(u.began) / availEvery)
	for len(u.windows) <= i {
		u.windows = append(u.windows, window{})
	}
	w := &u.windows[i]
	w.inUse = max(w.inUse, st.AcquiredConns())
	w.goroutines = max(w.goroutines, runtime.NumGoroutine())
	w.waits = u.waits
}

func TestAvailabilityCycle1000Devices(t *testing.T) {
	if *runFor < 2*availEvery {
		t.Fatalf("-load.duration %v: at least %v", *runFor, 2*availEvery)
	}
	env := testdb.New(t)
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := generate(dir, numDevices); err != nil {
		t.Fatal(err)
	}
	setupStart := time.Now()
	addrs := simtest.StartMany(t, dir, firstPort, numDevices)
	t.Logf("simulator with %d UDP ports ready in %v (first %v)", numDevices, time.Since(setupStart).Round(time.Second), addrs[0])

	cfg, pub, priv := pollerConfig(t, env)
	ids := addDevices(t, env, addrs, pub)

	dbPW, err := config.ReadSecretFile(cfg.DB.PasswordFile)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pool, err := store.Open(ctx, cfg.DB, dbPW) /* as cmd/poller opens it: db.max_conns from the config */
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	logFile, err := os.Create(filepath.Join(t.TempDir(), "poller.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logFile.Close() }()
	rec := &recorder{}
	p := poller.New(cfg, poller.Deps{
		Pool: pool, Priv: priv, Pub: pub, Pinger: okPinger{},
		Logger:              slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelWarn})),
		AvailabilityStarted: rec.record,
	})

	var u usage
	u.cpuStart, u.idleStart = cpuNow()
	runCtx, cancel := context.WithCancel(ctx)
	began := time.Now()
	u.began = began
	done := make(chan error, 1)
	go func() { done <- p.Run(runCtx) }()
	tick := time.NewTicker(time.Second)
	for time.Since(began) < *runFor {
		select {
		case err := <-done:
			t.Fatalf("poller stopped early: %v", err)
		case <-tick.C:
			u.sample(pool)
		}
	}
	tick.Stop()
	end := time.Now()
	total, idle := cpuNow()
	u.cpuUsed = (total - u.cpuStart) - (idle - u.idleStart)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(time.Minute):
		t.Fatal("poller did not stop within a minute")
	}

	rec.mu.Lock()
	starts := slices.Clone(rec.starts)
	rec.mu.Unlock()
	starts = censor(starts, ids, end)
	report(t, env, starts, ids, began, end, &u, logFile.Name())
}

/* pollerConfig writes poller.yaml with production defaults (workers, intervals, db.max_conns) and loads it. */
func pollerConfig(t *testing.T, env *testdb.Env) (poller.Config, *[32]byte, *[32]byte) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	db, pw := env.Config("nms_poller")
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(p)
	}
	yaml := fmt.Sprintf("poller_id: %s\ndb: {host: %q, port: %d, name: %q, user: %q, password_file: %q}\n"+
		"read_key_file: %q\nread_pub_key_file: %q\n", pollerID, db.Host, db.Port, db.Name, db.User,
		write("db_password", pw.Reveal()),
		write("read_key", base64.StdEncoding.EncodeToString(priv[:])),
		write("read_pub_key", base64.StdEncoding.EncodeToString(pub[:])))
	cfg, err := poller.LoadConfig(write("poller.yaml", yaml))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workers != 256 || cfg.DefaultIntervals.Availability != availEvery {
		t.Fatalf("not the production defaults: workers %d, availability %v", cfg.Workers, cfg.DefaultIntervals.Availability)
	}
	if priv, pub, err = cfg.ReadKeys(); err != nil {
		t.Fatal(err)
	}
	return cfg, pub, priv
}

/* addDevices creates one device per simulator port with its own SNMPv2c profile, as the api would. */
func addDevices(t *testing.T, env *testdb.Env, addrs []netip.AddrPort, pub *[32]byte) []int64 {
	t.Helper()
	ctx := context.Background()
	pool := env.Pool("nms_api")
	st := devices.NewStore(pool)
	var group int64
	if err := pool.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('load-'||gen_random_uuid()) RETURNING id`).
		Scan(&group); err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, len(addrs))
	const batch = 100
	for lo := 0; lo < len(addrs); lo += batch {
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			for i := lo; i < min(lo+batch, len(addrs)); i++ {
				id, err := st.Create(ctx, tx, devices.NewDevice{Name: community(i), Address: addrs[i].Addr(),
					SNMPPort: int(addrs[i].Port()), GroupID: group, PollerID: pollerID, InsecureProtocols: true})
				if err != nil {
					return err
				}
				owner := devices.Owner{Kind: devices.OwnerDevice, ID: id}
				ct := credstest.Seal(pub, owner, "snmp2c", map[string]string{"community": community(i)}, time.Now().Add(-time.Minute))
				if err := st.PutProfile(ctx, tx, owner, "snmp2c", ct, 1); err != nil {
					return err
				}
				ids[i] = id
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return ids
}

/*
censor adds, for every device whose next availability run was due before the
end but had not started, a sample with the end as its start: its delay is at
least that long, and leaving it out would flatter the result.
*/
func censor(starts []start, ids []int64, end time.Time) []start {
	last := map[int64]time.Time{}
	for _, s := range starts {
		if s.due.After(last[s.device]) {
			last[s.device] = s.due
		}
	}
	for _, id := range ids {
		if due, ok := last[id]; ok && due.Add(availEvery).Before(end) {
			starts = append(starts, start{device: id, due: due.Add(availEvery), at: end, censored: true})
		}
	}
	return starts
}

func percentile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	return sorted[max(i, 0)]
}

func report(t *testing.T, env *testdb.Env, starts []start, ids []int64, began, end time.Time, u *usage, logPath string) {
	t.Helper()
	wall := end.Sub(began)
	delays := make([]time.Duration, 0, len(starts))
	perDevice := map[int64]int{}
	censored := 0
	for _, s := range starts {
		delays = append(delays, s.at.Sub(s.due))
		if s.censored {
			censored++
			continue
		}
		perDevice[s.device]++
	}
	slices.Sort(delays)
	p50, p95, worst := percentile(delays, 0.50), percentile(delays, 0.95), percentile(delays, 1)
	minRuns := math.MaxInt
	for _, id := range ids {
		minRuns = min(minRuns, perDevice[id])
	}

	/* The stored points: one per started run, and the gaps between them. */
	ctx := context.Background()
	var rows, snmpOK, up, devs int
	var maxGap float64
	err := env.Pool("postgres").QueryRow(ctx, `
		WITH pts AS (
			SELECT device_id, ts, snmp_ok, state,
			       extract(epoch FROM ts - lag(ts) OVER (PARTITION BY device_id ORDER BY ts)) AS gap
			FROM metrics.availability WHERE device_id = ANY($1))
		SELECT count(*), count(*) FILTER (WHERE snmp_ok), count(*) FILTER (WHERE state = 'up'),
		       count(DISTINCT device_id), coalesce(max(gap), 0)
		FROM pts`, ids).Scan(&rows, &snmpOK, &up, &devs, &maxGap)
	if err != nil {
		t.Fatal(err)
	}
	var sysDevs, ifDevs int
	if err := env.Pool("postgres").QueryRow(ctx, `SELECT
		(SELECT count(DISTINCT device_id) FROM metrics.sys_metrics WHERE device_id = ANY($1)),
		(SELECT count(DISTINCT device_id) FROM metrics.if_metrics WHERE device_id = ANY($1))`, ids).Scan(&sysDevs, &ifDevs); err != nil {
		t.Fatal(err)
	}
	logged, _ := os.ReadFile(logPath) // #nosec G304 -- the test's own temp file
	warnLines := 0
	for _, b := range logged {
		if b == '\n' {
			warnLines++
		}
	}

	const mib = 1 << 20
	t.Logf("devices %d, workers 256, availability every %v, ran %v (fake ICMP, real SNMPv2c via snmpsim)",
		len(ids), availEvery, wall.Round(time.Second))
	t.Logf("availability start delay: p50 %v, p95 %v, max %v over %d runs (%d not started by the end, counted as late)",
		p50.Round(time.Millisecond), p95.Round(time.Millisecond), worst.Round(time.Millisecond), len(delays), censored)
	t.Logf("runs per device: min %d (expected about %d)", minRuns, int(wall/availEvery))
	t.Logf("stored points %d on %d devices, snmp_ok %.2f%%, up %.2f%%, largest gap between points %.1f s",
		rows, devs, 100*float64(snmpOK)/float64(max(rows, 1)), 100*float64(up)/float64(max(rows, 1)), maxGap)
	t.Logf("metrics stored for %d devices (sys) and %d devices (interfaces)", sysDevs, ifDevs)
	t.Logf("process CPU %.1f s = %.2f cores on average (Go runtime estimate, includes the test); heap in use peak %d MiB, from OS peak %d MiB, goroutines peak %d",
		u.cpuUsed, u.cpuUsed/wall.Seconds(), u.heapPeak/mib, u.sysPeak/mib, u.goroutinesPeak)
	t.Logf("db pool: max_conns %d, open peak %d, in use peak %d (1 s samples), %d of %d acquires waited, total wait %v",
		u.maxConns, u.connsPeak, u.acquiredPeak, u.waits, u.acquires, u.acquireWait.Round(time.Millisecond))
	t.Logf("poller warnings: %d lines (%s)", warnLines, logPath)
	if warnLines > 0 {
		t.Logf("first warnings:\n%s", firstLines(string(logged), 10))
	}

	byWindow := make([][]time.Duration, len(u.windows))
	for _, s := range starts {
		if i := int(s.due.Sub(began) / availEvery); i >= 0 && i < len(byWindow) {
			byWindow[i] = append(byWindow[i], s.at.Sub(s.due))
		}
	}
	table := "window(due)  runs  p95 delay   max delay  db in use  db waits  goroutines\n"
	var prevWaits int64
	for i, w := range u.windows {
		d := byWindow[i]
		slices.Sort(d)
		table += fmt.Sprintf("%4d-%-4ds %6d %10v %11v %10d %9d %11d\n", i*int(availEvery.Seconds()), (i+1)*int(availEvery.Seconds()),
			len(d), percentile(d, 0.95).Round(time.Millisecond), percentile(d, 1).Round(time.Millisecond), w.inUse, w.waits-prevWaits, w.goroutines)
		prevWaits = w.waits
	}
	t.Logf("per availability interval:\n%s", table)

	/* A run that finishes after its next due time reschedules from now, so lateness
	   after overruns is not accumulated in the delays: it is bounded by the minRuns and
	   censor checks below. */
	if p95 > p95Limit {
		t.Errorf("p95 availability start delay %v > %v", p95, p95Limit)
	}
	if want := int(wall/availEvery) - 2; minRuns < want {
		t.Errorf("a device ran availability %d times, want at least %d", minRuns, want)
	}
	if started := len(starts) - censored; rows < started-256 { /* runs still writing at the stop may miss their point */
		t.Errorf("%d points stored for %d started runs", rows, started)
	}
	/* a sanity guard on the simulator, not an acceptance criterion */
	if float64(snmpOK) < 0.90*float64(rows) {
		t.Errorf("SNMP answered in %d of %d points (< 90%%): simulator or host starvation, the poller was not what was measured", snmpOK, rows)
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitAfter(s, "\n")
	return strings.Join(lines[:min(n, len(lines))], "")
}
