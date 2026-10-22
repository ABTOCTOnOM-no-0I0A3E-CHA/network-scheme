package triggers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/notify"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/triggers"
	"github.com/beekamai/network-scheme/internal/triggers/metricsrc"
)

func TestMain(m *testing.M) { testdb.Main(m) }

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

/* harness is a clean database, a fake clock, an engine and a collector of its notifications. */
type harness struct {
	t      *testing.T
	ctx    context.Context
	env    *testdb.Env
	api    *pgxpool.Pool
	poller *pgxpool.Pool
	eventd *pgxpool.Pool
	root   *pgxpool.Pool
	clk    *fakeClock
	hub    *notify.Hub
	eng    *triggers.Engine
	group  int64
	n      atomic.Int64

	mu   sync.Mutex
	msgs []notify.Message
}

var addrSeq atomic.Int64

func newHarness(t *testing.T) *harness {
	t.Helper()
	env := testdb.New(t)
	h := &harness{t: t, ctx: context.Background(), env: env, api: env.Pool("nms_api"), poller: env.Pool("nms_poller"),
		eventd: env.Pool("nms_eventd"), root: env.Pool("postgres"), hub: notify.NewHub(),
		clk: &fakeClock{t: time.Now().UTC().Truncate(time.Second)}}
	h.reset()
	h.group = h.newGroup(nil)
	h.eng = h.newEngine(nil)
	ch, cancel := h.hub.Subscribe(nil)
	t.Cleanup(cancel)
	go func() {
		for m := range ch {
			h.mu.Lock()
			h.msgs = append(h.msgs, m)
			h.mu.Unlock()
		}
	}()
	h.step() /* creates the stream watermarks: events older than the first round are not replayed */
	return h
}

func (h *harness) newEngine(pollNow func(context.Context, int64) error) *triggers.Engine {
	return triggers.New(triggers.Config{Pool: h.api, Samples: metricsrc.Source{Store: metrics.NewStore(h.api)}, Channels: []notify.Channel{notify.Panel{Hub: h.hub}},
		Clock: h.clk, PollNow: pollNow})
}

/* reset empties everything the engine reads or writes, keeping the seed templates. */
func (h *harness) reset() {
	h.t.Helper()
	for _, q := range []string{
		`DELETE FROM problems.problem`, `DELETE FROM problems.engine_state`,
		`DELETE FROM core.maintenance_window`,
		`DELETE FROM core.monitoring_template WHERE name LIKE 'T:%'`,
		`DELETE FROM core.device`,
		`DELETE FROM events.trap`, `DELETE FROM events.syslog`, `DELETE FROM events.eventd_stats`,
		`DELETE FROM metrics.if_metrics`, `DELETE FROM metrics.sys_metrics`,
		`DELETE FROM inventory.poller_heartbeat`,
	} {
		if _, err := h.root.Exec(h.ctx, q); err != nil {
			h.t.Fatalf("%s: %v", q, err)
		}
	}
}

func (h *harness) exec(p *pgxpool.Pool, q string, args ...any) {
	h.t.Helper()
	if _, err := p.Exec(h.ctx, q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

func (h *harness) newGroup(parent *int64) int64 {
	h.t.Helper()
	var id int64
	err := h.api.QueryRow(h.ctx, `INSERT INTO core.device_group (parent_id, name) VALUES ($1, $2) RETURNING id`,
		parent, fmt.Sprintf("g-%d-%d", time.Now().UnixNano(), h.n.Add(1))).Scan(&id)
	if err != nil {
		h.t.Fatal(err)
	}
	return id
}

/* testDriver keeps the seeded driver templates (generic-snmp, eltex-*) away from test devices. */
const testDriver = "xt"

type devOpt func(*devSpec)

type devSpec struct {
	group  int64
	parent *int64
	poller string
	driver string
}

func inGroup(g int64) devOpt      { return func(d *devSpec) { d.group = g } }
func withParent(p int64) devOpt   { return func(d *devSpec) { d.parent = &p } }
func onPoller(id string) devOpt   { return func(d *devSpec) { d.poller = id } }
func withDriver(dr string) devOpt { return func(d *devSpec) { d.driver = dr } }

func (h *harness) newDevice(opts ...devOpt) int64 {
	h.t.Helper()
	s := devSpec{group: h.group, poller: "tp", driver: testDriver}
	for _, o := range opts {
		o(&s)
	}
	n := addrSeq.Add(1)
	var id int64
	err := h.api.QueryRow(h.ctx, `INSERT INTO core.device (name, address, group_id, parent_id, poller_id, driver)
		VALUES ($1, $2::inet, $3, $4, $5, $6) RETURNING id`,
		fmt.Sprintf("dev-%d", n), fmt.Sprintf("10.%d.%d.%d", 100+n/65000, n/250%250, n%250+1), s.group, s.parent, s.poller, s.driver).Scan(&id)
	if err != nil {
		h.t.Fatalf("device: %v", err)
	}
	return id
}

/* newTrigger adds a template for the group and a trigger in it. */
func (h *harness) newTrigger(group int64, kind, params string, durationS int, severity string) int64 {
	h.t.Helper()
	var tpl, id int64
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.monitoring_template (name, group_id) VALUES ($1, $2) RETURNING id`,
		fmt.Sprintf("T:%d:%d", time.Now().UnixNano(), h.n.Add(1)), group).Scan(&tpl); err != nil {
		h.t.Fatal(err)
	}
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.trigger (template_id, kind, params, duration_s, severity, name)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6) RETURNING id`, tpl, kind, params, durationS, severity, "trig "+kind).Scan(&id); err != nil {
		h.t.Fatalf("trigger: %v", err)
	}
	return id
}

/* heartbeat marks the test poller alive (the view compares with the database clock). */
func (h *harness) heartbeat(poller string) {
	h.t.Helper()
	h.exec(h.poller, `INSERT INTO inventory.poller_heartbeat (poller_id, at) VALUES ($1, now()) ON CONFLICT (poller_id) DO UPDATE SET at = now()`, poller)
}

func (h *harness) setState(dev int64, state string, since time.Time) {
	h.t.Helper()
	h.heartbeat("tp")
	h.exec(h.poller, `INSERT INTO inventory.device_status (device_id, state, since, last_poll_at, poller_id, last_error)
		VALUES ($1, $2, $3, $3, 'tp', '') ON CONFLICT (device_id) DO UPDATE SET state = $2, since = $3, last_poll_at = $3`, dev, state, since)
}

func (h *harness) writeIf(dev int64, idx int, ts time.Time, up bool) {
	h.t.Helper()
	h.exec(h.poller, `INSERT INTO metrics.if_metrics (device_id, if_index, ts, in_bps, out_bps, oper_up, speed_bps)
		VALUES ($1, $2, $3, 0, 0, $4, 1000000000)`, dev, idx, ts, up)
}

func (h *harness) writeIfRates(dev int64, idx int, ts time.Time, inBps float64) {
	h.t.Helper()
	h.exec(h.poller, `INSERT INTO metrics.if_metrics (device_id, if_index, ts, in_bps, out_bps, oper_up, speed_bps)
		VALUES ($1, $2, $3, $4, 0, true, 1000000000)`, dev, idx, ts, inBps)
}

func (h *harness) writeCPU(dev int64, ts time.Time, cpu float64) {
	h.t.Helper()
	h.exec(h.poller, `INSERT INTO metrics.sys_metrics (device_id, ts, cpu_pct) VALUES ($1, $2, $3)`, dev, ts, cpu)
}

func (h *harness) writeTrap(dev int64, ts time.Time, name string, ifIndex int) {
	h.t.Helper()
	vb := []map[string]string{}
	if ifIndex > 0 {
		vb = append(vb, map[string]string{"oid": fmt.Sprintf("1.3.6.1.2.1.2.2.1.1.%d", ifIndex), "type": "Integer", "value": fmt.Sprint(ifIndex)})
	}
	b, _ := json.Marshal(vb)
	h.exec(h.eventd, `INSERT INTO events.trap (ts, device_id, version, trap_oid, name, severity, varbinds, identified)
		VALUES ($1, $2, 2, $3, $4, 'average', $5::jsonb, true)`, ts, dev, "1.3.6.1.6.3.1.1.5."+name, name, string(b))
}

func (h *harness) writeSyslog(dev int64, ts time.Time, sev int, msg string) {
	h.t.Helper()
	h.exec(h.eventd, `INSERT INTO events.syslog (ts, device_id, facility, severity, host, app, msg, raw_len)
		VALUES ($1, $2, 1, $3, 'h', 'a', $4, 10)`, ts, dev, sev, msg)
}

func (h *harness) step() {
	h.t.Helper()
	if err := h.eng.StepAll(h.ctx); err != nil {
		h.t.Fatalf("step: %v", err)
	}
}

/* advance moves the clock and runs a full round. */
func (h *harness) advance(d time.Duration) {
	h.t.Helper()
	h.clk.Advance(d)
	h.step()
}

type prob struct {
	ID         int64
	Trigger    int64
	Sys        string
	Device     int64
	Object     string
	State      string
	Suppressed bool
	Reason     string
	Value      string
}

const probCols = `id, coalesce(trigger_id, 0), coalesce(system_kind, ''), coalesce(device_id, 0), object, state, suppressed, coalesce(resolve_reason, ''), coalesce(last_value, '')`

/* problems lists the problems of dev (0: all), oldest first. */
func (h *harness) problems(dev int64) []prob {
	h.t.Helper()
	q := `SELECT ` + probCols + ` FROM problems.problem WHERE ($1 = 0 OR device_id = $1) ORDER BY id`
	rows, err := h.api.Query(h.ctx, q, dev)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []prob
	for rows.Next() {
		var p prob
		if err := rows.Scan(&p.ID, &p.Trigger, &p.Sys, &p.Device, &p.Object, &p.State, &p.Suppressed, &p.Reason, &p.Value); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func (h *harness) openProblems(dev int64) []prob {
	var out []prob
	for _, p := range h.problems(dev) {
		if p.State != "resolved" {
			out = append(out, p)
		}
	}
	return out
}

/* take returns the notifications published so far and forgets them. */
func (h *harness) take() []notify.Message {
	time.Sleep(40 * time.Millisecond) /* the collector goroutine runs asynchronously */
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.msgs
	h.msgs = nil
	return out
}

func events(ms []notify.Message) map[notify.ProblemEvent]int {
	out := map[notify.ProblemEvent]int{}
	for _, m := range ms {
		out[m.Event]++
	}
	return out
}
