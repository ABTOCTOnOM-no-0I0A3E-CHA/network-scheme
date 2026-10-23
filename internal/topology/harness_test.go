package topology_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/topology"
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

type harness struct {
	t     *testing.T
	ctx   context.Context
	api   *pgxpool.Pool
	root  *pgxpool.Pool
	clk   *fakeClock
	b     *topology.Builder
	group int64
	n     int
}

/* newHarness starts from an empty device table (links, interfaces and neighbour data go with the devices; link_change is append-only and stays). */
func newHarness(t *testing.T) *harness {
	t.Helper()
	env := testdb.New(t)
	h := &harness{t: t, ctx: context.Background(), api: env.Pool("nms_api"), root: env.Pool("postgres"),
		clk: &fakeClock{t: time.Now().UTC().Truncate(time.Second)}}
	h.exec(`DELETE FROM core.device`)
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.device_group (name) VALUES ($1) RETURNING id`, fmt.Sprintf("topo-%d", time.Now().UnixNano())).Scan(&h.group); err != nil {
		t.Fatal(err)
	}
	h.b = topology.New(topology.Config{Pool: h.api, Clock: h.clk})
	return h
}

func (h *harness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.root.Exec(h.ctx, q, args...); err != nil {
		h.t.Fatalf("%s: %v", q, err)
	}
}

/* dev adds a device named name at 10.88.0.n with four interfaces g1..g4 (ifindex 1..4), up. */
func (h *harness) dev(name string) (id int64, addr string) {
	h.t.Helper()
	h.n++
	addr = fmt.Sprintf("10.88.%d.%d", h.n/250, h.n%250+1)
	if err := h.api.QueryRow(h.ctx, `INSERT INTO core.device (name, address, group_id) VALUES ($1, $2::inet, $3) RETURNING id`, name, addr, h.group).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	h.exec(`INSERT INTO inventory.interface SELECT $1, x, 'g' || x, '', 1000000000, true, now() FROM generate_series(1, 4) x`, id)
	return id, addr
}

/* nb adds an LLDP row: dev sees a neighbour on its port ifx. */
func (h *harness) nb(dev int64, ifx int, chassis, portID, sysName, mgmt string) {
	h.t.Helper()
	var m any
	if mgmt != "" {
		m = mgmt
	}
	h.exec(`INSERT INTO inventory.lldp_neighbor (device_id, local_if_index, chassis_id, port_id, sys_name, mgmt_addr, seen_at)
		VALUES ($1, $2, $3, $4, $5, $6::inet, now())`, dev, ifx, chassis, portID, sysName, m)
}

func (h *harness) dropNb(dev int64) {
	h.exec(`DELETE FROM inventory.lldp_neighbor WHERE device_id = $1`, dev)
}

/* up marks every device up under a fresh heartbeat; down then marks some down. */
func (h *harness) up(down ...int64) {
	h.t.Helper()
	h.exec(`INSERT INTO inventory.poller_heartbeat (poller_id, at) SELECT DISTINCT poller_id, now() FROM core.device
		ON CONFLICT (poller_id) DO UPDATE SET at = now()`)
	h.exec(`INSERT INTO inventory.device_status (device_id, state, since, last_poll_at, poller_id)
		SELECT id, CASE WHEN id = ANY($1) THEN 'down' ELSE 'up' END, now(), now(), poller_id FROM core.device
		ON CONFLICT (device_id) DO UPDATE SET state = EXCLUDED.state`, down)
}

func (h *harness) build(down ...int64) topology.Result {
	h.t.Helper()
	h.up(down...)
	h.clk.Advance(time.Minute)
	res, err := h.b.Build(h.ctx)
	if err != nil {
		h.t.Fatalf("build: %v", err)
	}
	return res
}

type row struct {
	id     int64
	a, b   int64
	ai, bi int
	source string
	conf   int
	manual bool
	misses int
}

func (h *harness) links() []row {
	h.t.Helper()
	rows, err := h.root.Query(h.ctx, `SELECT id, a_device_id, coalesce(a_if_index, 0), b_device_id, coalesce(b_if_index, 0), source,
		round(confidence * 100)::int, manual, misses FROM core.link ORDER BY id`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.a, &r.ai, &r.b, &r.bi, &r.source, &r.conf, &r.manual, &r.misses); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

/* between returns the links between x and y, whatever the order. */
func (h *harness) between(x, y int64) []row {
	var out []row
	for _, r := range h.links() {
		if (r.a == x && r.b == y) || (r.a == y && r.b == x) {
			out = append(out, r)
		}
	}
	return out
}

/* one requires exactly one link between x and y and returns it. */
func (h *harness) one(x, y int64) row {
	h.t.Helper()
	ls := h.between(x, y)
	if len(ls) != 1 {
		h.t.Fatalf("links between %d and %d: want 1, have %+v", x, y, ls)
	}
	return ls[0]
}

/* ports returns the ports of r as seen from x then y. */
func (r row) ports(x int64) (int, int) {
	if r.a == x {
		return r.ai, r.bi
	}
	return r.bi, r.ai
}

func (h *harness) changes(devs ...int64) (appeared, disappeared int) {
	h.t.Helper()
	rows, err := h.root.Query(h.ctx, `SELECT change, count(*) FROM core.link_change WHERE a_device_id = ANY($1) OR b_device_id = ANY($1) GROUP BY change`, devs)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		var n int
		if err := rows.Scan(&c, &n); err != nil {
			h.t.Fatal(err)
		}
		if c == "appeared" {
			appeared = n
		} else {
			disappeared = n
		}
	}
	return
}
