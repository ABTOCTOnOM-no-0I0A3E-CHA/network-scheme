package topology_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/beekamai/network-scheme/internal/drivers/generic"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

type refDevice struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	Fixture string `yaml:"fixture"`
}

type refLink struct {
	A          string  `yaml:"a"`
	APort      string  `yaml:"a_port"`
	B          string  `yaml:"b"`
	BPort      string  `yaml:"b_port"`
	Source     string  `yaml:"source"`
	Confidence float64 `yaml:"confidence"`
}

/* end is "device port"; text() renders a link independent of the order of its ends. */
func (l refLink) text() string {
	x, y := l.A+" "+l.APort, l.B+" "+l.BPort
	if x > y {
		x, y = y, x
	}
	return fmt.Sprintf("%s <-> %s %s %.2f", x, y, l.Source, l.Confidence)
}

/*
TestReferenceTopology polls the topology fixtures (the generic driver against the
simulator), stores the inventory and compares the builder's links with
test/lab/topology.yaml, the reference of the end-to-end test.
*/
func TestReferenceTopology(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "lab", "topology.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Devices []refDevice `yaml:"devices"`
		Links   []refLink   `yaml:"links"`
	}
	if err := yaml.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	if len(ref.Devices) < 3 || len(ref.Links) == 0 {
		t.Fatalf("reference is empty: %+v", ref)
	}

	files := make([]string, len(ref.Devices))
	for i, d := range ref.Devices {
		files[i] = simtest.Fixture(d.Fixture + ".snmprec")
	}
	sim := simtest.Start(t, files...)

	h := newHarness(t)
	store := inventory.NewStore(testdb.New(t).Pool("nms_poller"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, d := range ref.Devices {
		var id int64
		if err := h.api.QueryRow(h.ctx, `INSERT INTO core.device (name, address, group_id) VALUES ($1, $2::inet, $3) RETURNING id`,
			d.Name, d.Address, h.group).Scan(&id); err != nil {
			t.Fatal(err)
		}
		r, c, err := snmp.Dial(ctx, sim, simtest.V2Cred(d.Fixture), snmp.Options{Timeout: 10 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		inv, err := generic.New().Inventory(ctx, r, nil)
		_ = c.Close()
		if err != nil {
			t.Fatalf("%s: %v", d.Name, err)
		}
		if err := store.Apply(ctx, id, inv, time.Now().UTC()); err != nil {
			t.Fatalf("%s: %v", d.Name, err)
		}
	}
	h.build()

	got := builtLinks(t, h.root)
	var want []string
	for _, l := range ref.Links {
		want = append(want, l.text())
	}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("links\n got %q\nwant %q", got, want)
	}
}

/* builtLinks renders core.link like refLink.text. */
func builtLinks(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
SELECT da.name, coalesce(ia.name, ''), db.name, coalesce(ib.name, ''), l.source, round(l.confidence::numeric, 2)::float8
FROM core.link l
JOIN core.device da ON da.id = l.a_device_id JOIN core.device db ON db.id = l.b_device_id
LEFT JOIN inventory.interface ia ON ia.device_id = l.a_device_id AND ia.if_index = l.a_if_index
LEFT JOIN inventory.interface ib ON ib.device_id = l.b_device_id AND ib.if_index = l.b_if_index`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var l refLink
		if err := rows.Scan(&l.A, &l.APort, &l.B, &l.BPort, &l.Source, &l.Confidence); err != nil {
			t.Fatal(err)
		}
		out = append(out, l.text())
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}
