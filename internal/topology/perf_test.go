package topology_test

import (
	"testing"
	"time"
)

/* TestFiveThousandDevices measures a build over 5 000 devices in a chain, each with LLDP on both ends of every link. */
func TestFiveThousandDevices(t *testing.T) {
	if testing.Short() {
		t.Skip("load test")
	}
	h := newHarness(t)
	const n = 5000
	h.exec(`INSERT INTO core.device (name, address, group_id)
		SELECT 'p-' || i, ('10.64.0.0'::inet + i), $1 FROM generate_series(1, $2) i`, h.group, n)
	h.exec(`INSERT INTO inventory.interface SELECT d.id, x, 'g' || x, '', 1000000000, true, now() FROM core.device d, generate_series(1, 4) x`)
	/* device i port 1 <-> device i+1 port 2 */
	h.exec(`WITH d AS (SELECT id, name, host(address) AS ip, lead(id) OVER (ORDER BY id) AS nid FROM core.device)
		INSERT INTO inventory.lldp_neighbor (device_id, local_if_index, chassis_id, port_id, sys_name, mgmt_addr, seen_at)
		SELECT d.id, 1, 'chassis-' || n.name, 'g2', n.name, n.ip::inet, now() FROM d JOIN d n ON n.id = d.nid`)
	h.exec(`WITH d AS (SELECT id, name, host(address) AS ip, lead(id) OVER (ORDER BY id) AS nid FROM core.device)
		INSERT INTO inventory.lldp_neighbor (device_id, local_if_index, chassis_id, port_id, sys_name, mgmt_addr, seen_at)
		SELECT n.id, 2, 'chassis-' || d.name, 'g1', d.name, d.ip::inet, now() FROM d JOIN d n ON n.id = d.nid`)
	h.up()
	start := time.Now()
	res, err := h.b.Build(h.ctx)
	first := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if res.Appeared != n-1 {
		t.Fatalf("appeared %d", res.Appeared)
	}
	start = time.Now()
	res, err = h.b.Build(h.ctx)
	second := time.Since(start)
	if err != nil || res.Appeared != 0 || res.Disappeared != 0 || res.Links != n-1 {
		t.Fatalf("second build %+v %v", res, err)
	}
	t.Logf("5000 devices, %d links: first build %v, unchanged build %v", n-1, first, second)
	if first > 20*time.Second || second > 10*time.Second {
		t.Errorf("too slow: %v / %v", first, second)
	}
	for _, l := range h.links()[:3] {
		if l.conf != 100 {
			t.Errorf("%+v", l)
		}
	}
}
