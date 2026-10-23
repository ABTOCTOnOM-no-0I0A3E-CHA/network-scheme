package poller

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

func TestPollerRecordsTheV3EngineID(t *testing.T) {
	addr := simtest.Start(t, simtest.Fixture("eltex-mes.snmprec"))
	h := newHarness(t, "eltex-mes")
	id := h.device(addr)
	h.simProfile(id)
	start(t, h.poller(Intervals{Availability: time.Second, Metrics: time.Hour, Inventory: time.Hour}))
	eventually(t, 15*time.Second, "engine ID recorded", func() bool {
		return h.count(`SELECT count(*) FROM core.device_v3_engine WHERE device_id = $1 AND octet_length(engine_id) BETWEEN 5 AND 32`, id) == 1
	})
	var engine []byte
	if err := h.env.Pool("postgres").QueryRow(context.Background(), `SELECT engine_id FROM core.device_v3_engine WHERE device_id = $1`, id).Scan(&engine); err != nil {
		t.Fatal(err)
	}
	if len(engine) < 5 {
		t.Fatalf("engine ID = %x", engine)
	}
}

func TestEngineIDIsRecordedOnlyForOwnDevicesAndOnlyWhenChanged(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	mine := h.device(netip.MustParseAddrPort("198.51.100.200:161"))
	var foreign int64
	if err := h.env.Pool("nms_api").QueryRow(ctx, `INSERT INTO core.device (name, address, group_id, poller_id) VALUES ('f', '198.51.100.201', $1, 'someone-else') RETURNING id`, h.group).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	cache := newDevCache()
	id := []byte{0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3}
	if !p.recordEngine(ctx, device{ID: mine}, cache, id) || !p.recordEngine(ctx, device{ID: foreign}, newDevCache(), id) {
		t.Fatal("recordEngine reported failure")
	}
	if n := h.count(`SELECT count(*) FROM core.device_v3_engine WHERE device_id = $1`, mine); n != 1 {
		t.Fatalf("own device rows = %d", n)
	}
	if n := h.count(`SELECT count(*) FROM core.device_v3_engine WHERE device_id = $1`, foreign); n != 0 {
		t.Fatalf("a device of another poller got an engine ID")
	}
	/* Unchanged: no write (seen_at stays), changed: replaced. */
	before := h.str(`SELECT seen_at::text FROM core.device_v3_engine WHERE device_id = $1`, mine)
	p.recordEngine(ctx, device{ID: mine}, cache, id)
	if after := h.str(`SELECT seen_at::text FROM core.device_v3_engine WHERE device_id = $1`, mine); after != before {
		t.Fatal("unchanged engine ID was written again")
	}
	p.recordEngine(ctx, device{ID: mine}, cache, []byte{0x80, 9, 9, 9, 9})
	if got := h.str(`SELECT encode(engine_id, 'hex') FROM core.device_v3_engine WHERE device_id = $1`, mine); got != "8009090909" {
		t.Fatalf("engine ID = %s", got)
	}
	/* Out-of-range IDs are not recorded. */
	if p.recordEngine(ctx, device{ID: mine}, cache, []byte{1, 2, 3}) {
		t.Fatal("short engine ID accepted")
	}
}

func TestAPICannotPlantEngineIDs(t *testing.T) {
	h := newHarness(t, "")
	ctx := context.Background()
	id := h.device(netip.MustParseAddrPort("198.51.100.202:161"))
	for _, sql := range []string{
		`INSERT INTO core.device_v3_engine (device_id, engine_id) VALUES ($1, '\x8000000001')`,
		`UPDATE core.device_v3_engine SET engine_id = '\x8000000001' WHERE device_id = $1`,
		`DELETE FROM core.device_v3_engine WHERE device_id = $1`,
		`SELECT engine_id FROM core.device_v3_engine WHERE device_id = $1`,
	} {
		_, err := h.env.Pool("nms_api").Exec(ctx, sql, id)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "42501" {
			t.Errorf("%s as nms_api: %v, want permission denied", sql, err)
		}
	}
	/* The poller cannot delete or change the device it belongs to either. */
	if _, err := h.env.Pool("nms_poller").Exec(ctx, `DELETE FROM core.device_v3_engine WHERE device_id = $1`, id); err == nil {
		t.Error("nms_poller can delete engine IDs")
	}
}

func TestEngineIDChangeNotifiesEventdAndPoller(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	id := h.device(netip.MustParseAddrPort("198.51.100.203:161"))
	conn, err := h.env.Pool("nms_eventd").Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN device_changed`); err != nil {
		t.Fatal(err)
	}
	wait := func(want bool) {
		t.Helper()
		wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		_, err := conn.Conn().WaitForNotification(wctx)
		if (err == nil) != want {
			t.Fatalf("notification = %v, want %v (err %v)", err == nil, want, err)
		}
	}
	cache := newDevCache()
	p.recordEngine(ctx, device{ID: id}, cache, []byte{0x80, 1, 1, 1, 1})
	wait(true)
	p.recordEngine(ctx, device{ID: id}, newDevCache(), []byte{0x80, 1, 1, 1, 1}) /* same ID, other cache: written, unchanged */
	wait(false)
	p.recordEngine(ctx, device{ID: id}, cache, []byte{0x80, 2, 2, 2, 2})
	wait(true)
}
