package poller

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/ssh"
)

type showEnv struct {
	*backupEnv
	uid   int64
	mu    sync.Mutex
	sent  []string /* command lines the fake device received */
	reply func(cmd ssh.ShowCommand) (string, error)
}

func newShowEnv(t *testing.T, addr string, ifaces ...string) *showEnv {
	t.Helper()
	e := &showEnv{backupEnv: newBackupEnv(t, addr)}
	e.p.showEvery = 0 /* tests run many commands back to back; TestShowGap sets it */
	e.reply = func(cmd ssh.ShowCommand) (string, error) { return "output of " + cmd.String(), nil }
	e.p.runShowCmd = func(_ context.Context, _ device, _ *devCache, _ drivers.Driver, cmd ssh.ShowCommand) (string, error) {
		e.mu.Lock()
		e.sent = append(e.sent, cmd.String())
		e.mu.Unlock()
		return e.reply(cmd)
	}
	/* The device is identified already: no SNMP needed. */
	e.p.sched.mu.Lock()
	e.p.sched.devs[e.dev].cache.drv = e.drv
	e.p.sched.mu.Unlock()
	pg := e.env.Pool("postgres")
	if err := pg.QueryRow(context.Background(), `INSERT INTO core."user" (username, password_phc) VALUES ('u-' || gen_random_uuid(), 'x') RETURNING id`).Scan(&e.uid); err != nil {
		t.Fatal(err)
	}
	for i, n := range ifaces {
		if _, err := pg.Exec(context.Background(), `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at)
			VALUES ($1, $2, $3, '', 1000000000, true, now())`, e.dev, i+1, n); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *showEnv) commands() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.sent...)
}

/* row inserts a result row as the api role would (it may set only device, user, key and args). */
func (e *showEnv) row(dev int64, key, args string) int64 {
	e.t.Helper()
	var id int64
	if err := e.env.Pool("nms_api").QueryRow(context.Background(),
		`INSERT INTO backups.show_result (device_id, user_id, command_key, args) VALUES ($1, $2, $3, $4::jsonb) RETURNING id`, dev, e.uid, key, args).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

type showState struct {
	status    string
	output    *string
	truncated bool
	finished  bool
}

func (e *showEnv) state(id int64) showState {
	e.t.Helper()
	var s showState
	if err := e.env.Pool("postgres").QueryRow(context.Background(),
		`SELECT status, output, truncated, finished_at IS NOT NULL FROM backups.show_result WHERE id = $1`, id).Scan(&s.status, &s.output, &s.truncated, &s.finished); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func TestShowRunsTheResolvedCommand(t *testing.T) {
	e := newShowEnv(t, "203.0.113.201:161", "gi1/0/1")
	cases := []struct{ key, args, want string }{
		{"version", `{}`, "show version"},
		{"interface_status", `{"interface": "gi1/0/1"}`, "show interfaces status gi1/0/1"},
		{"vlan_tag", `{"vlan": 100}`, "show vlan tag 100"},
		{"mac_table_vlan", `{"vlan": 4094}`, "show mac address-table vlan 4094"},
	}
	for _, c := range cases {
		id := e.row(e.dev, c.key, c.args)
		if err := e.p.runShow(context.Background(), id); err != nil {
			t.Fatalf("%s: %v", c.key, err)
		}
		s := e.state(id)
		if s.status != "done" || s.output == nil || *s.output != "output of "+c.want || s.truncated || !s.finished {
			t.Errorf("%s: state %+v", c.key, s)
		}
	}
	want := []string{"show version", "show interfaces status gi1/0/1", "show vlan tag 100", "show mac address-table vlan 4094"}
	if got := e.commands(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("sent %q, want %q", got, want)
	}
}

/* Review Focus 4: a row forged straight into the table (the api role may insert it) gets no command onto the wire. */
func TestShowRefusesForgedRows(t *testing.T) {
	e := newShowEnv(t, "203.0.113.202:161", "gi1/0/1", "gi1/0/2")
	other := e.device(netip.MustParseAddrPort("203.0.113.203:161"))
	if _, err := e.env.Pool("postgres").Exec(context.Background(), `INSERT INTO inventory.interface (device_id, if_index, name, alias, speed_bps, oper_up, seen_at)
		VALUES ($1, 1, 'gi1/0/9', '', 1, true, now())`, other); err != nil {
		t.Fatal(err)
	}
	forged := []struct{ name, key, args string }{
		{"pipe", "interface_status", `{"interface": "gi1/0/1 | include x"}`},
		{"newline", "interface_status", `{"interface": "gi1/0/1\nshow running-config"}`},
		{"crlf", "interface_status", `{"interface": "gi1/0/1\r\nreload"}`},
		{"semicolon", "interface_counters", `{"interface": "gi1/0/1;reload"}`},
		{"cyrillic", "interface_status", `{"interface": "gі1/0/1"}`},
		{"fullwidth slash", "interface_status", `{"interface": "gi1／0／1"}`},
		{"zero width", "interface_status", `{"interface": "gi1/0/1\u200b"}`},
		{"case", "interface_status", `{"interface": "GI1/0/1"}`},
		{"not in inventory", "interface_status", `{"interface": "gi1/0/3"}`},
		{"inventory of another device", "interface_status", `{"interface": "gi1/0/9"}`},
		{"long form on MES", "interface_status", `{"interface": "gigabitethernet 1/0/1"}`},
		{"empty", "interface_status", `{"interface": ""}`},
		{"number", "interface_status", `{"interface": 1}`},
		{"missing arg", "interface_status", `{}`},
		{"extra arg", "interface_status", `{"interface": "gi1/0/1", "vlan": 1}`},
		{"wrong kind", "interface_status", `{"vlan": 1}`},
		{"arg for a bare command", "version", `{"interface": "gi1/0/1"}`},
		{"vlan 0", "vlan_tag", `{"vlan": 0}`},
		{"vlan 4095", "vlan_tag", `{"vlan": 4095}`},
		{"vlan negative", "vlan_tag", `{"vlan": -1}`},
		{"vlan fraction", "vlan_tag", `{"vlan": 1.5}`},
		{"vlan string", "vlan_tag", `{"vlan": "10"}`},
		{"vlan injection", "vlan_tag", `{"vlan": "10 | include x"}`},
		{"vlan null", "vlan_tag", `{"vlan": null}`},
		{"unknown key", "reload", `{}`},
		{"config key", "running_config", `{}`},
		{"config key dashed", "show-running-config", `{}`},
		{"startup key", "startup_config", `{}`},
		{"unknown member", "version", `{"x": 1}`},
	}
	for _, c := range forged {
		id := e.row(e.dev, c.key, c.args)
		if err := e.p.runShow(context.Background(), id); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		s := e.state(id)
		if s.status != "failed" || s.output == nil || *s.output != errShowRefused || !s.finished {
			t.Errorf("%s: state %+v", c.name, s)
		}
	}
	if got := e.commands(); len(got) != 0 {
		t.Fatalf("commands reached the device: %q", got)
	}
}

func TestShowIgnoresRowsThatAreNotQueued(t *testing.T) {
	e := newShowEnv(t, "203.0.113.204:161")
	pg := e.env.Pool("postgres")
	done := e.row(e.dev, "version", `{}`)
	if _, err := pg.Exec(context.Background(), `UPDATE backups.show_result SET status = 'done', output = 'old', finished_at = now() WHERE id = $1`, done); err != nil {
		t.Fatal(err)
	}
	running := e.row(e.dev, "version", `{}`)
	if _, err := pg.Exec(context.Background(), `UPDATE backups.show_result SET status = 'running' WHERE id = $1`, running); err != nil {
		t.Fatal(err)
	}
	expired := e.row(e.dev, "version", `{}`)
	if _, err := pg.Exec(context.Background(), `UPDATE backups.show_result SET expires_at = now() - interval '1 second' WHERE id = $1`, expired); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{done, running, expired, 0, 987654321} {
		if err := e.p.runShow(context.Background(), id); err != nil {
			t.Fatalf("row %d: %v", id, err)
		}
	}
	if got := e.commands(); len(got) != 0 {
		t.Fatalf("commands sent: %q", got)
	}
	if s := e.state(done); s.status != "done" || *s.output != "old" {
		t.Errorf("done row changed: %+v", s)
	}
	if s := e.state(expired); s.status != "queued" {
		t.Errorf("expired row changed: %+v", s)
	}
	/* The same row is never run twice. */
	id := e.row(e.dev, "version", `{}`)
	for range 3 {
		if err := e.p.runShow(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.commands(); len(got) != 1 {
		t.Errorf("a row ran %d times", len(got))
	}
}

func TestShowOutputIsCappedAndCleaned(t *testing.T) {
	e := newShowEnv(t, "203.0.113.205:161")
	/* 3 MiB of two-byte characters: the cut must fall on a character boundary. */
	huge := strings.Repeat("é", 3<<19)
	e.reply = func(ssh.ShowCommand) (string, error) { return huge, nil }
	id := e.row(e.dev, "version", `{}`)
	if err := e.p.runShow(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	s := e.state(id)
	if s.status != "done" || !s.truncated || s.output == nil || len(*s.output) != maxShowOutput || !utf8.ValidString(*s.output) {
		t.Fatalf("huge: status %s truncated %v len %d", s.status, s.truncated, len(*s.output))
	}
	/* Exactly at the limit is not truncated. */
	e.reply = func(ssh.ShowCommand) (string, error) { return strings.Repeat("x", maxShowOutput), nil }
	id = e.row(e.dev, "system", `{}`)
	if err := e.p.runShow(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if s := e.state(id); s.truncated || len(*s.output) != maxShowOutput {
		t.Errorf("at the limit: truncated %v len %d", s.truncated, len(*s.output))
	}
	/* Control, escape, bidi and invalid bytes never reach the row (NUL could not even be stored). */
	e.reply = func(ssh.ShowCommand) (string, error) {
		return "a\x00b\x1b[31mred\x07\r\nline\ttab\u202ertl\u200b\xff\xfe end\x7f", nil
	}
	id = e.row(e.dev, "arp", `{}`)
	if err := e.p.runShow(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if s := e.state(id); s.status != "done" || s.truncated || *s.output != "ab[31mred\nline\ttabrtl�� end" {
		t.Errorf("cleaned = %q", *s.output)
	}
}

func TestCleanShowOutputBoundary(t *testing.T) {
	/* A three-byte character that does not fit whole is dropped, not split. */
	in := strings.Repeat("a", maxShowOutput-2) + "€tail"
	out, trunc := cleanShowOutput(in)
	if !trunc || len(out) != maxShowOutput-2 || !utf8.ValidString(out) {
		t.Errorf("len %d truncated %v valid %v", len(out), trunc, utf8.ValidString(out))
	}
	if out, trunc := cleanShowOutput(""); out != "" || trunc {
		t.Errorf("empty = %q %v", out, trunc)
	}
}

func TestShowFailuresStoreFixedTexts(t *testing.T) {
	e := newShowEnv(t, "203.0.113.206:161")
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"device text", fmt.Errorf("SECRET-DEVICE-TEXT enable password hunter2"), errShowRefused},
		{"too large", &showFailed{text: errShowTooLarge, err: ssh.ErrOutputTooLarge}, errShowTooLarge},
		{"timeout", context.DeadlineExceeded, errShowTimedOut},
		{"ssh", &showFailed{text: errSSHFailed, err: errors.New("SECRET-DEVICE-TEXT")}, errSSHFailed},
	}
	for _, c := range cases {
		e.reply = func(ssh.ShowCommand) (string, error) { return "", c.err }
		id := e.row(e.dev, "version", `{}`)
		if err := e.p.runShow(context.Background(), id); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		s := e.state(id)
		if s.status != "failed" || s.output == nil || *s.output != c.want {
			t.Errorf("%s: %+v", c.name, s)
		}
		if strings.Contains(e.logs.String(), "SECRET-DEVICE-TEXT") {
			t.Fatalf("%s: device text in the log: %s", c.name, e.logs.String())
		}
	}
}

func TestShowNotMineAndInFlight(t *testing.T) {
	e := newShowEnv(t, "203.0.113.207:161")
	var foreign int64
	e.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) (err error) {
		foreign, err = st.Create(ctx, tx, devices.NewDevice{Name: "foreign", Address: netip.MustParseAddr("203.0.113.208"), GroupID: e.group, PollerID: "someone-else"})
		return err
	})
	id := e.row(foreign, "version", `{}`)
	if err := e.p.runShow(context.Background(), id); !errors.Is(err, errNotMine) {
		t.Fatalf("foreign device: %v", err)
	}
	if s := e.state(id); s.status != "queued" || len(e.commands()) != 0 {
		t.Errorf("foreign row: %+v, commands %q", s, e.commands())
	}
	/* One command per device in flight: the second request meanwhile fails at once. */
	entered, release := make(chan struct{}), make(chan struct{})
	e.reply = func(ssh.ShowCommand) (string, error) {
		close(entered)
		<-release
		return "slow", nil
	}
	first := e.row(e.dev, "version", `{}`)
	done := make(chan error, 1)
	go func() { done <- e.p.runShow(context.Background(), first) }()
	<-entered
	second := e.row(e.dev, "system", `{}`)
	if err := e.p.runShow(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if s := e.state(second); s.status != "failed" || *s.output != errShowDeviceBusy {
		t.Errorf("second: %+v", s)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s := e.state(first); s.status != "done" || *s.output != "slow" {
		t.Errorf("first: %+v", s)
	}
	if got := e.commands(); len(got) != 1 {
		t.Errorf("sent %q", got)
	}
}

func TestShowResultsExpireAndAreDeleted(t *testing.T) {
	e := newShowEnv(t, "203.0.113.209:161")
	old, fresh := e.row(e.dev, "version", `{}`), e.row(e.dev, "version", `{}`)
	var ttl time.Duration
	if err := e.env.Pool("postgres").QueryRow(context.Background(), `SELECT expires_at - requested_at FROM backups.show_result WHERE id = $1`, fresh).Scan(&ttl); err != nil {
		t.Fatal(err)
	}
	if ttl != time.Hour {
		t.Errorf("ttl = %v, want 1h", ttl)
	}
	if _, err := e.env.Pool("postgres").Exec(context.Background(), `UPDATE backups.show_result SET expires_at = now() - interval '1 second' WHERE id = $1`, old); err != nil {
		t.Fatal(err)
	}
	if err := e.p.deleteExpiredShow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM backups.show_result WHERE id = $1`, old) != 0 || e.count(`SELECT count(*) FROM backups.show_result WHERE id = $1`, fresh) != 1 {
		t.Error("expired row kept or fresh row deleted")
	}
}

/* The whole path through River: the show queue, the worker, and the job of a device that is not ours. */
func TestShowNowJobs(t *testing.T) {
	e := newShowEnv(t, "203.0.113.210:161", "gi1/0/1")
	var foreign int64
	e.api(func(ctx context.Context, tx pgx.Tx, st *devices.Store) (err error) {
		foreign, err = st.Create(ctx, tx, devices.NewDevice{Name: "foreign", Address: netip.MustParseAddr("203.0.113.211"), GroupID: e.group, PollerID: "someone-else"})
		return err
	})
	start(t, e.p)
	api := e.env.Pool("nms_api")
	enq, err := jobs.NewEnqueuer(api)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	queue := func(dev, id int64) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, api, func(tx pgx.Tx) error { return enq.EnqueueShowNow(ctx, tx, dev, id) }); err != nil {
			t.Fatal(err)
		}
	}
	good := e.row(e.dev, "interface_status", `{"interface": "gi1/0/1"}`)
	queue(e.dev, good)
	eventually(t, 15*time.Second, "show done", func() bool { return e.state(good).status == "done" })
	if s := e.state(good); *s.output != "output of show interfaces status gi1/0/1" {
		t.Errorf("output %q", *s.output)
	}
	var queueName string
	if err := e.env.Pool("postgres").QueryRow(ctx, `SELECT queue FROM jobs.river_job WHERE kind = 'show_now' LIMIT 1`).Scan(&queueName); err != nil || queueName != "show_"+e.pollerID {
		t.Errorf("queue %q, %v", queueName, err)
	}
	/* A job for a device of another poller cannot be routed here by the api: a forged one is cancelled and the row failed. */
	forgedRow := e.row(foreign, "version", `{}`)
	var q string
	if err := e.env.Pool("postgres").QueryRow(ctx, `SELECT queue FROM jobs.river_job WHERE kind = 'show_now' LIMIT 1`).Scan(&q); err != nil {
		t.Fatal(err)
	}
	if _, err := e.env.Pool("postgres").Exec(ctx, `INSERT INTO jobs.river_job (kind, queue, args, state, max_attempts) VALUES ('show_now', $1, jsonb_build_object('result_id', $2::bigint), 'available', 1)`, q, forgedRow); err != nil {
		t.Fatal(err)
	}
	eventually(t, 20*time.Second, "forged job cancelled", func() bool {
		return e.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'show_now' AND state = 'cancelled'`) == 1
	})
	/* The row is left alone: the poller that owns the device may be running it. */
	if s := e.state(forgedRow); s.status != "queued" || s.output != nil {
		t.Errorf("forged: %+v", s)
	}
	if got := e.commands(); len(got) != 1 {
		t.Errorf("sent %q", got)
	}
	eventually(t, 10*time.Second, "show jobs finished", func() bool {
		return e.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'show_now' AND state IN ('available', 'running', 'retryable')`) == 0
	})
	if n := e.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'show_now' AND state = 'cancelled'`); n != 1 {
		t.Errorf("%d cancelled show jobs, want the forged one", n)
	}
}

/* Sequential rows for one device inside the gap: only the first reaches the device. */
func TestShowGapBoundsSequentialRows(t *testing.T) {
	e := newShowEnv(t, "203.0.113.212:161")
	e.p.showEvery = time.Hour
	other := e.device(netip.MustParseAddrPort("203.0.113.213:161"))
	if err := e.p.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.p.sched.mu.Lock()
	e.p.sched.devs[other].cache.drv = e.drv
	e.p.sched.mu.Unlock()
	var ids []int64
	for range 8 {
		ids = append(ids, e.row(e.dev, "version", `{}`))
	}
	for _, id := range ids {
		if err := e.p.runShow(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.commands(); len(got) != 1 {
		t.Fatalf("%d commands reached the device, want 1: %q", len(got), got)
	}
	if s := e.state(ids[0]); s.status != "done" {
		t.Errorf("first: %+v", s)
	}
	for _, id := range ids[1:] {
		if s := e.state(id); s.status != "failed" || *s.output != errShowTooSoon {
			t.Errorf("row %d: %+v", id, s)
		}
	}
	/* Another device has its own gap. */
	if err := e.p.runShow(context.Background(), e.row(other, "version", `{}`)); err != nil || len(e.commands()) != 2 {
		t.Fatalf("other device: %v %q", err, e.commands())
	}
	/* After the gap the device is reachable again. */
	e.p.showEvery = 0
	id := e.row(e.dev, "version", `{}`)
	if err := e.p.runShow(context.Background(), id); err != nil || e.state(id).status != "done" {
		t.Errorf("after the gap: %v %+v", err, e.state(id))
	}
}

/* A job whose context ended while it waited for the device lock does not leave its row queued. */
func TestShowInterruptedRowIsFailed(t *testing.T) {
	e := newShowEnv(t, "203.0.113.214:161")
	e.p.sched.mu.Lock()
	lk := e.p.sched.devs[e.dev].lock
	e.p.sched.mu.Unlock()
	if err := lk.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer lk.Unlock()
	id := e.row(e.dev, "version", `{}`)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := e.p.runShow(ctx, id); err == nil {
		t.Fatal("expected the cancelled wait to fail")
	}
	if s := e.state(id); s.status != "failed" || *s.output != errShowInterrupted || len(e.commands()) != 0 {
		t.Errorf("row: %+v", s)
	}
}
