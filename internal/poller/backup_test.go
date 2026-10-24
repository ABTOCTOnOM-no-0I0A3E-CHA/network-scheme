package poller

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/eltexmes"
	"github.com/beekamai/network-scheme/internal/jobs"
)

const mesFixture = "../../test/fixtures/configs/mes-secrets"

/* cfgDriver is the real MES driver with a switchable ConfigNeedsWrite; the fetch itself is replaced through Poller.fetchRaw. */
type cfgDriver struct {
	drivers.Driver
	needsWrite bool
}

func (c cfgDriver) ConfigNeedsWrite() bool { return c.needsWrite }

type fetched struct {
	text string
	err  error
}

type backupEnv struct {
	*harness
	p      *Poller
	dev    int64
	bpub   *[32]byte
	bpriv  *[32]byte
	cfg    atomic.Pointer[fetched] /* what the fake device returns */
	fetchN atomic.Int64
	logs   *bytes.Buffer
	drv    cfgDriver
}

func newBackupEnv(t *testing.T, addr string) *backupEnv {
	t.Helper()
	h := newHarness(t, "")
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &backupEnv{harness: h, bpub: pub, bpriv: priv, logs: &bytes.Buffer{}}
	e.drv = cfgDriver{Driver: drivers.Default().ByName(eltexmes.Name)}
	e.dev = h.device(netip.MustParseAddrPort(addr))
	e.p = New(h.config(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour}), Deps{
		Pool: h.env.Pool("nms_poller"), Priv: h.priv, Pub: h.pub, BackupPub: pub, Pinger: fakePinger{ok: true},
		Logger: slog.New(slog.NewTextHandler(e.logs, nil)),
	})
	e.p.fetchRaw = func(context.Context, device, *devCache, drivers.Driver) (string, error) {
		e.fetchN.Add(1)
		if f := e.cfg.Load(); f != nil {
			return f.text, f.err
		}
		return "", errors.New("no config")
	}
	if err := e.p.reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *backupEnv) run(source string) error {
	return e.p.sched.runNow(context.Background(), e.dev, func(d device, c *devCache) error {
		c.drv = e.drv
		return e.p.backupDevice(context.Background(), d, c, source, nil)
	})
}

type version struct {
	id      int64
	sha     []byte
	source  string
	drift   bool
	masked  string
	ct, dek []byte
}

func (e *backupEnv) versions(dev int64) []version {
	e.t.Helper()
	rows, err := e.env.Pool("postgres").Query(context.Background(),
		`SELECT id, sha256, source, drift, masked, full_ct, full_dek_ct FROM backups.config_version WHERE device_id = $1 ORDER BY id`, dev)
	if err != nil {
		e.t.Fatal(err)
	}
	vs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (v version, err error) {
		err = r.Scan(&v.id, &v.sha, &v.source, &v.drift, &v.masked, &v.ct, &v.dek)
		return
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return vs
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fixtureSecrets(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(readFixture(t, mesFixture+".secrets"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	if len(out) < 10 {
		t.Fatalf("fixture secrets: %d", len(out))
	}
	return out
}

func TestBackupStoresAVersionOnlyWhenTheHashChanges(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.101:161")
	raw := readFixture(t, mesFixture+".txt")
	e.cfg.Store(&fetched{text: raw})
	if err := e.run(sourceSchedule); err != nil {
		t.Fatal(err)
	}
	vs := e.versions(e.dev)
	if len(vs) != 1 || vs[0].drift || vs[0].source != "schedule" {
		t.Fatalf("first backup: %+v", vs)
	}
	/* Both copies are made from the RAW text: the ciphertext opens to it, byte for byte, volatile header included. */
	aad := backup.AAD(e.dev, hex.EncodeToString(vs[0].sha))
	got, err := open.Open(e.bpriv, e.bpub, vs[0].ct, vs[0].dek, aad)
	if err != nil || string(got) != raw {
		t.Fatalf("ciphertext does not open to the raw configuration: %v", err)
	}
	for _, s := range fixtureSecrets(t) {
		if strings.Contains(vs[0].masked, s) {
			t.Errorf("masked copy contains %q", s)
		}
	}
	if !strings.Contains(vs[0].masked, "sw-lab-01") || !strings.Contains(vs[0].masked, "! Last configuration change at") {
		t.Error("masked copy lost structure or the raw header (it must be made from the raw text)")
	}
	wantSum := sha256.Sum256([]byte(e.drv.NormalizeConfig(raw)))
	if !bytes.Equal(vs[0].sha, wantSum[:]) {
		t.Error("stored hash is not the hash of the normalized text")
	}

	/* Only volatile lines differ: no new version, but the state is touched. */
	e.cfg.Store(&fetched{text: strings.Replace(raw, "10:21:33 UTC Mon Oct 20 2026", "23:59:59 UTC Tue Oct 21 2026", 1)})
	if err := e.run(sourceSchedule); err != nil {
		t.Fatal(err)
	}
	if n := len(e.versions(e.dev)); n != 1 {
		t.Fatalf("volatile change made %d versions", n)
	}
	if n := e.count(`SELECT count(*) FROM backups.backup_state WHERE device_id = $1 AND last_ok_at IS NOT NULL AND last_error IS NULL AND NOT needs_write`, e.dev); n != 1 {
		t.Fatal("backup_state not updated")
	}

	/* A real change: a new version, drift (an earlier version exists). */
	e.cfg.Store(&fetched{text: raw + "vlan 30\n"})
	if err := e.run(sourceEvent); err != nil {
		t.Fatal(err)
	}
	vs = e.versions(e.dev)
	if len(vs) != 2 || !vs[1].drift || vs[1].source != "event" {
		t.Fatalf("after a change: %+v", vs[1:])
	}
	/* A change taken as the pre-session snapshot is not drift. */
	e.cfg.Store(&fetched{text: raw + "vlan 31\n"})
	if err := e.run(sourcePreSess); err != nil {
		t.Fatal(err)
	}
	if vs = e.versions(e.dev); len(vs) != 3 || vs[2].drift {
		t.Fatalf("pre_session: %+v", vs[2:])
	}

	/* AAD binding: no other hash, no other device, no other key opens a ciphertext. */
	other := backup.AAD(e.dev, hex.EncodeToString(vs[1].sha))
	if _, err := open.Open(e.bpriv, e.bpub, vs[0].ct, vs[0].dek, other); err == nil {
		t.Error("ciphertext opened with another version's hash")
	}
	if _, err := open.Open(e.bpriv, e.bpub, vs[0].ct, vs[0].dek, backup.AAD(e.dev+1, hex.EncodeToString(vs[0].sha))); err == nil {
		t.Error("ciphertext opened as another device's")
	}
	if _, err := open.Open(e.bpriv, e.bpub, vs[1].ct, vs[0].dek, backup.AAD(e.dev, hex.EncodeToString(vs[1].sha))); err == nil {
		t.Error("ciphertext opened with another version's data key")
	}
	otherPub, otherPriv, _ := box.GenerateKey(rand.Reader)
	if _, err := open.Open(otherPriv, otherPub, vs[0].ct, vs[0].dek, aad); err == nil {
		t.Error("ciphertext opened without the backup private key")
	}
	if _, err := open.Open(e.bpub, e.bpub, vs[0].ct, vs[0].dek, aad); err == nil {
		t.Error("ciphertext opened with the public key")
	}
}

func TestBackupNeedsWriteIsRecordedAndNotFetched(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.102:161")
	e.drv.needsWrite = true
	e.cfg.Store(&fetched{text: "hostname x\n"})
	if err := e.run(sourceSchedule); err != nil {
		t.Fatal(err)
	}
	if e.fetchN.Load() != 0 {
		t.Fatal("the configuration was fetched from a model that needs a write account")
	}
	if len(e.versions(e.dev)) != 0 {
		t.Fatal("a version was stored")
	}
	if e.count(`SELECT count(*) FROM backups.backup_state WHERE device_id = $1 AND needs_write AND last_error = $2`, e.dev, errNeedsWrite) != 1 {
		t.Fatal("needs_write not recorded")
	}
	/* Once the model no longer needs it, the flag clears with the next successful backup. */
	e.drv.needsWrite = false
	if err := e.run(sourceSchedule); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM backups.backup_state WHERE device_id = $1 AND NOT needs_write AND last_error IS NULL`, e.dev) != 1 {
		t.Fatal("needs_write not cleared")
	}
}

/* A failed fetch records a fixed text; neither the device's words nor config text reach the database or the log. */
func TestBackupErrorsCarryNoDeviceText(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.103:161")
	e.cfg.Store(&fetched{err: errors.New("password Hunter2Secret rejected; username admin password S3cretValue")})
	if err := e.run(sourceSchedule); err == nil {
		t.Fatal("no error")
	}
	if got := e.str(`SELECT last_error FROM backups.backup_state WHERE device_id = $1`, e.dev); got != errFetchFailed {
		t.Fatalf("last_error = %q", got)
	}
	if strings.Contains(e.logs.String(), "Hunter2Secret") || strings.Contains(e.logs.String(), "S3cretValue") {
		t.Fatalf("device text in the log:\n%s", e.logs)
	}
	if len(e.versions(e.dev)) != 0 {
		t.Fatal("version stored after a failure")
	}
	/* Oversize is refused with a counter. */
	e.cfg.Store(&fetched{text: strings.Repeat("a", maxConfigBytes+1)})
	if err := e.run(sourceSchedule); err == nil || e.p.backupOversize.Load() != 1 {
		t.Fatalf("oversize: %v, counter %d", err, e.p.backupOversize.Load())
	}
	if got := e.str(`SELECT last_error FROM backups.backup_state WHERE device_id = $1`, e.dev); got != errTooLarge {
		t.Fatalf("last_error = %q", got)
	}
}

/* The masked copy and the ciphertext are one row, written with the state in one transaction: a failing state write leaves no version. */
func TestBackupVersionAndStateShareATransaction(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.104:161")
	const ghost = int64(987654321) /* no such device: backup_state's foreign key fails after the version insert */
	var sum [32]byte
	err := e.p.storeVersion(context.Background(), ghost, sourceSchedule, sum, 3, "masked", []byte("ct"), []byte("dek"), false, nil)
	if err == nil {
		t.Fatal("stored for a missing device")
	}
	if len(e.versions(ghost)) != 0 {
		t.Fatal("the version insert survived the failed state write")
	}
	if err := e.p.storeVersion(context.Background(), e.dev, sourceSchedule, sum, 3, "masked", []byte("ct"), []byte("dek"), false, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.versions(e.dev)) != 1 || e.count(`SELECT count(*) FROM backups.backup_state WHERE device_id = $1 AND last_sha256 = $2`, e.dev, sum[:]) != 1 {
		t.Fatal("version and state not written together")
	}
}

func TestBackupIntervalDefaultAndOverrides(t *testing.T) {
	h := newHarness(t, "")
	p := h.poller(Intervals{Availability: time.Hour, Metrics: time.Hour, Inventory: time.Hour})
	ctx := context.Background()
	api := h.env.Pool("nms_api")
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := api.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var gGroup, tGroup int64
	for _, q := range []struct {
		dst *int64
		sql string
	}{
		{&gGroup, `INSERT INTO core.device_group (name, interval_backup_s) VALUES ('g-'||gen_random_uuid(), 7200) RETURNING id`},
		{&tGroup, `INSERT INTO core.device_group (name) VALUES ('t-'||gen_random_uuid()) RETURNING id`},
	} {
		if err := api.QueryRow(ctx, q.sql).Scan(q.dst); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO core.monitoring_template (name, group_id, interval_backup_s) VALUES ('t-'||gen_random_uuid(), $1, 10800)`, tGroup)
	exec(`INSERT INTO core.monitoring_template (name, driver, interval_backup_s) VALUES ('t-'||gen_random_uuid(), 'eltex-esr', 14400)`)
	plain := h.device(netip.MustParseAddrPort("192.0.2.111:161"))
	inGroup := h.device(netip.MustParseAddrPort("192.0.2.112:161"))
	viaTpl := h.device(netip.MustParseAddrPort("192.0.2.113:161"))
	viaDrv := h.device(netip.MustParseAddrPort("192.0.2.114:161"))
	own := h.device(netip.MustParseAddrPort("192.0.2.115:161"))
	exec(`UPDATE core.device SET group_id = $2 WHERE id = $1`, inGroup, gGroup)
	exec(`UPDATE core.device SET group_id = $2 WHERE id = $1`, viaTpl, tGroup)
	exec(`UPDATE core.device SET driver = 'eltex-esr' WHERE id = $1`, viaDrv)
	exec(`UPDATE core.device SET group_id = $2, interval_backup_s = 3600 WHERE id = $1`, own, gGroup)
	devs, err := p.loadDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]time.Duration{
		plain: 24 * time.Hour, inGroup: 2 * time.Hour, viaTpl: 3 * time.Hour, viaDrv: 4 * time.Hour, own: time.Hour,
	}
	for _, d := range devs {
		if w, ok := want[d.ID]; ok {
			if d.Backup != w {
				t.Errorf("device %d backup interval = %v, want %v", d.ID, d.Backup, w)
			}
			delete(want, d.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("devices not loaded: %v", want)
	}
	if clampBackup(1) != time.Hour || clampBackup(1<<30) != maxBackupInterval {
		t.Error("clampBackup bounds")
	}
}

/* The schedule backs a device up repeatedly at its interval (shortened here), and stops with the context. */
func TestBackupScheduleRuns(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.116:161")
	e.cfg.Store(&fetched{text: "hostname a\n"})
	e.p.backupTick = 10 * time.Millisecond
	devs := e.p.sched.snapshot()
	for i := range devs {
		devs[i].Backup = 80 * time.Millisecond
	}
	e.p.sched.apply(devs)
	if err := e.p.sched.runNow(context.Background(), e.dev, func(_ device, c *devCache) error { c.drv = e.drv; return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.p.backupLoop(ctx); close(done) }()
	eventually(t, 10*time.Second, "three scheduled fetches", func() bool { return e.fetchN.Load() >= 3 })
	if n := len(e.versions(e.dev)); n != 1 {
		t.Errorf("unchanged configuration made %d versions", n)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("backupLoop did not stop")
	}
}

/* backup_now: coalesced within the gap, worked by the poller of the device's queue, source event, job id recorded. */
func TestBackupNowJob(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.117:161")
	e.cfg.Store(&fetched{text: "hostname b\n"})
	e.p.sched.mu.Lock()
	e.p.sched.devs[e.dev].cache.drv = e.drv
	e.p.sched.mu.Unlock()
	start(t, e.p)
	enq, err := jobs.NewEnqueuer(e.env.Pool("nms_api"))
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := pgx.BeginFunc(context.Background(), e.env.Pool("nms_api"), func(tx pgx.Tx) error {
			return enq.EnqueueBackupNow(context.Background(), tx, e.dev, "event")
		}); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(`SELECT count(*) FROM jobs.river_job WHERE kind = 'backup_now' AND (args->>'device_id')::bigint = $1`, e.dev); n != 1 {
		t.Fatalf("%d backup_now jobs, want 1 (coalesced)", n)
	}
	eventually(t, 15*time.Second, "version from the job", func() bool { return len(e.versions(e.dev)) == 1 })
	if e.count(`SELECT count(*) FROM backups.config_version WHERE device_id = $1 AND source = 'event' AND taken_by_job IS NOT NULL`, e.dev) != 1 {
		t.Error("job id or source not recorded")
	}
	if e.fetchN.Load() != 1 {
		t.Errorf("%d fetches for one job", e.fetchN.Load())
	}
}

/*
The api-role scan: after a configuration full of known secrets went through the
pipeline, every column that nms_api may read in any table or view is searched
for each secret, plain, base64 (standard and URL) and hex.
*/
func TestAPIRoleSeesNoSecretOfABackedUpConfig(t *testing.T) {
	e := newBackupEnv(t, "192.0.2.118:161")
	raw := readFixture(t, mesFixture+".txt")
	e.cfg.Store(&fetched{text: raw})
	if err := e.run(sourceSchedule); err != nil {
		t.Fatal(err)
	}
	e.cfg.Store(&fetched{text: raw + "username late password LateSecret123\n"})
	if err := e.run(sourceEvent); err != nil {
		t.Fatal(err)
	}
	if len(e.versions(e.dev)) != 2 {
		t.Fatal("versions not stored")
	}
	needles := map[string]string{}
	add := func(label, s string) { needles[label] = s }
	for _, s := range append(fixtureSecrets(t), "LateSecret123") {
		add("plain "+s, s)
		add("base64 "+s, base64.StdEncoding.EncodeToString([]byte(s)))
		add("base64url "+s, base64.URLEncoding.EncodeToString([]byte(s)))
		add("rawbase64 "+s, strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(s)), "="))
		add("hex "+s, hex.EncodeToString([]byte(s)))
	}
	ctx := context.Background()
	root, api := e.env.Pool("postgres"), e.env.Pool("nms_api")
	rows, err := root.Query(ctx, `
		SELECT n.nspname, c.relname, a.attname
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
		  AND has_schema_privilege('nms_api', n.oid, 'USAGE')
		  AND has_column_privilege('nms_api', c.oid, a.attnum, 'SELECT')
		ORDER BY 1, 2, 3`)
	if err != nil {
		t.Fatal(err)
	}
	type col struct{ schema, table, name string }
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (c col, err error) {
		err = r.Scan(&c.schema, &c.table, &c.name)
		return
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cols) < 100 {
		t.Fatalf("only %d readable columns found: the enumeration is broken", len(cols))
	}
	sawMasked := false
	for _, c := range cols {
		q := fmt.Sprintf(`SELECT coalesce(string_agg(%[3]s::text, E'\n'), '') FROM %[1]s.%[2]s`,
			pgx.Identifier{c.schema}.Sanitize(), pgx.Identifier{c.table}.Sanitize(), pgx.Identifier{c.name}.Sanitize())
		var all string
		if err := api.QueryRow(ctx, q).Scan(&all); err != nil {
			t.Fatalf("%s.%s.%s: %v", c.schema, c.table, c.name, err)
		}
		if c.schema == "backups" && c.table == "config_version" && c.name == "masked" {
			sawMasked = strings.Contains(all, "sw-lab-01")
		}
		if c.name == "full_ct" || c.name == "full_dek_ct" {
			t.Fatalf("nms_api can read %s.%s.%s", c.schema, c.table, c.name)
		}
		low := strings.ToLower(all)
		for label, n := range needles {
			if strings.Contains(all, n) || strings.Contains(low, strings.ToLower(n)) && len(n) >= 12 {
				t.Errorf("%s.%s.%s contains %s", c.schema, c.table, c.name, label)
			}
		}
	}
	if !sawMasked {
		t.Error("the scan did not reach the masked copy (it must be readable and clean)")
	}
}
