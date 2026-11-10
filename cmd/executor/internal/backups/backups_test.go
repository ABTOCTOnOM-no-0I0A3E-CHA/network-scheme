package backups

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const pw = "backups-test-password-1"

var master = [32]byte{9}

var addrs atomic.Int64

/* loopDialer connects wherever the registry says to the emulator (the network guard is tested in transport). */
type loopDialer struct{ addr netip.AddrPort }

func (l loopDialer) Dial(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", l.addr.String())
}

type rig struct {
	env        *testdb.Env
	g          *freeze.Guard
	row        map[string]any
	s          *Scheduler
	d          *devemu.Device
	id         int64
	priv, pubk *[32]byte
}

/* newRig registers an emulated device of line in a fresh registry, with backup_via_executor, and a scheduler over it. */
func newRig(t *testing.T, line string) *rig {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	k, err := seal.Derive(&master)
	if err != nil {
		t.Fatal(err)
	}
	pool := env.Pool("nms_executor")
	g := freeze.New(registry.New(pool, k, filepath.Join(t.TempDir(), "state")), pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	r := &rig{env: env, g: g, d: devemu.NewLine(t, line, devemu.Options{})}
	root := env.Pool("postgres")
	var gid int64
	if err := root.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('bk-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := root.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id) VALUES ('bk-' || gen_random_uuid(), $1, $2) RETURNING id`,
		netip.AddrFrom4([4]byte{192, 0, 2, byte(40 + addrs.Add(1))}), gid).Scan(&r.id); err != nil {
		t.Fatal(err)
	}
	addr, key, _ := devemu.StartSSH(t, r.d, func(c *sshemu.Config) { c.Username, c.Password = "admin", pw })
	r.row = map[string]any{"device_id": r.id, "address": netip.MustParseAddr("192.0.2.40"), "port": 22,
		"protocol": "ssh", "write_group": "core", "write_driver": line, "hostkey_algo": key.Type(),
		"hostkey_fp": gossh.FingerprintSHA256(key), "allow_ssh_rsa_sha1": line == "mes6", "writes_enabled": false,
		"backup_via_executor": true}
	r.put(t)
	if r.pubk, r.priv, err = box.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	r.s = New(Config{Registry: g, Net: loopDialer{addr}, Pool: pool, BackupPub: r.pubk, Locks: &Locks{},
		Open: func(*registry.Snapshot, int64) (creds.Credential, error) {
			return creds.Credential{Username: "admin", Password: secret.New(pw)}, nil
		},
		Alert: func(context.Context, string, string, int64, string) error { return nil }})
	return r
}

func (r *rig) put(t *testing.T) {
	t.Helper()
	if err := r.g.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_device", r.row)
	}); err != nil {
		t.Fatal(err)
	}
}

/* running makes the device answer "show running-config" with text. */
func (r *rig) running(text string) {
	r.d.SetShowLookup(func(cmd string) (string, bool) { return text, cmd == "show running-config" })
}

func (r *rig) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := r.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (r *rig) versions(t *testing.T) int {
	return r.count(t, `SELECT count(*) FROM backups.config_version WHERE device_id = $1`, r.id)
}

func (r *rig) backup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := r.s.backup(ctx, r.id); err != nil {
		t.Fatalf("backup: %v", err)
	}
}

/* due makes the next runDue find the device due. */
func (r *rig) due() {
	r.s.mu.Lock()
	r.s.next[r.id] = time.Time{}
	r.s.mu.Unlock()
}

/* Only the read dialect of the line reaches the device: the pager-off commands and allowlisted reads. */
func TestOnlyAllowlistedCommandsReachTheDevice(t *testing.T) {
	for _, line := range strategy.Lines() {
		t.Run(string(line), func(t *testing.T) {
			r := newRig(t, string(line))
			r.backup(t)
			d := readDriver(line).Dialect()
			lines := r.d.Lines()
			for _, l := range lines {
				if !slices.Contains(d.PagerOff, l) && !slices.ContainsFunc(d.Allowlist, func(c ssh.ShowCommand) bool { return c.Name == l }) {
					t.Errorf("%q reached the device outside the read allowlist", l)
				}
			}
			if !slices.Contains(lines, "show running-config") || r.versions(t) != 1 {
				t.Fatalf("no backup: lines %q, versions %d", lines, r.versions(t))
			}
			r.d.ExpectNone(t, "new-password", "answer")
		})
	}
}

/* A version is stored only when the normalized configuration changes; every success stamps backup_state and backup_taken. */
func TestNewVersionOnlyWhenTheConfigChanges(t *testing.T) {
	r := newRig(t, "mes6")
	base := r.d.Running()
	r.running(base)
	r.backup(t)
	r.backup(t)
	if n := r.versions(t); n != 1 {
		t.Fatalf("same configuration: %d versions", n)
	}
	var a []byte
	if err := r.env.Pool("postgres").QueryRow(context.Background(), `SELECT sha256 FROM backups.config_version WHERE device_id = $1`, r.id).Scan(&a); err != nil {
		t.Fatal(err)
	}
	/*
		Executor stored A, the poller stored B, the device is back at A: the
		newest version must be A again, so the executor stores it.
	*/
	if _, err := r.env.Pool("nms_poller").Exec(context.Background(), `INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct)
		VALUES ($1, 'schedule', $2, 1, 'x', '\x00', '\x00')`, r.id, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	r.backup(t)
	newest := func() (sha []byte, source string) {
		t.Helper()
		if err := r.env.Pool("postgres").QueryRow(context.Background(), `SELECT sha256, source FROM backups.config_version WHERE device_id = $1 ORDER BY id DESC LIMIT 1`,
			r.id).Scan(&sha, &source); err != nil {
			t.Fatal(err)
		}
		return
	}
	if sha, src := newest(); !bytes.Equal(sha, a) || src != Source || r.versions(t) != 3 {
		t.Fatalf("after a poller version: newest %x from %s, %d versions", sha, src, r.versions(t))
	}
	r.backup(t)
	if n := r.versions(t); n != 3 {
		t.Fatalf("unchanged again: %d versions", n)
	}
	r.running(base + "hostname changed\n")
	r.backup(t)
	if sha, _ := newest(); bytes.Equal(sha, a) || r.versions(t) != 4 {
		t.Fatalf("changed configuration: %d versions", r.versions(t))
	}
	if n := r.count(t, `SELECT count(*) FROM backups.backup_state s JOIN backups.config_version v ON v.device_id = s.device_id AND v.sha256 = s.last_sha256
		WHERE s.device_id = $1 AND v.source = 'executor' AND v.drift AND s.last_error IS NULL AND NOT s.needs_write`, r.id); n != 1 {
		t.Fatal("backup_state does not name the newest executor version")
	}
	if n := r.count(t, `SELECT count(*) FROM execpub.backup_taken WHERE device_id = $1 AND at > now() - interval '1 minute'`, r.id); n != 1 {
		t.Fatal("no backup_taken stamp")
	}
	/* a device no longer backed up by the executor loses its stamp at once (the poller takes it back) and is not contacted */
	r.row["backup_via_executor"] = false
	r.put(t)
	sent := len(r.d.Journal())
	r.due()
	r.s.runDue(context.Background())
	if n := r.count(t, `SELECT count(*) FROM execpub.backup_taken WHERE device_id = $1`, r.id); n != 0 || len(r.d.Journal()) != sent {
		t.Fatalf("stamp kept (%d) or device contacted after backup_via_executor was cleared", n)
	}
}

/* The masked copy holds none of the known secrets; the sealed copy opens with the backup-domain key to the raw text. */
func TestMaskedCopyHasNoKnownSecrets(t *testing.T) {
	r := newRig(t, "mes6")
	raw, err := os.ReadFile("../../../../test/fixtures/configs/mes-secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := os.ReadFile("../../../../test/fixtures/configs/mes-secrets.secrets")
	if err != nil {
		t.Fatal(err)
	}
	r.running(string(raw))
	r.backup(t)
	var masked string
	var sum, ct, dek []byte
	if err := r.env.Pool("postgres").QueryRow(context.Background(), `SELECT masked, sha256, full_ct, full_dek_ct FROM backups.config_version WHERE device_id = $1`,
		r.id).Scan(&masked, &sum, &ct, &dek); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range strings.Split(string(sec), "\n") {
		if s = strings.TrimSpace(s); s != "" {
			n++
			if strings.Contains(masked, s) {
				t.Errorf("secret %q in the masked copy", s)
			}
		}
	}
	if n < 10 || !strings.Contains(masked, "***") {
		t.Fatalf("fixture secrets %d, masked %d bytes", n, len(masked))
	}
	full, err := open.Open(r.priv, r.pubk, ct, dek, backup.AAD(r.id, hex.EncodeToString(sum)))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(readDriver(strategy.MES6).NormalizeConfig(string(full))))
	if !bytes.Equal(want[:], sum) || !strings.Contains(string(full), strings.TrimSpace(strings.Split(string(sec), "\n")[0])) {
		t.Fatal("the sealed copy is not the raw configuration")
	}
}

/* A device whose lease a session holds is skipped and backed up after; BeforeSession works only under the caller's lease. */
func TestDeviceInSessionIsSkipped(t *testing.T) {
	r := newRig(t, "mes6")
	ctx := context.Background()
	le, ok := r.s.cfg.Locks.TryLock(r.id)
	if !ok {
		t.Fatal("lock")
	}
	if _, ok := r.s.cfg.Locks.TryLock(r.id); ok {
		t.Fatal("a second lease of a held device")
	}
	r.due()
	r.s.runDue(ctx)
	if len(r.d.Journal()) != 0 || r.versions(t) != 0 {
		t.Fatalf("a held device was contacted: %q", r.d.Lines())
	}
	if _, err := r.s.BeforeSession(ctx, le, nil); err != nil || r.versions(t) != 1 {
		t.Fatalf("before session: %v, versions %d", err, r.versions(t))
	}
	le.Release()
	le.Release()
	if _, err := r.s.BeforeSession(ctx, le, nil); err != errLease {
		t.Fatalf("released lease: %v", err)
	}
	/* a released lease stays dead while another holder (the scheduler) has the device, and cannot free it */
	other, ok := r.s.cfg.Locks.TryLock(r.id)
	if !ok {
		t.Fatal("relock")
	}
	if _, err := r.s.BeforeSession(ctx, le, nil); err != errLease {
		t.Fatalf("released lease while the device is held again: %v", err)
	}
	le.Release()
	if _, ok := r.s.cfg.Locks.TryLock(r.id); ok {
		t.Fatal("a released lease freed the next holder's lock")
	}
	other.Release()
	fl, _ := (&Locks{}).TryLock(r.id)
	if _, err := r.s.BeforeSession(ctx, fl, nil); err != errLease {
		t.Fatalf("foreign lease: %v", err)
	}
	r.running(r.d.Running() + "hostname after\n")
	r.due()
	r.s.runDue(ctx)
	if r.versions(t) != 2 {
		t.Fatalf("released device not backed up: %d versions", r.versions(t))
	}
}

/*
Nothing outside starts a backup: api rows in jobs and execpub (and their
NOTIFY) do not, and the package neither reads jobs nor any execpub table
nor backup_state.
*/
func TestExternalInsertsStartNoBackup(t *testing.T) {
	r := newRig(t, "mes6")
	ctx := context.Background()
	old := firstSpread
	firstSpread = time.Hour
	t.Cleanup(func() { firstSpread = old })
	r.s.runDue(ctx) /* first sight: planned within the hour, not now */
	api := r.env.Pool("nms_api")
	for _, sql := range []string{
		`INSERT INTO jobs.river_job (kind, queue, args, state, max_attempts) VALUES ('backup_now', 'default', jsonb_build_object('device_id', $1::bigint), 'available', 1)`,
		`INSERT INTO execpub.freeze_request (requested_by) VALUES ($1) ON CONFLICT DO NOTHING`,
	} {
		if _, err := api.Exec(ctx, sql, r.id); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	if _, err := api.Exec(ctx, `NOTIFY execpub_freeze`); err != nil {
		t.Logf("notify: %v", err)
	}
	for range 3 {
		r.s.runDue(ctx)
	}
	if len(r.d.Journal()) != 0 || r.versions(t) != 0 {
		t.Fatalf("an external row started a backup: %q", r.d.Lines())
	}
	src, err := os.ReadFile("backups.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, re := range []string{`\briver`, `jobs\.`, `freeze_request`, `device_busy`, `session_summary`, `(?i)listen`,
		/* of execpub only its own backup_taken (only the executor writes it) */
		`(?i)execpub\.(alert|status)`, `(?i)select[^;` + "`" + `]*backup_state`, `(?i)from\s+backups\.backup_state`} {
		if loc := regexp.MustCompile(re).FindIndex(src); loc != nil {
			t.Errorf("backups.go reads %q: %q", re, src[loc[0]:loc[1]])
		}
	}
}

/* A disabled policy hands every device back to the poller at once and contacts none. */
func TestDisabledPolicyDropsTheStamps(t *testing.T) {
	r := newRig(t, "mes6")
	r.backup(t)
	r.s.cfg.Enabled = func() bool { return false }
	sent := len(r.d.Journal())
	r.due()
	r.s.runDue(context.Background())
	if n := r.count(t, `SELECT count(*) FROM execpub.backup_taken`); n != 0 || len(r.d.Journal()) != sent {
		t.Fatalf("disabled: %d stamps kept, device contacted %v", n, len(r.d.Journal()) != sent)
	}
}

/* A failure is written to backup_state only for a device the executor already backed up; the poller's state stays otherwise. */
func TestFailureTouchesOnlyTheExecutorsState(t *testing.T) {
	r := newRig(t, "mes6")
	ctx := context.Background()
	if _, err := r.env.Pool("nms_poller").Exec(ctx, `INSERT INTO backups.backup_state (device_id, last_ok_at) VALUES ($1, now())`, r.id); err != nil {
		t.Fatal(err)
	}
	failed := func() int {
		return r.count(t, `SELECT count(*) FROM backups.backup_state WHERE device_id = $1 AND last_error = $2`, r.id, ErrFailed)
	}
	key := r.s.cfg.BackupPub
	r.s.cfg.BackupPub = nil /* every backup fails */
	if err := r.s.backup(ctx, r.id); err == nil || failed() != 0 {
		t.Fatalf("a failure overwrote the poller's backup_state: %v", err)
	}
	r.s.cfg.BackupPub = key
	r.backup(t)
	r.s.cfg.BackupPub = nil
	if err := r.s.backup(ctx, r.id); err == nil || failed() != 1 {
		t.Fatalf("failure of an executor-backed device not recorded: %v", err)
	}
}

/*
I2: an out-of-band change before a session stays visible as drift: the
pre-session version is drift when it differs from the newest version and
is no session's result; what a session left is not drift.
*/
func TestPreSessionKeepsDriftVisible(t *testing.T) {
	r := newRig(t, "mes6")
	ctx := context.Background()
	r.backup(t)
	pre := func() (Pre, bool) {
		t.Helper()
		le, ok := r.s.cfg.Locks.TryLock(r.id)
		if !ok {
			t.Fatal("lock")
		}
		defer le.Release()
		p, err := r.s.BeforeSession(ctx, le, func(ctx context.Context, sum [32]byte) (bool, error) {
			var ok bool
			err := r.env.Pool("nms_executor").QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.session_summary WHERE device_id = $1 AND post_sha256 = $2)`,
				r.id, sum[:]).Scan(&ok)
			return ok, err
		})
		if err != nil {
			t.Fatal(err)
		}
		var drift bool
		if err := r.env.Pool("postgres").QueryRow(ctx, `SELECT drift FROM backups.config_version WHERE device_id = $1 AND source = 'pre_session'
			ORDER BY id DESC LIMIT 1`, r.id).Scan(&drift); err != nil {
			t.Fatal(err)
		}
		return p, drift
	}
	if _, drift := pre(); drift {
		t.Fatal("an unchanged configuration is drift")
	}
	r.running(r.d.Running() + "hostname out-of-band\n")
	if _, drift := pre(); !drift {
		t.Fatal("an out-of-band change is not drift")
	}
	/* a session left this configuration */
	left := r.d.Running() + "hostname by-session\n"
	r.running(left)
	sum := sha256.Sum256([]byte(drivers.NormalizeText(left)))
	if _, err := r.env.Pool("nms_executor").Exec(ctx, `INSERT INTO execpub.session_summary (session_id, user_id, device_id, opened_at, closed_at, status, post_sha256)
		VALUES (gen_random_uuid(), 1, $1, now() - interval '1 minute', now(), 'closed', $2)`, r.id, sum[:]); err != nil {
		t.Fatal(err)
	}
	if p, drift := pre(); drift || p.SHA256 != sum {
		t.Fatalf("a session's result is drift (%v) or hashed otherwise", drift)
	}
}
