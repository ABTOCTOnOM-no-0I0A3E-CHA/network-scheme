package unmask_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/unmask"
	"github.com/beekamai/network-scheme/internal/backup"
	rdrivers "github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

type fx struct {
	env       *testdb.Env
	st        *unmask.Store
	az        *authz.Authorizer
	adm       *admin.Admin
	guard     *freeze.Guard
	conf      *confirm.Store
	pol       *policy.Holder
	polF      string
	pub, priv *[32]byte
	start     time.Time
	offset    atomic.Int64
	mu        sync.Mutex
	alerts    []string /* kind/severity */
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

func newFx(t *testing.T) *fx {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, start: time.Now()}
	pool := env.Pool("nms_executor")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	f.guard = freeze.New(reg, pool, log)
	if err := f.guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f.polF = filepath.Join(dir, "executor.yaml")
	f.pol = policy.New(f.polF)
	f.policy(t, "")
	if f.az, err = authz.New(authz.Config{Guard: f.guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Now: f.now,
		TicketKey: ticketKey.Public().(ed25519.PublicKey), Started: f.start, GuardsFile: filepath.Join(dir, "guards")}); err != nil {
		t.Fatal(err)
	}
	f.adm = &admin.Admin{Guard: f.guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Lockouts: f.az}
	f.conf = confirm.New(f.az, f.now)
	if f.pub, f.priv, err = box.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.st, err = unmask.New(unmask.Config{Pool: pool, Gate: f.guard, Priv: f.priv, Pub: f.pub, Clean: terminal.Clean, Policy: f.pol.Current,
		Alert: func(_ context.Context, kind, sev string, _ int64, _ string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.alerts = append(f.alerts, kind+"/"+sev)
			return nil
		}, Audit: f.az.Record, Log: log, Now: f.now}); err != nil {
		t.Fatal(err)
	}
	f.device(t, 7, "core")
	f.device(t, 8, "edge")
	return f
}

func (f *fx) policy(t *testing.T, extra string) {
	t.Helper()
	if err := os.WriteFile(f.polF, []byte("enabled: true\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, cur, _ := f.pol.Reload(true); cur.Err != nil {
		t.Fatalf("policy: %v", cur.Err)
	}
}

/* device puts a write device of group into the registry (nmsctl's way, here directly). */
func (f *fx) device(t *testing.T, id int64, group string) {
	t.Helper()
	if err := f.guard.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put("write_device", map[string]any{"device_id": id, "address": netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", id)), "port": 22,
			"protocol": "ssh", "write_group": group, "write_driver": "mes6", "hostkey_algo": nil, "hostkey_fp": nil, "allow_ssh_rsa_sha1": false,
			"writes_enabled": false, "backup_via_executor": false})
	}); err != nil {
		t.Fatal(err)
	}
}

func (f *fx) alerted(kind string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.alerts {
		if strings.HasPrefix(a, kind+"/") {
			n++
		}
	}
	return n
}

func (f *fx) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

/* version stores a configuration version of device as the poller does (text sealed under AAD(device, its hash)) and returns its id. */
func (f *fx) version(t *testing.T, device int64, text string) int64 {
	t.Helper()
	sum := sha256.Sum256([]byte(rdrivers.NormalizeText(text)))
	return f.versionRow(t, device, sum[:], text, backup.AAD(device, hex.EncodeToString(sum[:])))
}

/* versionRow stores a row with the given hash whose envelope holds text under aad (a forger's, with the backup public key). */
func (f *fx) versionRow(t *testing.T, device int64, sum []byte, text string, aad []byte) int64 {
	t.Helper()
	ct, dek, err := backup.Seal(f.pub, []byte(text), aad)
	if err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `INSERT INTO backups.config_version
		(device_id, source, sha256, size, masked, full_ct, full_dek_ct) VALUES ($1, 'schedule', $2, $3, 'masked', $4, $5) RETURNING id`,
		device, sum, len(text), ct, dek).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

type who struct {
	id         int64
	name, totp string
}

/* user is a panel user with a change TOTP and the given grants (kind, or write:<group>). */
func (f *fx) user(t *testing.T, grants ...string) who {
	t.Helper()
	name := fmt.Sprintf("um-%d", time.Now().UnixNano()%1e9)
	var u who
	if err := f.env.Pool("postgres").QueryRow(context.Background(),
		`INSERT INTO core."user" (username, password_phc) VALUES ($1, 'x') RETURNING id`, name).Scan(&u.id); err != nil {
		t.Fatal(err)
	}
	u.name = name
	reqs := []execadmin.Request{{Cmd: execadmin.CmdEnroll}}
	for _, g := range grants {
		kind, group, _ := strings.Cut(g, ":")
		reqs = append(reqs, execadmin.Request{Cmd: execadmin.CmdGrant, Kind: kind, Group: group})
	}
	for _, req := range reqs {
		req.User, req.V, req.Operator = name, execadmin.Version, "tester"
		resp := f.adm.Handle(context.Background(), req)
		if resp.OK && resp.Confirm != nil {
			req.UserID, req.UserCreated = resp.Confirm.ID, resp.Confirm.CreatedAt
			resp = f.adm.Handle(context.Background(), req)
		}
		if !resp.OK {
			t.Fatalf("%s %s: %s", req.Cmd, req.Kind, resp.Error)
		}
		if resp.Enrollment != nil {
			u.totp = resp.Enrollment.Secret
		}
	}
	return u
}

func (f *fx) ticket(t *testing.T, u who, key ed25519.PrivateKey) string {
	t.Helper()
	tok, _, err := ticket.Issue(key, u.id, u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

/* code is u's next change TOTP code (the clock moves a step on). */
func (f *fx) code(t *testing.T, u who) string {
	t.Helper()
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

/* issue is /x/confirm/issue of action on (device, version) for u: Identify, then Describe and the challenge. */
func (f *fx) issue(t *testing.T, u who, action string, device, version int64) (confirm.Challenge, error) {
	t.Helper()
	ctx := context.Background()
	by, err := f.az.Identify(ctx, authz.Request{Ticket: f.ticket(t, u, ticketKey), Action: "confirm.issue", Object: action})
	if err != nil {
		return confirm.Challenge{}, err
	}
	need, d, err := f.st.Describe(action)(ctx, by, json.RawMessage(fmt.Sprintf(`{"device_id":%d,"version_id":%d}`, device, version)))
	if err != nil {
		return confirm.Challenge{}, err
	}
	return f.conf.Issue(by.UserID, need, d)
}

/*
confirmed is the route of action: the challenge confirmed with tok and code
(confirm.Store and authz, the path in the audit's details as web passes it),
then View or Export on the route's objects.
*/
func (f *fx) confirmed(t *testing.T, c confirm.Challenge, tok, code string, objs ...string) (string, error) {
	t.Helper()
	ctx := context.Background()
	ch, by, err := f.conf.Confirm(ctx, c.ID, c.H[:], authz.Request{Ticket: tok, Code: code, IP: "192.0.2.7"})
	if err != nil {
		return "", err
	}
	if len(objs) == 0 {
		objs = []string{field(ch.Description, "device_id"), field(ch.Description, "version_id")}
	}
	if ch.Action == unmask.ActionExport {
		_, body, err := f.st.Export(ctx, ch, by, objs)
		return string(body), err
	}
	res, err := f.st.View(ctx, ch, by, objs)
	if err != nil {
		return "", err
	}
	return res.(unmask.Shown).Text, nil
}

/* show is issue + confirmed with u's own ticket and next code. */
func (f *fx) show(t *testing.T, u who, action string, device, version int64) (string, error) {
	t.Helper()
	c, err := f.issue(t, u, action, device, version)
	if err != nil {
		return "", err
	}
	return f.confirmed(t, c, f.ticket(t, u, ticketKey), f.code(t, u))
}

func field(d confirm.Description, k string) string {
	for _, x := range d.Fields {
		if x.Key == k {
			return x.Value
		}
	}
	return ""
}

/* audits counts the executor's audit rows of action with result and, if not empty, class. */
func (f *fx) audits(t *testing.T, action, result, class string) int {
	t.Helper()
	return f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = $2
		AND ($3 = '' OR convert_from(payload, 'UTF8')::jsonb #>> '{details,class}' = $3)`, action, result, class)
}

const configText = "hostname sw1\nusername admin password Secr3t\nsnmp-server community CommStr ro\n"

/*
C9: an unmasked configuration only with the unmask grant and write on the
device's write group (from the registry) and the user's own change TOTP
code: without the grant, without write on the group, without or with a
wrong code, with another user's code, with a forged ticket or another
user's ticket it is refused; the grant on group A never opens a device of
group B, also when the device moves to B after the challenge. Each view and
export is an executor audit row with user, device, version and hash; the
api's role still cannot read the envelope columns.
*/
func TestC9UnmaskNeedsGrantGroupAndTOTP(t *testing.T) {
	f := newFx(t)
	v7 := f.version(t, 7, configText)
	v8 := f.version(t, 8, "hostname sw2\n")
	writeOnly := f.user(t, "write:core", execadmin.KindAuditRead, execadmin.KindWriteAdmin)
	unmaskOnly := f.user(t, execadmin.KindUnmask, "write:edge")
	alice := f.user(t, execadmin.KindUnmask, "write:core")
	bob := f.user(t, execadmin.KindUnmask, "write:core")
	for name, u := range map[string]who{"write without unmask": writeOnly, "unmask without write on core": unmaskOnly} {
		if _, err := f.show(t, u, unmask.ActionView, 7, v7); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	/* alice's challenge: no code, a wrong code, bob's code, a forged ticket, bob's own ticket and code */
	c, err := f.issue(t, alice, unmask.ActionView, 7, v7)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	attempts := map[string]func() (string, error){
		"no code":      func() (string, error) { return f.confirmed(t, c, f.ticket(t, alice, ticketKey), "") },
		"wrong code":   func() (string, error) { return f.confirmed(t, c, f.ticket(t, alice, ticketKey), "000000") },
		"bob's code":   func() (string, error) { return f.confirmed(t, c, f.ticket(t, alice, ticketKey), f.code(t, bob)) },
		"forged":       func() (string, error) { return f.confirmed(t, c, f.ticket(t, alice, otherKey), f.code(t, alice)) },
		"bob's ticket": func() (string, error) { return f.confirmed(t, c, f.ticket(t, bob, ticketKey), f.code(t, bob)) },
	}
	for name, try := range attempts {
		f.az.ResetUser(alice.id)
		var err error
		if c, err = f.issue(t, alice, unmask.ActionView, 7, v7); err != nil {
			t.Fatal(err)
		}
		if text, err := try(); err == nil || text != "" {
			t.Fatalf("%s: %q %v", name, text, err)
		}
	}
	f.az.ResetUser(alice.id)
	f.az.ResetUser(bob.id)
	/* a forged ticket does not even get a challenge */
	if _, err := f.az.Identify(context.Background(), authz.Request{Ticket: f.ticket(t, alice, otherKey), Action: "confirm.issue",
		Object: unmask.ActionView}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("forged ticket identified: %v", err)
	}
	/* group scope: core's grant does not open edge's device */
	if _, err := f.show(t, alice, unmask.ActionView, 8, v8); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("edge device with core's grant: %v", err)
	}
	/* the route names another version than the confirmed one */
	c, _ = f.issue(t, alice, unmask.ActionView, 7, v7)
	if _, err := f.confirmed(t, c, f.ticket(t, alice, ticketKey), f.code(t, alice), "7", strconv.FormatInt(v7+1, 10)); !errors.Is(err, unmask.ErrMismatch) {
		t.Fatalf("other version on the route: %v", err)
	}
	/* the view and the export, each audited with device, version and hash */
	text, err := f.show(t, alice, unmask.ActionView, 7, v7)
	if err != nil || text != configText {
		t.Fatalf("view: %q %v", text, err)
	}
	if body, err := f.show(t, alice, unmask.ActionExport, 7, v7); err != nil || body != configText {
		t.Fatalf("export: %q %v", body, err)
	}
	sum := sha256.Sum256([]byte(rdrivers.NormalizeText(configText)))
	for _, action := range []string{unmask.ActionView, unmask.ActionExport} {
		if n := f.count(t, `SELECT count(*) FROM exec.audit_event WHERE action = $1 AND result = 'ok' AND user_id = $2 AND object = 'device:7'
			AND convert_from(payload, 'UTF8')::jsonb #>> '{details,version_id}' = $3 AND convert_from(payload, 'UTF8')::jsonb #>> '{details,sha256}' = $4`,
			action, alice.id, strconv.FormatInt(v7, 10), hex.EncodeToString(sum[:])); n != 1 {
			t.Fatalf("%s: %d audit rows", action, n)
		}
	}
	if n := f.audits(t, unmask.ActionView, "denied", "mismatch"); n != 1 {
		t.Fatalf("mismatch audited %d times", n)
	}
	/* the device moves to edge after the challenge: the registry decides, the confirmed group no longer holds */
	c, _ = f.issue(t, alice, unmask.ActionView, 7, v7)
	f.device(t, 7, "edge")
	if _, err := f.confirmed(t, c, f.ticket(t, alice, ticketKey), f.code(t, alice)); !errors.Is(err, unmask.ErrChanged) {
		t.Fatalf("moved device: %v", err)
	}
	if n := f.audits(t, unmask.ActionView, "denied", "changed"); n != 1 {
		t.Fatalf("changed audited %d times", n)
	}
	/* the api never reads the envelope, not even its ciphertext */
	var pgErr *pgconn.PgError
	_, err = f.env.Pool("nms_api").Exec(context.Background(), `SELECT full_ct, full_dek_ct FROM backups.config_version`)
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("nms_api reads the envelope: %v", err)
	}
}

/* Describe reads the executor's own data: an unregistered device or a version of another device gets no challenge. */
func TestDescribeFromTheExecutorsData(t *testing.T) {
	f := newFx(t)
	v8 := f.version(t, 8, "hostname sw2\n")
	v99 := f.version(t, 99, "hostname sw99\n")
	alice := f.user(t, execadmin.KindUnmask, "write:core")
	if _, err := f.issue(t, alice, unmask.ActionView, 99, v99); !errors.Is(err, unmask.ErrNotRegistered) {
		t.Fatalf("unregistered device: %v", err)
	}
	if _, err := f.issue(t, alice, unmask.ActionView, 7, v8); !errors.Is(err, unmask.ErrNotFound) {
		t.Fatalf("another device's version: %v", err)
	}
	c, err := f.issue(t, alice, unmask.ActionExport, 8, v8)
	if err != nil {
		t.Fatal(err)
	}
	if field(c.Description, "write_group") != "edge" || field(c.Description, "device_id") != "8" || field(c.Description, "sha256") == "" {
		t.Fatalf("description %+v", c.Description)
	}
	/* the list needs the grant of the registry's group of the device */
	need, err := f.st.ListNeed(context.Background(), json.RawMessage(`{"device_id":8}`))
	if err != nil || need.Kind != execadmin.KindUnmask || len(need.Groups) != 1 || need.Groups[0] != "edge" {
		t.Fatalf("list need %+v %v", need, err)
	}
	if need, _ := f.st.ListNeed(context.Background(), json.RawMessage(`{"device_id":99}`)); !need.Valid() || need.Groups[0] != "-unregistered" {
		t.Fatalf("unregistered list need %+v", need)
	}
}

/*
C9: views and exports per user and hour are bounded by unmask_per_hour: the
N+1th is refused (audited) with one high alert an hour; more than
mass_unmask_alert of all users within an hour raise one high mass_unmask.
*/
func TestUnmaskLimitAndMassAlert(t *testing.T) {
	f := newFx(t)
	f.policy(t, "unmask_per_hour: 2\nmass_unmask_alert: 2\n")
	v := f.version(t, 7, configText)
	alice := f.user(t, execadmin.KindUnmask, "write:core")
	bob := f.user(t, execadmin.KindUnmask, "write:core")
	for i, action := range []string{unmask.ActionView, unmask.ActionExport} {
		if _, err := f.show(t, alice, action, 7, v); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	for range 2 {
		if _, err := f.show(t, alice, unmask.ActionView, 7, v); !errors.Is(err, unmask.ErrViewLimit) {
			t.Fatalf("past the limit: %v", err)
		}
	}
	if n := f.alerted(unmask.KindViews); n != 1 {
		t.Fatalf("%d view-limit alerts, want 1", n)
	}
	if n := f.audits(t, unmask.ActionView, "denied", "view_limit"); n != 2 {
		t.Fatalf("refusals audited %d times", n)
	}
	if f.alerted(unmask.KindMass) != 0 {
		t.Fatal("mass alert at the threshold")
	}
	if _, err := f.show(t, bob, unmask.ActionView, 7, v); err != nil {
		t.Fatal(err)
	}
	if n := f.alerted(unmask.KindMass); n != 1 {
		t.Fatalf("%d mass alerts, want 1", n)
	}
	f.offset.Add(int64(time.Hour))
	if _, err := f.show(t, alice, unmask.ActionView, 7, v); err != nil {
		t.Fatalf("an hour later: %v", err)
	}
}

/*
C9, Review Focus 4d (2): the envelope proves nothing, so before anything is
shown the opened text must hash to the version row. A row whose envelope a
forger sealed (another text under the right AAD), one that does not open,
and another device's envelope copied in are refused with a high alert and
an audit row; nothing is shown.
*/
func TestUnmaskRefusesTamperedVersions(t *testing.T) {
	f := newFx(t)
	alice := f.user(t, execadmin.KindUnmask, "write:core")
	good := sha256.Sum256([]byte(rdrivers.NormalizeText(configText)))
	goodHex := hex.EncodeToString(good[:])
	forged := f.versionRow(t, 7, good[:], "hostname evil\n", backup.AAD(7, goodHex))
	other := f.versionRow(t, 7, good[:], configText, backup.AAD(8, goodHex))
	broken := f.version(t, 7, configText)
	attacktest.Tamper(t, f.env, `ALTER TABLE backups.config_version DISABLE TRIGGER config_version_append_only`)
	attacktest.Tamper(t, f.env, `UPDATE backups.config_version SET full_ct = 'garbage' WHERE id = $1`, broken)
	attacktest.Tamper(t, f.env, `ALTER TABLE backups.config_version ENABLE TRIGGER config_version_append_only`)
	for name, v := range map[string]int64{"forged text": forged, "another device's envelope": other, "broken envelope": broken} {
		before := f.alerted(unmask.KindTamper)
		text, err := f.show(t, alice, unmask.ActionView, 7, v)
		if !errors.Is(err, unmask.ErrTampered) || text != "" {
			t.Fatalf("%s: %q %v", name, text, err)
		}
		if f.alerted(unmask.KindTamper) != before+1 {
			t.Fatalf("%s: no tamper alert", name)
		}
	}
	if n := f.audits(t, unmask.ActionView, "denied", "config_tampered"); n != 3 {
		t.Fatalf("tampering audited %d times", n)
	}
}

/*
The configuration is device data: shown and exported as text without
escape sequences (CSI, OSC 52, unterminated OSC), C0 controls but tab and
line end, DEL, C1, bidirectional overrides or zero-width characters; an
unterminated sequence does not swallow the lines after it.
*/
func TestUnmaskedTextIsCleaned(t *testing.T) {
	f := newFx(t)
	alice := f.user(t, execadmin.KindUnmask, "write:core")
	raw := "hostname \x1b[31msw1\x1b[0m\r\n" +
		"banner \x1b]52;c;ZXZpbA==\x07ok\n" +
		"description \x1b]0;unterminated\n" +
		"interface\tgi1/0/1\n" +
		"name \xe2\x80\xaeevil\xe2\x80\x8b\x07\x7f\u009b31m\n" +
		"end\n"
	v := f.version(t, 7, raw)
	want := "hostname sw1\nbanner ok\ndescription \ninterface\tgi1/0/1\nname evil\nend\n"
	for _, action := range []string{unmask.ActionView, unmask.ActionExport} {
		text, err := f.show(t, alice, action, 7, v)
		if err != nil || text != want {
			t.Fatalf("%s: %q %v, want %q", action, text, err, want)
		}
	}
}
