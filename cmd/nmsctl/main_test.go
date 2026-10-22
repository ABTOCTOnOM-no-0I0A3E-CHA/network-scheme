package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

/* fakeSys is a System inside or outside the tools container that records commands. */
type fakeSys struct {
	inContainer bool
	cmds        []install.Cmd
	stdins      []string
	err         error  /* result of every command */
	failMatch   string /* when set, only commands whose argv contains it fail (with err) */
	listing     string /* stdout of iptables -L ... --line-numbers */
}

func (*fakeSys) GOOS() string                         { return "linux" }
func (f *fakeSys) InContainer() bool                  { return f.inContainer }
func (*fakeSys) DockerServerVersion() (string, error) { return "28.0.0", nil }
func (*fakeSys) Chown(string, int, int) error         { return nil }
func (*fakeSys) Executable() (string, error)          { return os.Executable() }
func (f *fakeSys) Run(_ context.Context, c install.Cmd) error {
	f.cmds = append(f.cmds, c)
	var b bytes.Buffer
	if c.Stdin != nil {
		_, _ = b.ReadFrom(c.Stdin)
	}
	f.stdins = append(f.stdins, b.String())
	if c.Stdout != nil && strings.Contains(strings.Join(c.Args, " "), "--line-numbers") {
		_, _ = c.Stdout.Write([]byte(f.listing))
	}
	if f.failMatch != "" && !strings.Contains(strings.Join(c.Args, " "), f.failMatch) {
		return nil
	}
	return f.err
}

var testKey = func() *[32]byte {
	k := new([32]byte)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}()

/* cli runs nmsctl inside the (simulated) tools container against the test database. */
func cli(t *testing.T, env *testdb.Env, stdin string, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	d := deps{
		in: strings.NewReader(stdin), out: &out, errw: &out,
		sys: &fakeSys{inContainer: true},
		openDB: func(context.Context) (*pgxpool.Pool, *[32]byte, func(), error) {
			return env.Pool("nms_cli"), testKey, func() {}, nil
		},
		now: time.Now,
	}
	code := run(context.Background(), args, d)
	return code, out.String()
}

func totpSecret(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if s, ok := strings.CutPrefix(l, install.TOTPSecretLinePrefix); ok {
			return strings.TrimSpace(s)
		}
	}
	t.Fatalf("no TOTP secret line in output:\n%s", out)
	return ""
}

/* login completes password + TOTP and returns the session token. */
func login(t *testing.T, env *testdb.Env, user, pw, sec string, at time.Time) string {
	t.Helper()
	ctx := context.Background()
	svc := auth.NewService(env.Pool("nms_api"), testKey, func() time.Time { return at })
	step, err := svc.BeginLogin(ctx, user, pw, "192.0.2.10")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if step.Kind != "totp" {
		t.Fatalf("login step %q, want totp", step.Kind)
	}
	code, err := totp.GenerateCode(sec, at)
	if err != nil {
		t.Fatal(err)
	}
	ns, err := svc.CompleteTOTP(ctx, step.ChallengeID, code, "192.0.2.10", "test")
	if err != nil {
		t.Fatalf("CompleteTOTP: %v", err)
	}
	return ns.Token
}

func auditCount(t *testing.T, env *testdb.Env, action string) int {
	t.Helper()
	var n int
	if err := env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM audit.event WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const (
	pw1 = "Plume-harbor-Quartz-71"
	pw2 = "Velvet-Orbit-cactus-38"
)

func TestAdminCreateEnrollsTOTPAndGrantsAdmin(t *testing.T) {
	env := testdb.New(t)
	before := auditCount(t, env, "cli.admin_create")
	code, out := cli(t, env, pw1+"\n", "admin", "create", "--user", "Alice", "--password-file", "-")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if strings.Contains(out, pw1) {
		t.Fatal("password echoed")
	}
	if !strings.Contains(out, "\u2580") && !strings.Contains(out, "\u2584") {
		t.Errorf("no QR code in output:\n%s", out)
	}
	sec := totpSecret(t, out)
	login(t, env, "alice", pw1, sec, time.Now())

	var id int64
	if err := env.Pool("postgres").QueryRow(context.Background(),
		`SELECT id FROM core."user" WHERE username = 'alice'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	sub, err := rbac.NewStore(env.Pool("nms_api")).LoadSubject(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if !sub.Can(rbac.PermUsersManage, nil, nil) {
		t.Fatalf("alice is not a global admin: %+v", sub.Bindings)
	}
	if got := auditCount(t, env, "cli.admin_create"); got != before+1 {
		t.Fatalf("cli.admin_create events = %d, want %d", got, before+1)
	}

	if code, out := cli(t, env, pw1+"\n", "admin", "create", "--user", "alice", "--password-file", "-"); code != 1 {
		t.Fatalf("duplicate admin create: exit %d\n%s", code, out)
	}
	if code, out := cli(t, env, "short\n", "admin", "create", "--user", "carol", "--password-file", "-"); code != 1 {
		t.Fatalf("weak password accepted: exit %d\n%s", code, out)
	}
}

func TestUserResetClearsTOTPAndSessions(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	code, out := cli(t, env, pw1+"\n", "admin", "create", "--user", "bob", "--password-file", "-")
	if code != 0 {
		t.Fatalf("admin create: %d\n%s", code, out)
	}
	sec := totpSecret(t, out)
	svc := auth.NewService(env.Pool("nms_api"), testKey, nil)
	token := login(t, env, "bob", pw1, sec, time.Now())
	if _, err := svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("session before reset: %v", err)
	}
	before := auditCount(t, env, "cli.user_reset")

	if code, out := cli(t, env, "", "user", "reset", "bob", "--totp"); code != 0 {
		t.Fatalf("user reset --totp: %d\n%s", code, out)
	}
	if _, err := svc.Authenticate(ctx, token); err == nil {
		t.Fatal("session survived TOTP reset")
	}
	var enrolled bool
	var sessions int
	if err := env.Pool("postgres").QueryRow(ctx,
		`SELECT u.totp_secret_enc IS NOT NULL, (SELECT count(*) FROM core.session s WHERE s.user_id = u.id)
		 FROM core."user" u WHERE username = 'bob'`).Scan(&enrolled, &sessions); err != nil {
		t.Fatal(err)
	}
	if enrolled || sessions != 0 {
		t.Fatalf("after reset: enrolled=%v sessions=%d", enrolled, sessions)
	}
	step, err := svc.BeginLogin(ctx, "bob", pw1, "192.0.2.10")
	if err != nil || step.Kind != "enroll" {
		t.Fatalf("next login: %+v %v, want enroll", step, err)
	}

	if code, out := cli(t, env, pw2+"\n", "user", "reset", "bob", "--password", "--password-file", "-"); code != 0 {
		t.Fatalf("user reset --password: %d\n%s", code, out)
	}
	if _, err := svc.BeginLogin(ctx, "bob", pw1, "192.0.2.11"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old password: %v", err)
	}
	if _, err := svc.BeginLogin(ctx, "bob", pw2, "192.0.2.11"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if got := auditCount(t, env, "cli.user_reset"); got != before+2 {
		t.Fatalf("cli.user_reset events = %d, want %d", got, before+2)
	}

	for _, args := range [][]string{
		{"user", "reset", "bob"},
		{"user", "reset", "nobody", "--totp"},
		{"user", "reset", "--totp"},
	} {
		if code, out := cli(t, env, "", args...); code != 1 {
			t.Fatalf("%v: exit %d\n%s", args, code, out)
		}
	}
}

func TestUserUnlockAndResetClearAccountLock(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	code, out := cli(t, env, pw1+"\n", "admin", "create", "--user", "erin", "--password-file", "-")
	if code != 0 {
		t.Fatalf("admin create: %d\n%s", code, out)
	}
	svc := auth.NewService(env.Pool("nms_api"), testKey, nil)
	lock := func() {
		t.Helper()
		for range 5 {
			if _, err := svc.BeginLogin(ctx, "erin", "wrong-password-123", "192.0.2.20"); !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Fatalf("bad password: %v", err)
			}
		}
		if _, err := svc.BeginLogin(ctx, "erin", pw1, "192.0.2.21"); !errors.Is(err, auth.ErrLocked) {
			t.Fatalf("after 5 failures: %v, want ErrLocked", err)
		}
	}
	before := auditCount(t, env, "cli.user_unlock")

	lock()
	if code, out := cli(t, env, "", "user", "unlock", "erin"); code != 0 {
		t.Fatalf("user unlock: %d\n%s", code, out)
	}
	if _, err := svc.BeginLogin(ctx, "erin", pw1, "192.0.2.21"); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	if got := auditCount(t, env, "cli.user_unlock"); got != before+1 {
		t.Fatalf("cli.user_unlock events = %d, want %d", got, before+1)
	}
	var result string
	if err := env.Pool("postgres").QueryRow(ctx,
		`SELECT convert_from(payload, 'UTF8')::jsonb->>'result' FROM audit.event
		 WHERE action = 'cli.user_unlock' ORDER BY id DESC LIMIT 1`).Scan(&result); err != nil || result != "success" {
		t.Fatalf("cli.user_unlock result = %q, %v; want success", result, err)
	}

	lock()
	if code, out := cli(t, env, "", "user", "reset", "erin", "--totp"); code != 0 {
		t.Fatalf("user reset: %d\n%s", code, out)
	}
	if _, err := svc.BeginLogin(ctx, "erin", pw1, "192.0.2.21"); err != nil {
		t.Fatalf("after reset: %v", err)
	}

	for _, args := range [][]string{
		{"user", "unlock"},
		{"user", "unlock", "nobody"},
		{"user", "unlock", "erin", "extra"},
		{"user", "unlock", "--totp"},
	} {
		if code, out := cli(t, env, "", args...); code != 1 {
			t.Fatalf("%v: exit %d\n%s", args, code, out)
		}
	}
}

/* resetAudit empties the log as postgres with the guard triggers disabled. */
func resetAudit(t *testing.T, env *testdb.Env, extra ...string) {
	t.Helper()
	ctx := context.Background()
	stmts := append([]string{
		`ALTER TABLE audit.event DISABLE TRIGGER USER`,
		`ALTER TABLE audit.chain_head DISABLE TRIGGER USER`,
	}, extra...)
	stmts = append(stmts,
		`ALTER TABLE audit.event ENABLE TRIGGER USER`,
		`ALTER TABLE audit.chain_head ENABLE TRIGGER USER`)
	err := pgx.BeginFunc(ctx, env.Pool("postgres"), func(tx pgx.Tx) error {
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

const truncateAudit = `TRUNCATE audit.event RESTART IDENTITY`
const resetHead = `UPDATE audit.chain_head SET last_id = 0, hash = decode(repeat('00', 32), 'hex')`

func appendEvents(t *testing.T, env *testdb.Env, ts time.Time, n int) {
	t.Helper()
	ctx := context.Background()
	for i := range n {
		err := pgx.BeginFunc(ctx, env.Pool("nms_api"), func(tx pgx.Tx) error {
			_, err := audit.Append(ctx, tx, audit.Event{TS: ts, Action: "test.event", Result: "ok", ObjectID: fmt.Sprint(i)})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditVerifyCLIExitCodes(t *testing.T) {
	env := testdb.New(t)
	resetAudit(t, env, truncateAudit, resetHead)
	t.Cleanup(func() { resetAudit(t, env, truncateAudit, resetHead) })
	anchors := filepath.Join(t.TempDir(), "anchors.log")

	appendEvents(t, env, time.Now(), 3)
	if code, out := cli(t, env, "", "audit", "verify", "--anchors", anchors); code != 0 || !strings.Contains(out, "OK") {
		t.Fatalf("intact chain: exit %d\n%s", code, out)
	}

	if code, out := cli(t, env, "", "audit", "anchor", "--anchors", anchors); code != 0 {
		t.Fatalf("anchor: exit %d\n%s", code, out)
	}
	f, err := os.Open(anchors) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	got, err := audit.ParseAnchors(f)
	_ = f.Close()
	if err != nil || len(got) != 1 || got[0].ID != 3 {
		t.Fatalf("anchors file: %+v %v", got, err)
	}
	if code, out := cli(t, env, "", "audit", "verify", "--anchors", anchors); code != 0 {
		t.Fatalf("anchored chain: exit %d\n%s", code, out)
	}

	/* A forged payload breaks the chain. */
	resetAudit(t, env, `UPDATE audit.event SET payload = convert_to(replace(convert_from(payload, 'UTF8'), '"ok"', '"denied"'), 'UTF8') WHERE id = 2`)
	code, out := cli(t, env, "", "audit", "verify", "--anchors", anchors)
	if code != 1 || !strings.Contains(out, "hash mismatch") || !strings.Contains(out, "2") {
		t.Fatalf("tampered chain: exit %d\n%s", code, out)
	}

	/* Truncation with a rewritten head passes Verify but not the anchors. */
	resetAudit(t, env, truncateAudit, resetHead)
	appendEvents(t, env, time.Now(), 2)
	code, out = cli(t, env, "", "audit", "verify", "--anchors", anchors)
	if code != 1 || !strings.Contains(out, "anchor 3") {
		t.Fatalf("anchor mismatch: exit %d\n%s", code, out)
	}
}

func TestAuditVerifyRequiresAnchorsForOldEvents(t *testing.T) {
	env := testdb.New(t)
	resetAudit(t, env, truncateAudit, resetHead)
	t.Cleanup(func() { resetAudit(t, env, truncateAudit, resetHead) })
	dir := t.TempDir()
	missing, empty := filepath.Join(dir, "missing.log"), filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	appendEvents(t, env, time.Now().Add(-2*time.Hour), 2)
	for _, p := range []string{missing, empty} {
		code, out := cli(t, env, "", "audit", "verify", "--anchors", p)
		if code != 1 || !strings.Contains(out, "no anchors") {
			t.Fatalf("%s: exit %d\n%s", p, code, out)
		}
	}
	if code, out := cli(t, env, "", "audit", "anchor", "--anchors", empty); code != 0 {
		t.Fatalf("anchor: exit %d\n%s", code, out)
	}
	if code, out := cli(t, env, "", "audit", "verify", "--anchors", empty); code != 0 {
		t.Fatalf("anchored: exit %d\n%s", code, out)
	}
}

func TestAuditVerifyFailsOnStaleAnchors(t *testing.T) {
	env := testdb.New(t)
	resetAudit(t, env, truncateAudit, resetHead)
	t.Cleanup(func() { resetAudit(t, env, truncateAudit, resetHead) })
	anchors := filepath.Join(t.TempDir(), "anchors.log")

	appendEvents(t, env, time.Now(), 2)
	if code, out := cli(t, env, "", "audit", "anchor", "--anchors", anchors); code != 0 {
		t.Fatalf("anchor: exit %d\n%s", code, out)
	}
	/* Backdate the anchor by 3 h: the timer has not run since. */
	f, err := os.Open(anchors) // #nosec G304 -- test path
	if err != nil {
		t.Fatal(err)
	}
	got, err := audit.ParseAnchors(f)
	_ = f.Close()
	if err != nil || len(got) != 1 {
		t.Fatalf("anchors file: %+v %v", got, err)
	}
	got[0].At = time.Now().Add(-3 * time.Hour)
	if err := os.WriteFile(anchors, []byte(got[0].String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := cli(t, env, "", "audit", "verify", "--anchors", anchors); code != 0 {
		t.Fatalf("old anchor, no newer events: exit %d\n%s", code, out)
	}

	appendEvents(t, env, time.Now(), 1)
	code, out := cli(t, env, "", "audit", "verify", "--anchors", anchors)
	if code != 1 || !strings.Contains(out, "anchor timer is not running") {
		t.Fatalf("stale anchor: exit %d\n%s", code, out)
	}
	if code, out := cli(t, env, "", "audit", "anchor", "--anchors", anchors); code != 0 {
		t.Fatalf("anchor: exit %d\n%s", code, out)
	}
	if code, out := cli(t, env, "", "audit", "verify", "--anchors", anchors); code != 0 {
		t.Fatalf("fresh anchor: exit %d\n%s", code, out)
	}
}

func TestHostRunsDBCommandsInToolsContainer(t *testing.T) {
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte(pw1+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sys := &fakeSys{}
	var out bytes.Buffer
	d := deps{in: strings.NewReader(""), out: &out, errw: &out, sys: sys, now: time.Now,
		openDB: func(context.Context) (*pgxpool.Pool, *[32]byte, func(), error) {
			t.Fatal("host process opened the database")
			return nil, nil, nil, nil
		}}
	prefix := "docker compose -f /etc/nms/compose.yaml --profile tools run --rm --no-deps -T nmsctl "
	cases := []struct {
		args  []string
		want  string
		stdin string
	}{
		{[]string{"admin", "create", "--user", "dave", "--password-file", pwFile}, "admin create --user dave --password-file -", pw1 + "\n"},
		{[]string{"user", "reset", "dave", "--password", "--password-file", pwFile}, "user reset dave --password --password-file -", pw1 + "\n"},
		{[]string{"user", "reset", "dave", "--totp"}, "user reset dave --totp", ""},
		{[]string{"user", "unlock", "dave"}, "user unlock dave", ""},
		{[]string{"audit", "verify"}, "audit verify", ""},
		{[]string{"audit", "anchor"}, "audit anchor", ""},
	}
	for i, c := range cases {
		if code := run(context.Background(), c.args, d); code != 0 {
			t.Fatalf("%v: exit %d\n%s", c.args, code, out.String())
		}
		got := sys.cmds[i].Name + " " + strings.Join(sys.cmds[i].Args, " ")
		if got != prefix+c.want || sys.stdins[i] != c.stdin {
			t.Fatalf("%v:\n got %q stdin %q\nwant %q stdin %q", c.args, got, sys.stdins[i], prefix+c.want, c.stdin)
		}
	}
	if code := run(context.Background(), []string{"install", "--public-host", "x"}, deps{out: &out, errw: &out, sys: &fakeSys{inContainer: true}}); code != 1 {
		t.Fatal("install ran inside the container")
	}
}

func TestEgressCheck(t *testing.T) {
	old := egressFile
	t.Cleanup(func() { egressFile = old })
	egressFile = filepath.Join(t.TempDir(), "egress.yaml")
	if err := os.WriteFile(egressFile, []byte("devices_subnet: 172.30.1.0/24\nmgmt_subnets: [10.0.0.0/8]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	argv := func(c install.Cmd) string { return c.Name + " " + strings.Join(c.Args, " ") }
	/* The chain as "iptables -L --line-numbers" prints it: per port the RETURN rule, then the DROP. */
	listing := func(dropFirst bool) string {
		var b strings.Builder
		n := 0
		for _, p := range []string{"udp-1514", "tcp-1514", "tcp-6514", "udp-1162"} {
			rows := []string{"RETURN", "DROP"}
			if dropFirst {
				rows = []string{"DROP", "RETURN"}
			}
			for _, tgt := range rows {
				n++
				fmt.Fprintf(&b, "%d    %s     all  --  0.0.0.0/0   172.30.1.0/24   /* nms-ingress-%s */\n", n, tgt, p)
			}
		}
		return b.String()
	}
	for _, c := range []struct {
		err   error
		match string
		code  int
		note  string
	}{
		{nil, "", 0, ""},
		{nil, "order", 1, "nms-ingress-udp-1514"},
		{errors.New("exit status 1"), "", 1, "DOCKER-USER"},
		/* Docker passes traffic to DOCKER-USER, but the eventd ingress rule is gone. */
		{errors.New("exit status 1"), "nms-ingress-tcp-6514 -j DROP", 1, "--dport 6514"},
		{errors.New("exit status 1"), "-s 172.30.1.0/24 -j DROP", 1, "-s 172.30.1.0/24 -j DROP"},
	} {
		sys := &fakeSys{err: c.err, failMatch: c.match, listing: listing(c.match == "order")}
		if c.match == "order" {
			sys.failMatch, sys.err = "", nil
		}
		var out bytes.Buffer
		code := run(context.Background(), []string{"egress", "check"}, deps{out: &out, errw: &out, sys: sys})
		if code != c.code || len(sys.cmds) == 0 || argv(sys.cmds[0]) != "iptables -w -C FORWARD -j DOCKER-USER" {
			t.Fatalf("err %v: exit %d, commands %v\n%s", c.err, code, sys.cmds, out.String())
		}
		if c.err == nil && c.code == 0 && len(sys.cmds) != 1+4*2+3+1 { /* FORWARD jump, 4 ports x (1 allow + DROP), conntrack + 1 subnet + DROP */
			t.Fatalf("checked %d rules: %v", len(sys.cmds), sys.cmds)
		}
		if c.note != "" && !strings.Contains(out.String(), c.note) {
			t.Fatalf("failure not explained (%q): %s", c.note, out.String())
		}
	}
	sys := &fakeSys{inContainer: true}
	var out bytes.Buffer
	if code := run(context.Background(), []string{"egress", "check"}, deps{out: &out, errw: &out, sys: sys}); code != 1 || len(sys.cmds) != 0 {
		t.Fatalf("egress check in container: exit %d, commands %v", code, sys.cmds)
	}
}

func TestEgressApplyOnlyOnHost(t *testing.T) {
	for _, c := range []struct {
		inContainer bool
		args        []string
	}{
		{true, []string{"egress", "apply"}},
		{false, []string{"egress", "apply", "--extra"}},
	} {
		sys := &fakeSys{inContainer: c.inContainer}
		var out bytes.Buffer
		if code := run(context.Background(), c.args, deps{out: &out, errw: &out, sys: sys}); code != 1 || len(sys.cmds) != 0 {
			t.Fatalf("%v in container=%v: exit %d, commands %v", c.args, c.inContainer, code, sys.cmds)
		}
	}
}
