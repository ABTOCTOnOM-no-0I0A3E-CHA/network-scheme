package ssh_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const password = "read-only-secret-pw"

var cred = creds.Credential{Kind: creds.KindSSHRead, Username: "mon", Password: secret.New(password)}

func must(t *testing.T) func(ssh.Arg, error) ssh.Arg {
	return func(a ssh.Arg, err error) ssh.Arg {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
}

func dialect() ssh.Dialect {
	return ssh.Dialect{
		ExecPrompt: regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}#$`),
		PagerOff:   []string{"terminal datadump"},
		Allowlist: []ssh.ShowCommand{
			{Name: "show version"},
			{Name: "show interfaces status", Args: []ssh.Arg{ssh.AnyIfName}},
			{Name: "show vlan tag", Args: []ssh.Arg{ssh.AnyVLANID}},
		},
	}
}

/* newDevice inserts a device row and returns its id. */
func newDevice(t *testing.T, env *testdb.Env) int64 {
	t.Helper()
	ctx := context.Background()
	p := env.Pool("postgres")
	var gid, id int64
	if err := p.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('g-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `INSERT INTO core.device (name, address, group_id)
		VALUES ('d', '10.0.0.0'::inet + $1, $1)
		RETURNING id`, gid).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func emu(t *testing.T, key gossh.Signer, cfg sshemu.Config) (netip.AddrPort, *sshemu.Log) {
	t.Helper()
	cfg.HostKey = key
	if cfg.Prompt == "" {
		cfg.Prompt = "sw1#"
	}
	cfg.Username, cfg.Password = "mon", password
	return sshemu.Start(t, cfg)
}

func TestOnlyAllowlistedCommandsReachDevice(t *testing.T) {
	env := testdb.New(t)
	hk := ssh.NewHostKeys(env.Pool("nms_poller"))
	id := newDevice(t, env)
	addr, log := emu(t, sshemu.NewHostKey(t), sshemu.Config{Responses: map[string]string{
		"terminal datadump":              "",
		"show version":                   "SW version 10.3.6\nBoot 1.0",
		"show interfaces status gi1/0/1": "gi1/0/1 Up",
		"show vlan tag 100":              "VLAN 100",
	}})
	ctx := context.Background()
	arg := must(t)
	r, err := ssh.Dial(ctx, addr, id, cred, hk, dialect())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	out, err := r.Run(ctx, ssh.ShowCommand{Name: "show version"})
	if err != nil || out != "SW version 10.3.6\nBoot 1.0" {
		t.Fatalf("show version: %q %v", out, err)
	}
	if out, err := r.Run(ctx, ssh.ShowCommand{Name: "show interfaces status", Args: []ssh.Arg{arg(ssh.IfName("gi1/0/1"))}}); err != nil || out != "gi1/0/1 Up" {
		t.Fatalf("show interfaces: %q %v", out, err)
	}
	if _, err := r.Run(ctx, ssh.ShowCommand{Name: "show vlan tag", Args: []ssh.Arg{arg(ssh.VLANID(100))}}); err != nil {
		t.Fatal(err)
	}

	vlan := arg(ssh.VLANID(5))
	ifn := arg(ssh.IfName("gi1/0/2"))
	rejected := []ssh.ShowCommand{
		{Name: "reload"},
		{Name: "configure terminal"},
		{Name: "show version "},
		{Name: "SHOW VERSION"},
		{Name: "show version", Args: []ssh.Arg{ifn}},                     /* extra arg */
		{Name: "show interfaces status"},                                 /* missing arg */
		{Name: "show interfaces status", Args: []ssh.Arg{vlan}},          /* wrong kind */
		{Name: "show interfaces status", Args: []ssh.Arg{ssh.AnyIfName}}, /* placeholder has no value */
		{Name: "show interfaces status", Args: []ssh.Arg{{}}},            /* zero Arg */
		{Name: "show version\nreload"},
	}
	for _, c := range rejected {
		if _, err := r.Run(ctx, c); !errors.Is(err, ssh.ErrNotAllowed) {
			t.Errorf("%q %v: got %v", c.Name, c.Args, err)
		}
	}
	/* The session is still usable after rejections. */
	if _, err := r.Run(ctx, ssh.ShowCommand{Name: "show version"}); err != nil {
		t.Fatal(err)
	}
	want := []string{"terminal datadump", "show version", "show interfaces status gi1/0/1", "show vlan tag 100", "show version"}
	if got := log.Commands(); !slices.Equal(got, want) {
		t.Fatalf("device saw %q, want %q", got, want)
	}
}

func TestConfigPromptAborts(t *testing.T) {
	env := testdb.New(t)
	hk := ssh.NewHostKeys(env.Pool("nms_poller"))
	ctx := context.Background()
	key := sshemu.NewHostKey(t)

	t.Run("after a command", func(t *testing.T) {
		addr, log := emu(t, key, sshemu.Config{
			Responses:   map[string]string{"terminal datadump": "", "show version": "v1"},
			PromptAfter: map[string]string{"show version": "sw1(config)#"},
		})
		r, err := ssh.Dial(ctx, addr, newDevice(t, env), cred, hk, dialect())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		if _, err := r.Run(ctx, ssh.ShowCommand{Name: "show version"}); !errors.Is(err, ssh.ErrUnexpectedPrompt) {
			t.Fatalf("got %v", err)
		}
		if _, err := r.Run(ctx, ssh.ShowCommand{Name: "show version"}); !errors.Is(err, ssh.ErrClosed) {
			t.Fatalf("after abort: %v", err)
		}
		if got := log.Commands(); !slices.Equal(got, []string{"terminal datadump", "show version"}) {
			t.Fatalf("device saw %q", got)
		}
	})
	t.Run("unanchored dialect regexp", func(t *testing.T) {
		d := dialect()
		d.ExecPrompt = regexp.MustCompile(`#$`)
		addr, log := emu(t, key, sshemu.Config{
			Prompt:      "#",
			Responses:   map[string]string{"terminal datadump": "", "show version": "v1"},
			PromptAfter: map[string]string{"show version": "sw1(config)#"},
		})
		r, err := ssh.Dial(ctx, addr, newDevice(t, env), cred, hk, d)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		if _, err := r.Run(ctx, ssh.ShowCommand{Name: "show version"}); !errors.Is(err, ssh.ErrUnexpectedPrompt) {
			t.Fatalf("got %v", err)
		}
		if _, err := r.Run(ctx, ssh.ShowCommand{Name: "show version"}); !errors.Is(err, ssh.ErrClosed) {
			t.Fatalf("after abort: %v", err)
		}
		if got := log.Commands(); !slices.Equal(got, []string{"terminal datadump", "show version"}) {
			t.Fatalf("device saw %q", got)
		}
	})
	t.Run("at login", func(t *testing.T) {
		addr, log := emu(t, key, sshemu.Config{Prompt: "sw1(config)#"})
		if _, err := ssh.Dial(ctx, addr, newDevice(t, env), cred, hk, dialect()); !errors.Is(err, ssh.ErrUnexpectedPrompt) {
			t.Fatalf("got %v", err)
		}
		if got := log.Commands(); len(got) != 0 {
			t.Fatalf("device saw %q", got)
		}
	})
}

func pinned(t *testing.T, env *testdb.Env, id int64) (algo, fp string) {
	t.Helper()
	err := env.Pool("postgres").QueryRow(context.Background(),
		`SELECT algorithm, fingerprint_sha256 FROM ssh_hosts.host_key WHERE device_id = $1`, id).Scan(&algo, &fp)
	if err != nil {
		t.Fatal(err)
	}
	return algo, fp
}

func TestTOFUPinsByDevice(t *testing.T) {
	env := testdb.New(t)
	hk := ssh.NewHostKeys(env.Pool("nms_poller"))
	ctx := context.Background()
	id := newDevice(t, env)
	key := sshemu.NewHostKey(t)
	resp := sshemu.Config{Responses: map[string]string{"terminal datadump": ""}}

	addr, _ := emu(t, key, resp)
	r, err := ssh.Dial(ctx, addr, id, cred, hk, dialect())
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	algo, fp := pinned(t, env, id)
	if algo != gossh.KeyAlgoED25519 || fp != gossh.FingerprintSHA256(key.PublicKey()) {
		t.Fatalf("pinned %s %s", algo, fp)
	}
	/* Same key on a new address: the pin follows the device, not the address. */
	addr2, _ := emu(t, key, resp)
	r, err = ssh.Dial(ctx, addr2, id, cred, hk, dialect())
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	/* Another device on the same address gets its own pin. */
	other := newDevice(t, env)
	r, err = ssh.Dial(ctx, addr, other, cred, hk, dialect())
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if _, fp2 := pinned(t, env, other); fp2 != fp {
		t.Fatalf("other device pin %s", fp2)
	}
}

func TestTOFURaceSafe(t *testing.T) {
	env := testdb.New(t)
	hk := ssh.NewHostKeys(env.Pool("nms_poller"))
	id := newDevice(t, env)
	addr := netip.MustParseAddr("192.0.2.1")
	tcp := &net.TCPAddr{IP: net.IP(addr.AsSlice()), Port: 22}
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		key := sshemu.NewHostKey(t).PublicKey()
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = hk.Callback(id, addr)("h:22", tcp, key)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ssh.ErrHostKeyMismatch):
			t.Fatalf("unexpected: %v", err)
		}
	}
	var mismatches int
	if err := env.Pool("postgres").QueryRow(context.Background(),
		`SELECT count(*) FROM ssh_hosts.mismatch WHERE device_id = $1 AND address = $2`, id, addr).Scan(&mismatches); err != nil {
		t.Fatal(err)
	}
	if ok != 1 || mismatches != n-1 {
		t.Fatalf("accepted %d, mismatches %d", ok, mismatches)
	}
}

func TestHostKeyMismatchSendsNoCredential(t *testing.T) {
	env := testdb.New(t)
	hk := ssh.NewHostKeys(env.Pool("nms_poller"))
	ctx := context.Background()
	id := newDevice(t, env)
	resp := sshemu.Config{Responses: map[string]string{"terminal datadump": ""}}

	addr, _ := emu(t, sshemu.NewHostKey(t), resp)
	r, err := ssh.Dial(ctx, addr, id, cred, hk, dialect())
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	_, fp := pinned(t, env, id)

	impostorKey := sshemu.NewHostKey(t)
	impostor, log := emu(t, impostorKey, resp)
	if _, err := ssh.Dial(ctx, impostor, id, cred, hk, dialect()); !errors.Is(err, ssh.ErrHostKeyMismatch) {
		t.Fatalf("got %v", err)
	}
	if got := log.AuthAttempts(); len(got) != 0 {
		t.Fatalf("impostor saw auth attempts %q", got)
	}
	for _, c := range log.Commands() {
		t.Fatalf("impostor saw command %q", c)
	}
	if _, fp2 := pinned(t, env, id); fp2 != fp {
		t.Fatal("pin changed")
	}
	var seen string
	var at netip.Addr
	if err := env.Pool("postgres").QueryRow(ctx,
		`SELECT seen_fingerprint, address FROM ssh_hosts.mismatch WHERE device_id = $1`, id).Scan(&seen, &at); err != nil {
		t.Fatal(err)
	}
	if seen != gossh.FingerprintSHA256(impostorKey.PublicKey()) || at != impostor.Addr() {
		t.Fatalf("mismatch row %s %s", seen, at)
	}
}

func TestTypedArgsRejectInjection(t *testing.T) {
	for _, s := range []string{"gi1/0/1; reload", "gi1/0/1\nreload", "gi 1/0/1", "", strings.Repeat("a", 65), "gi1/0/1|inc", "gi1/0/1\x00", "гиг1"} {
		if _, err := ssh.IfName(s); err == nil {
			t.Errorf("IfName(%q) accepted", s)
		}
	}
	for _, s := range []string{"gi1/0/1", "te1/0/1.100", "Port-channel1", "vlan:1", strings.Repeat("a", 64)} {
		if _, err := ssh.IfName(s); err != nil {
			t.Errorf("IfName(%q): %v", s, err)
		}
	}
	for _, v := range []int{0, -1, 4095, 1 << 20} {
		if _, err := ssh.VLANID(v); err == nil {
			t.Errorf("VLANID(%d) accepted", v)
		}
	}
	for _, v := range []int{1, 4094} {
		if _, err := ssh.VLANID(v); err != nil {
			t.Errorf("VLANID(%d): %v", v, err)
		}
	}
}

func TestDialRejectsUnsafeDialect(t *testing.T) {
	ctx := context.Background()
	addr := netip.MustParseAddrPort("127.0.0.1:1")
	for name, d := range map[string]ssh.Dialect{
		"no prompt":       {PagerOff: []string{"terminal datadump"}},
		"newline pager":   {ExecPrompt: regexp.MustCompile(`#$`), PagerOff: []string{"terminal datadump\nreload"}},
		"newline command": {ExecPrompt: regexp.MustCompile(`#$`), Allowlist: []ssh.ShowCommand{{Name: "show version\rreload"}}},
		"bad placeholder": {ExecPrompt: regexp.MustCompile(`#$`), Allowlist: []ssh.ShowCommand{{Name: "show x", Args: []ssh.Arg{{}}}}},
	} {
		if _, err := ssh.Dial(ctx, addr, 1, cred, (*ssh.HostKeys)(nil), d); err == nil || !strings.Contains(err.Error(), "dialect") {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := cred
	bad.Kind = creds.KindTelnet
	if _, err := ssh.Dial(ctx, addr, 1, bad, (*ssh.HostKeys)(nil), dialect()); err == nil {
		t.Error("telnet credential accepted")
	}
}

func TestHostKeyGrants(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	id := newDevice(t, env)
	if _, err := env.Pool("postgres").Exec(ctx,
		`INSERT INTO ssh_hosts.host_key (device_id, algorithm, fingerprint_sha256) VALUES ($1, 'ssh-ed25519', 'SHA256:x')`, id); err != nil {
		t.Fatal(err)
	}
	denied := func(p *pgxpool.Pool, sql string, args ...any) {
		t.Helper()
		_, err := p.Exec(ctx, sql, args...)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%q: want 42501, got %v", sql, err)
		}
	}
	api, poller, cli := env.Pool("nms_api"), env.Pool("nms_poller"), env.Pool("nms_cli")
	denied(api, `SELECT 1 FROM ssh_hosts.host_key`)
	denied(api, `SELECT 1 FROM ssh_hosts.mismatch`)
	denied(poller, `UPDATE ssh_hosts.host_key SET fingerprint_sha256 = 'SHA256:y' WHERE device_id = $1`, id)
	denied(poller, `DELETE FROM ssh_hosts.host_key WHERE device_id = $1`, id)
	denied(poller, `SELECT 1 FROM ssh_hosts.mismatch`)
	denied(cli, `INSERT INTO ssh_hosts.host_key (device_id, algorithm, fingerprint_sha256) VALUES ($1, 'a', 'SHA256:z')`, id+1)
	denied(cli, `DELETE FROM ssh_hosts.mismatch`)
	if _, err := cli.Exec(ctx, `DELETE FROM ssh_hosts.host_key WHERE device_id = $1`, id); err != nil {
		t.Fatalf("nmsctl reset: %v", err)
	}
}

/*
A compromised api must not be able to delete a device and re-create it under
the same id to get a fresh TOFU pin and the device's sealed read credential.
*/
func TestDeletedDeviceIDCannotBeReclaimed(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	hk := ssh.NewHostKeys(env.Pool("nms_poller"))
	pg := env.Pool("postgres")
	resp := sshemu.Config{Responses: map[string]string{"terminal datadump": ""}}

	var gid int64
	if err := pg.QueryRow(ctx, `INSERT INTO core.device_group (name) VALUES ('g-' || gen_random_uuid()) RETURNING id`).Scan(&gid); err != nil {
		t.Fatal(err)
	}
	/* One api session throughout, so currval() holds the deleted id. */
	api, err := env.Pool("nms_api").Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Release()
	insert := func(extra string, args ...any) (int64, error) {
		var id int64
		err := api.QueryRow(ctx, `INSERT INTO core.device `+extra, args...).Scan(&id)
		return id, err
	}
	x, err := insert(`(name, address, group_id) VALUES ('x', '10.200.0.0'::inet + $1, $1) RETURNING id`, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `INSERT INTO core.access_profile (owner_kind, owner_id, kind, ciphertext, key_version)
		VALUES ('device', $1, 'ssh_read', '\x00', 1)`, x); err != nil {
		t.Fatal(err)
	}
	realKey := sshemu.NewHostKey(t)
	addr, _ := emu(t, realKey, resp)
	r, err := ssh.Dial(ctx, addr, x, cred, hk, dialect())
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()

	if _, err := api.Exec(ctx, `DELETE FROM core.device WHERE id = $1`, x); err != nil {
		t.Fatal(err)
	}
	var profiles int
	if err := pg.QueryRow(ctx, `SELECT count(*) FROM core.access_profile WHERE owner_kind = 'device' AND owner_id = $1`, x).Scan(&profiles); err != nil || profiles != 0 {
		t.Fatalf("access profiles after delete: %d %v", profiles, err)
	}
	if _, fp := pinned(t, env, x); fp != gossh.FingerprintSHA256(realKey.PublicKey()) {
		t.Fatal("pin removed with the device")
	}

	denied := func(what string, err error) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: want 42501, got %v", what, err)
		}
	}
	_, err = insert(`(id, name, address, group_id) OVERRIDING SYSTEM VALUE VALUES ($1, 'x', '10.201.0.0'::inet + $2, $2) RETURNING id`, x, gid)
	denied("re-create deleted id", err)
	_, err = insert(`(id, name, address, group_id) OVERRIDING SYSTEM VALUE VALUES ($1, 'y', '10.202.0.0'::inet + $2, $2) RETURNING id`, x+1_000_000, gid)
	denied("explicit unused id", err)

	/* A legitimately re-added device gets a new id and its own pin. */
	y, err := insert(`(name, address, group_id) VALUES ('x', '10.200.0.0'::inet + $1, $1) RETURNING id`, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Exec(ctx, `UPDATE core.device SET id = $1 WHERE id = $2`, x, y); err == nil {
		t.Error("id change accepted")
	}
	impostorKey := sshemu.NewHostKey(t)
	impostor, log := emu(t, impostorKey, resp)
	r, err = ssh.Dial(ctx, impostor, y, cred, hk, dialect())
	if err != nil || y == x {
		t.Fatalf("new device %d: %v", y, err)
	}
	_ = r.Close()
	if _, fp := pinned(t, env, y); fp != gossh.FingerprintSHA256(impostorKey.PublicKey()) {
		t.Fatal("new device not pinned to its own key")
	}

	/* The old id still refuses the impostor before any credential is sent. */
	before := len(log.AuthAttempts())
	if _, err := ssh.Dial(ctx, impostor, x, cred, hk, dialect()); !errors.Is(err, ssh.ErrHostKeyMismatch) {
		t.Fatalf("old id: %v", err)
	}
	if got := log.AuthAttempts()[before:]; len(got) != 0 {
		t.Fatalf("impostor saw auth attempts %q", got)
	}
}
