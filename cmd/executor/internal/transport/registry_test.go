package transport_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/test/sim/devemu"
	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const pw = "transport-registry-pw-1"

var master = [32]byte{7}

func guard(t *testing.T) *freeze.Guard {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	k, err := seal.Derive(&master)
	if err != nil {
		t.Fatal(err)
	}
	pool := env.Pool("nms_executor")
	g := freeze.New(registry.New(pool, k, filepath.Join(t.TempDir(), "state")), pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := g.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return g
}

func put(t *testing.T, g *freeze.Guard, table string, row map[string]any) {
	t.Helper()
	if err := g.HostWrite(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		return tx.Put(table, row)
	}); err != nil {
		t.Fatal(err)
	}
}

/*
guardKind builds the network guard of the tests around dial, which connects
to the emulator wherever the guard let the connection go, and names the
error it denies with. fakeGuard stands in for netguard (4b.3), which
netguard_test.go adds to guards.
*/
type guardKind struct {
	build  func(dial func(ctx context.Context, address string) (net.Conn, error)) (transport.Dialer, error)
	denied error
}

var guards = map[string]guardKind{"fake": {build: newFakeGuard, denied: errFakeDenied}}

var errFakeDenied = errors.New("fake guard: address not allowed")

/* fakeGuard allows only host addresses of 192.0.2.0/24, as netguard with that management subnet. */
type fakeGuard struct {
	dial func(ctx context.Context, address string) (net.Conn, error)
}

func newFakeGuard(dial func(ctx context.Context, address string) (net.Conn, error)) (transport.Dialer, error) {
	return fakeGuard{dial}, nil
}

func (g fakeGuard) Dial(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	a := ap.Addr()
	if !netip.MustParsePrefix("192.0.2.0/24").Contains(a) || a.As4()[3] == 0 || a.As4()[3] == 255 {
		return nil, errFakeDenied
	}
	return g.dial(ctx, ap.String())
}

/* emulated is an MES 6.x device on loopback that the network guard reaches as if at a management address. */
type emulated struct {
	d      *devemu.Device
	log    *sshemu.Log
	key    gossh.PublicKey
	ng     transport.Dialer
	denied error
	mu     sync.Mutex
	seen   []string /* addresses the guard let through */
}

func emulate(t *testing.T, g guardKind) *emulated {
	t.Helper()
	e := &emulated{d: devemu.NewLine(t, "mes6", devemu.Options{}), denied: g.denied}
	var addr netip.AddrPort
	addr, e.key, e.log = devemu.StartSSH(t, e.d, func(c *sshemu.Config) { c.Username, c.Password = "admin", pw })
	ng, err := g.build(func(ctx context.Context, address string) (net.Conn, error) {
		e.mu.Lock()
		e.seen = append(e.seen, address)
		e.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr.String())
	})
	if err != nil {
		t.Fatal(err)
	}
	e.ng = ng
	return e
}

func (e *emulated) dialled() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.seen...)
}

func device(id int64, address string, fp string, writes bool) map[string]any {
	return map[string]any{"device_id": id, "address": netip.MustParseAddr(address), "port": 22, "protocol": "ssh",
		"write_group": "core", "write_driver": "mes6", "hostkey_algo": gossh.KeyAlgoRSA, "hostkey_fp": fp,
		"allow_ssh_rsa_sha1": true, "writes_enabled": writes, "backup_via_executor": false}
}

func config(g *freeze.Guard, e *emulated, id int64, access transport.Access) transport.Config {
	return transport.Config{DeviceID: id, Access: access, Credential: transport.Credential{Username: "admin", Password: secret.New(pw)},
		Registry: g, Net: e.ng, CommandTimeout: 5 * time.Second,
		Alert: func(context.Context, string, string, int64, string) error { return nil }}
}

func dial(t *testing.T, cfg transport.Config) (*transport.Shell, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sh, err := transport.Dial(ctx, cfg)
	if sh != nil {
		t.Cleanup(func() { _ = sh.Close() })
	}
	return sh, err
}

/*
The connection takes address, port, line and host key from the verified
write_device row only, through the network guard; the model gate reads the
verified model profiles: unverified allows only ReadOnly, a profile allows
writes with its strategies.
*/
func TestDialUsesTheVerifiedRegistry(t *testing.T) {
	for name, gk := range guards {
		t.Run(name, func(t *testing.T) { dialUsesTheVerifiedRegistry(t, gk) })
	}
}

func dialUsesTheVerifiedRegistry(t *testing.T, gk guardKind) {
	g, e := guard(t), emulate(t, gk)
	fp := gossh.FingerprintSHA256(e.key)
	put(t, g, "write_device", device(5, "192.0.2.10", fp, true))

	if _, err := dial(t, config(g, e, 6, transport.ReadOnly)); !errors.Is(err, transport.ErrNotRegistered) {
		t.Fatalf("unregistered device: %v", err)
	}
	if _, err := dial(t, config(g, e, 5, transport.Write)); !errors.Is(err, transport.ErrModelUnverified) {
		t.Fatalf("unverified write: %v", err)
	}
	sh, err := dial(t, config(g, e, 5, transport.ReadOnly))
	if err != nil || sh.Decision().Write {
		t.Fatalf("unverified read-only: %v", err)
	}
	put(t, g, "model_profile", map[string]any{"id": int64(1), "write_driver": "mes6", "model_re": "^(?:MES2324)$",
		"firmware_re": `^(?:6\.6\..*)$`, "strategies": json.RawMessage(`{"errors":"strict"}`), "note": "stand"})
	sh, err = dial(t, config(g, e, 5, transport.Write))
	if err != nil || !sh.Decision().Write || sh.Decision().Profile != 1 || sh.Strategies().Errors != "strict" {
		t.Fatalf("verified write: %v", err)
	}
	for _, a := range e.dialled() {
		if a != "192.0.2.10:22" {
			t.Errorf("dialled %s, not the registry's address", a)
		}
	}
	put(t, g, "write_device", device(5, "192.0.2.10", fp, false))
	if _, err := dial(t, config(g, e, 5, transport.Write)); !errors.Is(err, transport.ErrWritesDisabled) {
		t.Fatalf("writes disabled: %v", err)
	}
}

/* The network guard and the pinned host key apply at dial time, before any credential is sent. */
func TestNetguardAndHostKeyAtDial(t *testing.T) {
	for name, gk := range guards {
		t.Run(name, func(t *testing.T) { netguardAndHostKeyAtDial(t, gk) })
	}
}

func netguardAndHostKeyAtDial(t *testing.T, gk guardKind) {
	g, e := guard(t), emulate(t, gk)
	fp := gossh.FingerprintSHA256(e.key)
	for i, addr := range []string{"127.0.0.1", "172.30.1.5", "198.51.100.7", "192.0.2.255", "169.254.1.1"} {
		id := int64(10 + i)
		put(t, g, "write_device", device(id, addr, fp, true))
		if _, err := dial(t, config(g, e, id, transport.ReadOnly)); !errors.Is(err, e.denied) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if len(e.dialled()) != 0 || len(e.log.AuthAttempts()) != 0 {
		t.Fatalf("a denied address was dialled: %q %q", e.dialled(), e.log.AuthAttempts())
	}
	put(t, g, "write_device", device(20, "192.0.2.11", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true))
	if _, err := dial(t, config(g, e, 20, transport.ReadOnly)); !errors.Is(err, transport.ErrHostKeyMismatch) {
		t.Fatalf("other host key: %v", err)
	}
	unpinned := device(21, "192.0.2.12", "", false)
	unpinned["hostkey_algo"], unpinned["hostkey_fp"] = nil, nil
	put(t, g, "write_device", unpinned)
	if _, err := dial(t, config(g, e, 21, transport.ReadOnly)); !errors.Is(err, transport.ErrNoHostKey) {
		t.Fatalf("no accepted host key: %v", err)
	}
	if len(e.log.AuthAttempts()) != 0 || len(e.d.Journal()) != 0 {
		t.Fatalf("credential or command sent: %q %+v", e.log.AuthAttempts(), e.d.Journal())
	}
}
