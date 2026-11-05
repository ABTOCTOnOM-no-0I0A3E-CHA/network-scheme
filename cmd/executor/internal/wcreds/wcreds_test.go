package wcreds_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/wcreds"
	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/store"
	"github.com/beekamai/network-scheme/internal/testdb"
)

func TestMain(m *testing.M) { testdb.Main(m) }

const password = "Wr1te-Pass-0123456"

var admin = authz.Decision{UserID: 7, Username: "wadmin"}

type fixture struct {
	env     *testdb.Env
	reg     *registry.Registry
	st      *wcreds.Store
	pub     *[32]byte
	at      time.Time
	audited []string /* stage and reason of every refusal Record got */
}

/* newFixture is an executor registry with devices 1 (esr) and 2 (mes6), write-admin for admin and a write-domain key pair. */
func newFixture(t *testing.T) *fixture {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{5, 1})
	if err != nil {
		t.Fatal(err)
	}
	db, pw := env.Config("nms_executor")
	pool, err := store.Open(ctx, db, pw, registry.PinSession, registry.BoundMessages)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := registry.New(pool, keys, filepath.Join(t.TempDir(), "state"))
	guard := freeze.New(reg, pool, log)
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{env: env, reg: reg, pub: pub, at: time.Now().UTC().Truncate(time.Second)}
	f.st = &wcreds.Store{Gate: guard, Priv: priv, Pub: pub, Log: log, Record: func(_ context.Context, ev audit.Event) {
		f.audited = append(f.audited, fmt.Sprint(ev.Details["stage"], " ", ev.Details["reason"]))
	}}
	f.put(t, func(tx *registry.Tx) error {
		for id, drv := range map[int64]string{1: "esr", 2: "mes6"} {
			if err := tx.Put("write_device", map[string]any{"device_id": id, "address": netip.AddrFrom4([4]byte{10, 9, 0, byte(id)}), "port": 22,
				"protocol": "ssh", "write_group": "core", "write_driver": drv, "hostkey_algo": nil, "hostkey_fp": nil,
				"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false}); err != nil {
				return err
			}
		}
		return tx.Put("write_grant", map[string]any{"user_id": admin.UserID, "kind": "write-admin", "write_group": nil, "username_snapshot": admin.Username})
	})
	return f
}

func (f *fixture) put(t *testing.T, fn func(tx *registry.Tx) error) {
	t.Helper()
	if err := f.reg.Write(context.Background(), func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error { return fn(tx) }); err != nil {
		t.Fatal(err)
	}
}

/* sealed seals a payload as the browser does, with the nonce given (nil: random). */
func (f *fixture) sealed(t *testing.T, owner, kind string, at time.Time, nonce []byte, secret any) []byte {
	t.Helper()
	if nonce == nil {
		nonce = make([]byte, 16)
		_, _ = rand.Read(nonce)
	}
	pt, err := json.Marshal(map[string]any{"v": 1, "owner": owner, "kind": kind, "created_at": at.UTC().Format(time.RFC3339),
		"nonce": base64.StdEncoding.EncodeToString(nonce), "secret": secret})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := box.SealAnonymous(nil, pt, f.pub, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func login(pw string) map[string]string {
	return map[string]string{"username": "netadmin", "password": pw}
}

func (f *fixture) ct(t *testing.T, device int64, at time.Time) []byte {
	return f.sealed(t, fmt.Sprintf("device:%d", device), creds.KindSSHWrite, at, nil, login(password))
}

func params(device int64, ct []byte) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"device_id": device, "ciphertext": base64.StdEncoding.EncodeToString(ct)})
	return b
}

/* submit is the whole action as confirm runs it: Describe, then Run on the described challenge. */
func (f *fixture) submit(t *testing.T, device int64, ct []byte) error {
	t.Helper()
	ctx := context.Background()
	need, d, err := f.st.Describe(ctx, admin, params(device, ct))
	if err != nil {
		return err
	}
	if need.Kind != "write-admin" || d.Action != wcreds.Action {
		t.Fatalf("described %+v %s", need, d.Action)
	}
	_, err = f.st.Run(ctx, confirm.Challenge{Action: d.Action, Description: d}, admin)
	return err
}

func (f *fixture) stored(t *testing.T, device int64) []byte {
	t.Helper()
	var ct []byte
	if err := f.reg.View(context.Background(), func(s *registry.Snapshot) error {
		if r, ok := s.Get("write_credential", device); ok {
			ct, _ = r.Get("ciphertext").([]byte)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return ct
}

/*
C2j (security.md 18): a ciphertext sealed for device 1 submitted for device 2
is a mismatch inside Run's write, after the confirmation (Describe does not
open it); a description the client built itself never reaches the registry
either.
*/
func TestC2jCiphertextOfAnotherDeviceIsAMismatch(t *testing.T) {
	f := newFixture(t)
	ct := f.ct(t, 1, f.at)
	if err := f.submit(t, 2, ct); !errors.Is(err, wcreds.ErrMismatch) {
		t.Fatalf("submit: %v", err)
	}
	forged := confirm.Description{Action: wcreds.Action, Fields: []confirm.Field{{Key: "address", Value: "10.9.0.2"},
		{Key: "ciphertext", Value: base64.StdEncoding.EncodeToString(ct)}, {Key: "device_id", Value: "2"}, {Key: "write_key", Value: f.st.WriteKey()}}}
	if _, err := f.st.Run(context.Background(), confirm.Challenge{Action: wcreds.Action, Description: forged}, admin); !errors.Is(err, wcreds.ErrMismatch) {
		t.Fatalf("Run: %v", err)
	}
	if f.stored(t, 2) != nil {
		t.Fatal("device 2 got device 1's credential")
	}
	read := f.sealed(t, "device:2", creds.KindSSHRead, f.at, nil, login(password))
	if err := f.submit(t, 2, read); !errors.Is(err, wcreds.ErrMismatch) {
		t.Fatalf("an ssh_read payload: %v", err)
	}
}

/*
C2j: replaying an old ciphertext is stale; the stored one again, or a new
one with the same created_at, too; a newer created_at with the stored nonce
is a replay.
*/
func TestC2jReplayIsStale(t *testing.T) {
	f := newFixture(t)
	old, cur := f.ct(t, 1, f.at.Add(-time.Hour)), f.ct(t, 1, f.at)
	if err := f.submit(t, 1, old); err != nil {
		t.Fatal(err)
	}
	if err := f.submit(t, 1, cur); err != nil {
		t.Fatal(err)
	}
	for name, ct := range map[string][]byte{"old": old, "stored": cur, "same created_at": f.ct(t, 1, f.at)} {
		if err := f.submit(t, 1, ct); !errors.Is(err, wcreds.ErrStale) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !bytes.Equal(f.stored(t, 1), cur) {
		t.Fatal("the stored credential changed")
	}
	c, err := f.st.Open(view(t, f), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Wipe()
	again := f.sealed(t, "device:1", creds.KindSSHWrite, f.at.Add(time.Minute), c.Nonce, login(password))
	if err := f.submit(t, 1, again); !errors.Is(err, wcreds.ErrReplay) {
		t.Fatalf("stored nonce: %v", err)
	}
}

func view(t *testing.T, f *fixture) *registry.Snapshot {
	t.Helper()
	var snap *registry.Snapshot
	if err := f.reg.View(context.Background(), func(s *registry.Snapshot) error { snap = s; return nil }); err != nil {
		t.Fatal(err)
	}
	return snap
}

func rsaKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func edKey(t *testing.T) string {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	b, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(b))
}

/* Form and weakness (security.md 6.1) and the MES 6.x RSA-only rule ([R §4]); nothing refused is stored. */
func TestFormWeaknessAndKeyType(t *testing.T) {
	f := newFixture(t)
	for i, tc := range []struct {
		name   string
		device int64
		secret map[string]string
		want   error
	}{
		{"weak password", 1, login("short-pass1"), wcreds.ErrWeak},
		{"RSA 1024", 1, map[string]string{"username": "netadmin", "private_key": rsaKey(t, 1024)}, wcreds.ErrWeak},
		{"password and key", 1, map[string]string{"username": "netadmin", "password": password, "private_key": edKey(t)}, wcreds.ErrMalformed},
		{"no username", 1, map[string]string{"password": password}, wcreds.ErrMalformed},
		{"MES 6.x ed25519", 2, map[string]string{"username": "netadmin", "private_key": edKey(t)}, wcreds.ErrKeyType},
		{"unregistered device", 3, login(password), wcreds.ErrNotRegistered},
		{"ESR ed25519", 1, map[string]string{"username": "netadmin", "private_key": edKey(t)}, nil},
		{"MES 6.x RSA 2048", 2, map[string]string{"username": "netadmin", "private_key": rsaKey(t, 2048)}, nil},
	} {
		ct := f.sealed(t, fmt.Sprintf("device:%d", tc.device), creds.KindSSHWrite, f.at.Add(time.Duration(i)*time.Second), nil, tc.secret)
		before := f.stored(t, tc.device)
		err := f.submit(t, tc.device, ct)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
		if got := f.stored(t, tc.device); (tc.want == nil) != bytes.Equal(got, ct) || (tc.want != nil && !bytes.Equal(got, before)) {
			t.Errorf("%s: stored credential changed wrongly", tc.name)
		}
	}
	if _, _, err := f.st.Describe(context.Background(), admin, json.RawMessage(`{"device_id":1,"ciphertext":"!!","x":1}`)); !errors.Is(err, wcreds.ErrMalformed) {
		t.Errorf("bad params: %v", err)
	}
}

/* Only a write-admin whose grant snapshot is the ticket's name is described at all (no probing of the registry). */
func TestNeedsWriteAdmin(t *testing.T) {
	f := newFixture(t)
	for _, by := range []authz.Decision{{UserID: 8, Username: "other"}, {UserID: admin.UserID, Username: "renamed"}} {
		if _, _, err := f.st.Describe(context.Background(), by, params(1, f.ct(t, 1, f.at))); !errors.Is(err, wcreds.ErrDenied) {
			t.Errorf("%+v: %v", by, err)
		}
	}
}

/*
The binding is inside the ciphertext: a row that holds another device's
ciphertext under a valid MAC (as after a reset re-MACing tampered rows), or
whose created_at or nonce are not the payload's, does not open.
*/
func TestStoredCredentialIsBoundInside(t *testing.T) {
	f := newFixture(t)
	ct := f.ct(t, 1, f.at)
	if err := f.submit(t, 1, ct); err != nil {
		t.Fatal(err)
	}
	c, err := f.st.Open(view(t, f), 1)
	if err != nil || c.Password.Reveal() != password || c.Username != "netadmin" {
		t.Fatalf("open: %v", err)
	}
	nonce := c.Nonce
	c.Wipe()
	for name, row := range map[string]map[string]any{
		"another device's ciphertext": {"device_id": 2, "created_at": f.at, "nonce": nonce},
		"other created_at":            {"device_id": 1, "created_at": f.at.Add(-time.Second), "nonce": nonce},
		"other nonce":                 {"device_id": 1, "created_at": f.at, "nonce": bytes.Repeat([]byte{1}, 16)},
	} {
		row["kind"], row["ciphertext"] = creds.KindSSHWrite, ct
		f.put(t, func(tx *registry.Tx) error { return tx.Put("write_credential", row) })
		if _, err := f.st.Open(view(t, f), int64(row["device_id"].(int))); !errors.Is(err, wcreds.ErrMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := f.st.Open(view(t, f), 3); !errors.Is(err, wcreds.ErrNoCredential) {
		t.Errorf("no credential: %v", err)
	}
}

/* The roles of the api and the poller cannot read the stored write credentials at all. */
func TestAPIAndPollerCannotReadWriteCredentials(t *testing.T) {
	f := newFixture(t)
	if err := f.submit(t, 1, f.ct(t, 1, f.at)); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"nms_api", "nms_poller", "nms_eventd"} {
		_, err := f.env.Pool(role).Exec(context.Background(), `SELECT ciphertext FROM exec.write_credential`)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s read exec.write_credential: %v", role, err)
		}
	}
}

/*
Review M4: before the change TOTP Describe tells nothing of the ciphertext:
undecryptable bytes, another device's payload and a weak password all get
the same description (device id, address, write key fingerprint); refusals
of the grant or the device are audited at that stage.
*/
func TestDescribeTellsNothingOfTheCiphertext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var keys [][]string
	for _, ct := range [][]byte{[]byte("not a sealed box"), f.ct(t, 2, f.at), f.sealed(t, "device:1", creds.KindSSHWrite, f.at, nil, login("short-pass1"))} {
		_, d, err := f.st.Describe(ctx, admin, params(1, ct))
		if err != nil {
			t.Fatalf("Describe: %v", err)
		}
		var ks []string
		for _, fl := range d.Fields {
			ks = append(ks, fl.Key)
			if fl.Key == "address" && fl.Value != "10.9.0.1" || fl.Key == "write_key" && fl.Value != f.st.WriteKey() {
				t.Errorf("%s = %q", fl.Key, fl.Value)
			}
		}
		keys = append(keys, ks)
	}
	for _, ks := range keys {
		if fmt.Sprint(ks) != "[address ciphertext device_id write_key]" {
			t.Fatalf("described fields %v", ks)
		}
	}
	if _, _, err := f.st.Describe(ctx, admin, params(9, f.ct(t, 9, f.at))); !errors.Is(err, wcreds.ErrNotRegistered) {
		t.Fatalf("unregistered: %v", err)
	}
	if fmt.Sprint(f.audited) != "[describe not_registered]" {
		t.Fatalf("audited %v", f.audited)
	}
}

/* Review M1/M6: a device whose address changed after Describe, or a write key other than the confirmed one, is changed. */
func TestRunRefusesWhatChangedSinceTheConfirmation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, d, err := f.st.Describe(ctx, admin, params(1, f.ct(t, 1, f.at)))
	if err != nil {
		t.Fatal(err)
	}
	other := confirm.Description{Action: d.Action}
	for _, fl := range d.Fields {
		if fl.Key == "write_key" {
			fl.Value = "0000:0000:0000:0000:0000:0000:0000:0000"
		}
		other.Fields = append(other.Fields, fl)
	}
	if _, err := f.st.Run(ctx, confirm.Challenge{Action: d.Action, Description: other}, admin); !errors.Is(err, wcreds.ErrChanged) {
		t.Fatalf("other write key: %v", err)
	}
	f.put(t, func(tx *registry.Tx) error {
		return tx.Put("write_device", map[string]any{"device_id": 1, "address": netip.MustParseAddr("10.9.9.9"), "port": 22,
			"protocol": "ssh", "write_group": "core", "write_driver": "esr", "hostkey_algo": nil, "hostkey_fp": nil,
			"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false})
	})
	if _, err := f.st.Run(ctx, confirm.Challenge{Action: d.Action, Description: d}, admin); !errors.Is(err, wcreds.ErrChanged) {
		t.Fatalf("moved device: %v", err)
	}
	if f.stored(t, 1) != nil {
		t.Fatal("stored although changed")
	}
	if fmt.Sprint(f.audited) != "[run changed run changed]" {
		t.Fatalf("audited %v", f.audited)
	}
}

/* Review M2: a key stored for an ESR whose line is now MES 6.x does not open (RSA only). */
func TestOpenChecksTheLineAgain(t *testing.T) {
	f := newFixture(t)
	ct := f.sealed(t, "device:1", creds.KindSSHWrite, f.at, nil, map[string]string{"username": "netadmin", "private_key": edKey(t)})
	if err := f.submit(t, 1, ct); err != nil {
		t.Fatal(err)
	}
	f.put(t, func(tx *registry.Tx) error {
		return tx.Put("write_device", map[string]any{"device_id": 1, "address": netip.MustParseAddr("10.9.0.1"), "port": 22,
			"protocol": "ssh", "write_group": "core", "write_driver": "mes6", "hostkey_algo": nil, "hostkey_fp": nil,
			"allow_ssh_rsa_sha1": false, "writes_enabled": false, "backup_via_executor": false})
	})
	if _, err := f.st.Open(view(t, f), 1); !errors.Is(err, wcreds.ErrKeyType) {
		t.Fatalf("ed25519 on mes6: %v", err)
	}
}

/* failingGate fails every Write without a verdict and, if view is set, every View too. */
type failingGate struct {
	wcreds.Gate
	view bool
}

func (g failingGate) Write(context.Context, func(context.Context, *registry.Snapshot, *registry.Tx) error) error {
	return errors.New("commit outcome not known")
}

func (g failingGate) View(ctx context.Context, fn func(*registry.Snapshot) error) error {
	if g.view {
		return errors.New("registry unreadable")
	}
	return g.Gate.View(ctx, fn)
}

/* Review M3: a write without a verdict is read back; if that fails too the answer is outcome_unknown (503), never success or refusal. */
func TestRunOutcomeUnknown(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	_, d, err := f.st.Describe(ctx, admin, params(1, f.ct(t, 1, f.at)))
	if err != nil {
		t.Fatal(err)
	}
	live := f.st.Gate
	f.st.Gate = failingGate{Gate: live}
	cancel() /* the client went away: the read back still runs */
	if _, err := f.st.Run(ctx, confirm.Challenge{Action: d.Action, Description: d}, admin); err == nil || errors.Is(err, wcreds.ErrOutcomeUnknown) {
		t.Fatalf("not stored, registry readable: %v", err)
	}
	f.st.Gate = failingGate{Gate: live, view: true}
	_, err = f.st.Run(context.Background(), confirm.Challenge{Action: d.Action, Description: d}, admin)
	var st interface{ HTTPStatus() int }
	if !errors.Is(err, wcreds.ErrOutcomeUnknown) || !errors.As(err, &st) || st.HTTPStatus() != 503 {
		t.Fatalf("unreadable: %v", err)
	}
}
