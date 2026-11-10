package recording_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/testdb"
	"github.com/beekamai/network-scheme/internal/ticket"
)

func TestMain(m *testing.M) { testdb.Main(m) }

var ticketKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

/* Known test secrets (C8): none of them may be stored, in any form. */
var secrets = []string{"Secr3tUserPw1", "EnablePw77Xq", "CommStr99Zz", "RadKey55Yy", "PskAsc66Vv", "UrlPw33Uu", "PemBody88Tt", "TacKey44Ss"}

/* secretText is device output that carries every one of them. */
const secretText = "username admin privilege 15 password Secr3tUserPw1\n" +
	"enable password EnablePw77Xq\n" +
	"snmp-server community CommStr99Zz ro\n" +
	"radius-server host 192.0.2.5 key RadKey55Yy\n" +
	"tacacs-server host 192.0.2.6 key TacKey44Ss\n" +
	"security ike proposal p1\n pre-shared-key ascii-text PskAsc66Vv\n" +
	"boot host sftp://bob:UrlPw33Uu@192.0.2.9/cfg\n" +
	"-----BEGIN RSA PRIVATE KEY-----\nPemBody88Tt\n-----END RSA PRIVATE KEY-----\n"

/* leak names the form in which a secret appears in b ("" if none): as is, base64 (three alphabets) or hex. */
func leak(b []byte) string {
	for _, s := range secrets {
		forms := map[string]string{"raw": s, "base64": base64.StdEncoding.EncodeToString([]byte(s)),
			"base64raw": base64.RawStdEncoding.EncodeToString([]byte(s)), "base64url": base64.RawURLEncoding.EncodeToString([]byte(s)),
			"hex": hex.EncodeToString([]byte(s)), "HEX": strings.ToUpper(hex.EncodeToString([]byte(s)))}
		for k, f := range forms {
			if bytes.Contains(b, []byte(f)) {
				return s + " as " + k
			}
		}
	}
	return ""
}

type fx struct {
	env       *testdb.Env
	st        *recording.Store
	az        *authz.Authorizer
	adm       *admin.Admin
	pol       *policy.Holder
	polF      string
	pub, priv *[32]byte
	mac       *[32]byte
	logs      *syncBuf
	start     time.Time
	offset    atomic.Int64
	mu        sync.Mutex
	alerts    []string /* kind/severity */
	live      map[[16]byte]bool
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b.Bytes())
}

func (f *fx) now() time.Time { return f.start.Add(time.Duration(f.offset.Load())) }

func newFx(t *testing.T) *fx {
	t.Helper()
	env := testdb.New(t)
	attacktest.Reset(t, env)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{8})
	if err != nil {
		t.Fatal(err)
	}
	f := &fx{env: env, start: time.Now(), logs: &syncBuf{}, live: map[[16]byte]bool{}}
	pool := env.Pool("nms_executor")
	log := slog.New(slog.NewJSONHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dir := t.TempDir()
	reg := registry.New(pool, keys, filepath.Join(dir, "state"))
	guard := freeze.New(reg, pool, log)
	if err := guard.Start(ctx); err != nil {
		t.Fatal(err)
	}
	f.polF = filepath.Join(dir, "executor.yaml")
	f.pol = policy.New(f.polF)
	f.policy(t, "")
	if f.az, err = authz.New(authz.Config{Guard: guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Now: f.now,
		TicketKey: ticketKey.Public().(ed25519.PublicKey), Started: f.start, GuardsFile: filepath.Join(dir, "guards")}); err != nil {
		t.Fatal(err)
	}
	f.adm = &admin.Admin{Guard: guard, Reg: reg, Keys: keys, Policy: f.pol, Log: log, Lockouts: f.az}
	if f.pub, f.priv, err = box.GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	f.mac = keys.MAC()
	if f.st, err = recording.New(recording.Config{Pool: pool, MAC: keys.MAC(), Pub: f.pub, Priv: f.priv, Clean: terminal.Clean,
		Policy: f.pol.Current, Live: func(id [16]byte) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.live[id]
		}, Alert: func(_ context.Context, kind, sev string, _ int64, _ string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.alerts = append(f.alerts, kind+"/"+sev)
			return nil
		}, Audit: f.az.Record, Log: log, Now: f.now}); err != nil {
		t.Fatal(err)
	}
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

/* session inserts a session and its device's row (as a session's open does) and returns the session's id. */
func (f *fx) session(t *testing.T, device int64) [16]byte {
	t.Helper()
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES ($1, 1, now(), '{}', $2)`,
		id, make([]byte, 32))
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
		VALUES ($1, $2, $3, 'x', 'x', $3)`, id, device, make([]byte, 32))
	return id
}

func sid(id [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

var mask = mes6.New().MaskSecrets

/* record writes a recording with secrets in its input and output (split across answers and chunks) and closes it. */
func (f *fx) record(t *testing.T, id [16]byte, device int64) {
	t.Helper()
	ctx := context.Background()
	s, err := f.st.Open(ctx, id, device, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return s.Input(ctx, "show running-config") },
		func() error { return s.Output(ctx, secretText) },
		func() error { return s.Input(ctx, "configure") },
		func() error { return s.Input(ctx, "enable password EnablePw77Xq") },
		func() error { return s.Mark(ctx, "dangerous line confirmed (challenge x)") },
		func() error { return s.Input(ctx, "crypto certificate c1 import") },
		func() error { return s.Input(ctx, "PemBody88Tt") },
		func() error { return s.Input(ctx, ".") },
		/* a PEM block across two answers */
		func() error { return s.Output(ctx, "-----BEGIN RSA PRIVATE KEY-----\n") },
		func() error { return s.Output(ctx, "PemBody88Tt\n-----END RSA PRIVATE KEY-----\n") },
		/* a secret split across two answers of the device */
		func() error { return s.Output(ctx, "snmp-server community Comm") },
		func() error { return s.Output(ctx, "Str99Zz ro\n") },
		func() error { return s.Input(ctx, "end") },
	}
	for i, st := range steps {
		f.offset.Add(int64(time.Second))
		if err := st(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if err := s.Close(ctx, "session ended: closed"); err != nil {
		t.Fatal(err)
	}
}

/* chunks returns the stored rows of a recording: n, ct, dek_ct, mac. */
func (f *fx) chunks(t *testing.T, id [16]byte, device int64) (out [][4]any) {
	t.Helper()
	rows, err := f.env.Pool("postgres").Query(context.Background(), `SELECT n, ct, dek_ct, mac FROM exec.recording_chunk
		WHERE session_id = $1 AND device_id = $2 ORDER BY n`, id, device)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			n            int
			ct, dek, mac []byte
		)
		if err := rows.Scan(&n, &ct, &dek, &mac); err != nil {
			t.Fatal(err)
		}
		out = append(out, [4]any{n, ct, dek, mac})
	}
	return out
}

/*
C8 (recording package): input and output are masked before anything is
stored — by the driver, the read drivers' mask.Secrets and the stream's block
state — also when a secret is split across two answers of the device or a
chunk boundary, or a PEM or "crypto ... import" block spans pieces. No known
test secret is in any decrypted chunk, its ciphertext rows, the logs or the
executor's audit, as is, in base64 or in hex; the replay is the recorded
fact but for the masks.
*/
func TestC8RecordingHoldsNoSecret(t *testing.T) {
	f := newFx(t)
	t.Cleanup(recording.SetMaxChunk(97)) /* many chunk boundaries, through every line */
	id := f.session(t, 7)
	f.record(t, id, 7)
	rows := f.chunks(t, id, 7)
	if len(rows) < 10 {
		t.Fatalf("%d chunks", len(rows))
	}
	var all []byte
	for _, r := range rows {
		n, ct, dek := r[0].(int), r[1].([]byte), r[2].([]byte)
		if w := leak(ct); w != "" || leak(dek) != "" {
			t.Fatalf("chunk %d ciphertext holds %s", n, w)
		}
		pt, err := open.Open(f.priv, f.pub, ct, dek, recording.AAD(id, 7, n))
		if err != nil {
			t.Fatalf("chunk %d: %v", n, err)
		}
		if len(pt) > recording.MaxChunk() {
			t.Fatalf("chunk %d: %d bytes", n, len(pt))
		}
		if w := leak(pt); w != "" {
			t.Fatalf("chunk %d holds %s: %q", n, w, pt)
		}
		all = append(all, pt...)
	}
	if w := leak(all); w != "" {
		t.Fatalf("the recording holds %s", w)
	}
	r, err := f.st.Replay(context.Background(), id, 7)
	if err != nil {
		t.Fatal(err)
	}
	var in, out, marks []string
	for _, e := range r.Events {
		switch e.Code {
		case "i":
			in = append(in, e.Data)
		case "o":
			out = append(out, e.Data)
		case "m":
			marks = append(marks, e.Data)
		}
	}
	wantIn := []string{"show running-config\n", "configure\n", mask("enable password EnablePw77Xq") + "\n",
		mask("crypto certificate c1 import") + "\n", "***\n", ".\n", "end\n"}
	if !slices.Equal(in, wantIn) {
		t.Fatalf("input %q, want %q", in, wantIn)
	}
	wantOut := []string{mask(secretText), "-----BEGIN RSA PRIVATE KEY-----\n", "***\n-----END RSA PRIVATE KEY-----\n",
		mask("snmp-server community CommStr99Zz ro\n")}
	if !slices.Equal(out, wantOut) || !slices.Equal(marks, []string{"session opened by tester", "dangerous line confirmed (challenge x)",
		"session ended: closed"}) {
		t.Fatalf("output %q\nmarks %q", out, marks)
	}
	if !strings.Contains(out[0], "username admin ***") || !strings.Contains(out[0], "sftp://***@192.0.2.9/cfg") {
		t.Fatalf("masks %q", out[0])
	}
	if w := leak(f.logs.Bytes()); w != "" {
		t.Fatalf("the log holds %s", w)
	}
	var audit []byte
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT coalesce(string_agg(payload, ''), '') FROM exec.audit_event`).
		Scan(&audit); err != nil || leak(audit) != "" {
		t.Fatalf("audit: %v %s", err, leak(audit))
	}
}

/* A chunk's plaintext never exceeds maxChunk (its row stays below registry.MaxMessage): a 3 MiB answer spans chunks. */
func TestChunkSizeBound(t *testing.T) {
	f := newFx(t)
	id := f.session(t, 7)
	ctx := context.Background()
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat(strings.Repeat("y ", 49)+"y\n", 3<<20/100) /* words, not key material */
	if err := s.Output(ctx, big); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx, "end"); err != nil {
		t.Fatal(err)
	}
	rows := f.chunks(t, id, 7)
	if len(rows) < 4 {
		t.Fatalf("%d chunks", len(rows))
	}
	for _, r := range rows {
		if ct := r[1].([]byte); len(ct) > recording.MaxChunk()+40 || recording.MaxChunk() > 1<<20 {
			t.Fatalf("chunk %d: %d bytes", r[0], len(ct))
		}
	}
	r, err := f.st.Replay(ctx, id, 7)
	if err != nil || len(r.Events) != 3 || r.Events[1].Data != big {
		t.Fatalf("replay: %v", err)
	}
}

/* Past recording_max_mib the stream refuses every further line (warning alert, once); markers, the end and the replay still work. */
func TestVolumeLimit(t *testing.T) {
	f := newFx(t)
	f.policy(t, "recording_max_mib: 1\n")
	id := f.session(t, 7)
	ctx := context.Background()
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Input(ctx, "show running-config"); err != nil {
		t.Fatal(err)
	}
	if err := s.Output(ctx, strings.Repeat("z\n", 1<<19)); err != nil { /* the answer to a line sent is recorded whole */
		t.Fatal(err)
	}
	for range 2 {
		if err := s.Input(ctx, "configure"); !errors.Is(err, recording.ErrFull) {
			t.Fatalf("over the limit: %v", err)
		}
	}
	if f.alerted(recording.KindFull) != 1 {
		t.Fatalf("alerts %v", f.alerts)
	}
	if err := s.Mark(ctx, "save"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx, "end"); err != nil {
		t.Fatal(err)
	}
	r, err := f.st.Replay(ctx, id, 7)
	if err != nil || r.Events[len(r.Events)-1].Data != "end" {
		t.Fatalf("replay: %v", err)
	}
	for _, e := range r.Events {
		if e.Code == "i" && e.Data == "configure\n" {
			t.Fatal("a refused line was recorded as sent")
		}
	}
}

/* A failed store latches: every further line and marker is refused (high alert, once); the end retries what was buffered. */
func TestRecorderFailureIsFailClosed(t *testing.T) {
	f := newFx(t)
	id := f.session(t, 7)
	ctx := context.Background()
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	/* chunk 1 taken by someone else: the next store fails */
	attacktest.Tamper(t, f.env, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ($1, 7, 1, 'x', 'x', $2)`,
		id, make([]byte, 32))
	if err := s.Input(ctx, "configure"); !errors.Is(err, recording.ErrFailed) {
		t.Fatalf("input: %v", err)
	}
	if err := s.Input(ctx, "hostname x"); !errors.Is(err, recording.ErrFailed) {
		t.Fatalf("next input: %v", err)
	}
	if err := s.Mark(ctx, "save"); !errors.Is(err, recording.ErrFailed) {
		t.Fatalf("mark: %v", err)
	}
	if f.alerted(recording.KindFailed) != 1 {
		t.Fatalf("alerts %v", f.alerts)
	}
	if err := s.Close(ctx, "end"); err == nil {
		t.Fatal("closed over the planted chunk")
	}
	if _, err := f.st.Replay(ctx, id, 7); !errors.Is(err, recording.ErrTampered) {
		t.Fatalf("replay without a manifest: %v", err)
	}
}

/*
C2h / tampering: the replay verifies the manifest and every chunk before
anything is returned. A swapped, deleted, truncated or duplicated chunk, a
changed manifest, a chunk sealed under another AAD (with a MAC only the
key's holder could make), a foreign session's chunk or a missing manifest
refuse the replay with a high tamper alert.
*/
func TestReplayRefusesTampering(t *testing.T) {
	t.Cleanup(recording.SetMaxChunk(300))
	f := newFx(t)
	/* su runs a statement as a superuser with the append-only triggers off for it */
	su := func(t *testing.T, sql string, args ...any) {
		t.Helper()
		attacktest.Tamper(t, f.env, `ALTER TABLE exec.recording_chunk DISABLE TRIGGER recording_chunk_append_only; ALTER TABLE exec.recording_manifest DISABLE TRIGGER recording_manifest_append_only`)
		defer attacktest.Tamper(t, f.env, `ALTER TABLE exec.recording_chunk ENABLE TRIGGER recording_chunk_append_only; ALTER TABLE exec.recording_manifest ENABLE TRIGGER recording_manifest_append_only`)
		attacktest.Tamper(t, f.env, sql, args...)
	}
	other := f.session(t, 9)
	f.record(t, other, 9)
	foreign := f.chunks(t, other, 9)
	cases := map[string]func(t *testing.T, id [16]byte){
		"swap": func(t *testing.T, id [16]byte) {
			su(t, `UPDATE exec.recording_chunk SET n = n + 500000 WHERE session_id = $1 AND n IN (1, 2)`, id)
			su(t, `UPDATE exec.recording_chunk SET n = CASE n WHEN 500001 THEN 2 ELSE 1 END WHERE session_id = $1 AND n > 499999`, id)
		},
		"delete": func(t *testing.T, id [16]byte) {
			su(t, `DELETE FROM exec.recording_chunk WHERE session_id = $1 AND n = 2`, id)
		},
		"truncate": func(t *testing.T, id [16]byte) {
			su(t, `DELETE FROM exec.recording_chunk WHERE session_id = $1 AND n = (SELECT max(n) FROM exec.recording_chunk WHERE session_id = $1)`, id)
		},
		"duplicate": func(t *testing.T, id [16]byte) {
			attacktest.Tamper(t, f.env, `INSERT INTO exec.recording_chunk SELECT session_id, device_id, (SELECT max(n) + 1 FROM exec.recording_chunk WHERE session_id = $1), ct, dek_ct, mac
				FROM exec.recording_chunk WHERE session_id = $1 AND n = 1`, id)
		},
		"manifest": func(t *testing.T, id [16]byte) {
			su(t, `UPDATE exec.recording_manifest SET chunks = chunks - 1 WHERE session_id = $1`, id)
		},
		"truncate, manifest rewritten to match": func(t *testing.T, id [16]byte) {
			rows := f.chunks(t, id, 7)
			h := sha256.New()
			for _, r := range rows[:len(rows)-1] {
				c, k := sha256.Sum256(r[1].([]byte)), sha256.Sum256(r[2].([]byte))
				h.Write(c[:])
				h.Write(k[:])
			}
			su(t, `DELETE FROM exec.recording_chunk WHERE session_id = $1 AND n = $2`, id, len(rows)-1)
			su(t, `UPDATE exec.recording_manifest SET chunks = $2, sha256 = $3 WHERE session_id = $1`, id, len(rows)-1, h.Sum(nil))
		},
		"no manifest": func(t *testing.T, id [16]byte) {
			su(t, `DELETE FROM exec.recording_manifest WHERE session_id = $1`, id)
		},
		"wrong aad": func(t *testing.T, id [16]byte) {
			ct, dek, err := backup.Seal(f.pub, []byte("[1.0, \"o\", \"forged\"]\n"), recording.AAD(id, 7, 3))
			if err != nil {
				t.Fatal(err)
			}
			c, k := sha256.Sum256(ct), sha256.Sum256(dek)
			su(t, `UPDATE exec.recording_chunk SET ct = $2, dek_ct = $3, mac = $4 WHERE session_id = $1 AND n = 2`,
				id, ct, dek, f.st.ChunkMAC(id, 7, 2, c[:], k[:]))
		},
		"foreign chunk": func(t *testing.T, id [16]byte) {
			r := foreign[1]
			su(t, `UPDATE exec.recording_chunk SET ct = $2, dek_ct = $3, mac = $4 WHERE session_id = $1 AND n = 1`,
				id, r[1], r[2], r[3])
		},
		"foreign chunk, MAC forged": func(t *testing.T, id [16]byte) {
			r := foreign[1]
			c, k := sha256.Sum256(r[1].([]byte)), sha256.Sum256(r[2].([]byte))
			su(t, `UPDATE exec.recording_chunk SET ct = $2, dek_ct = $3, mac = $4 WHERE session_id = $1 AND n = 1`,
				id, r[1], r[2], f.st.ChunkMAC(id, 7, 1, c[:], k[:]))
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			id := f.session(t, 7)
			f.record(t, id, 7)
			if _, err := f.st.Replay(context.Background(), id, 7); err != nil {
				t.Fatalf("before: %v", err)
			}
			before := f.alerted(recording.KindTamper)
			tamper(t, id)
			if _, err := f.st.Replay(context.Background(), id, 7); !errors.Is(err, recording.ErrTampered) {
				t.Fatalf("replay: %v", err)
			}
			if f.alerted(recording.KindTamper) != before+1 {
				t.Fatalf("alerts %v", f.alerts)
			}
		})
	}
	/* an open session has no manifest yet: refused, not tampering */
	id := f.session(t, 7)
	if _, err := f.st.Open(context.Background(), id, 7, "tester", mask); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.live[id] = true
	f.mu.Unlock()
	if _, err := f.st.Replay(context.Background(), id, 7); !errors.Is(err, recording.ErrOpen) {
		t.Fatalf("open session: %v", err)
	}
}

/* Recover finishes a recording a previous process left without its end: a marker of the loss and the manifest; a bad chunk leaves it unreplayable. */
func TestRecover(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	id := f.session(t, 7)
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Input(ctx, "configure"); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Recover(ctx, id, 7, f.now()); err != nil {
		t.Fatal(err)
	}
	r, err := f.st.Replay(ctx, id, 7)
	if err != nil || !strings.HasPrefix(r.Events[len(r.Events)-1].Data, "recording recovered after an executor restart") {
		t.Fatalf("replay %+v: %v", r, err)
	}
	if err := f.st.Recover(ctx, id, 7, f.now()); err != nil || len(f.chunks(t, id, 7)) != 3 {
		t.Fatal("a second recover changed it")
	}
	bad := f.session(t, 7)
	if _, err := f.st.Open(ctx, bad, 7, "tester", mask); err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, f.env, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ($1, 7, 1, 'x', 'x', $2)`,
		bad, make([]byte, 32))
	if err := f.st.Recover(ctx, bad, 7, f.now()); err != nil || f.alerted(recording.KindTamper) != 1 {
		t.Fatalf("recover: %v, alerts %v", err, f.alerts)
	}
	if _, err := f.st.Replay(ctx, bad, 7); !errors.Is(err, recording.ErrTampered) {
		t.Fatalf("replay: %v", err)
	}
}

type who struct {
	id         int64
	name, totp string
}

/* user is a panel user with a change TOTP and the given grants (kind, or write:<group>). */
func (f *fx) user(t *testing.T, grants ...string) who {
	t.Helper()
	name := fmt.Sprintf("rec-%d", time.Now().UnixNano()%1e9)
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

/* read is web's authorized read: authz with the read's own Need (ticket, code), then Run. */
func (f *fx) read(t *testing.T, u who, path, code string, params any) (any, error) {
	t.Helper()
	rd := f.st.Reads()[path]
	tok, _, err := ticket.Issue(ticketKey, u.id, u.name, f.now())
	if err != nil {
		t.Fatal(err)
	}
	by, err := f.az.Authorize(context.Background(), authz.Request{Ticket: tok, Code: code, Need: rd.Need, Action: rd.Action, Object: path})
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(params)
	return rd.Run(context.Background(), by, b)
}

func (f *fx) code(t *testing.T, u who) string {
	t.Helper()
	f.offset.Add(int64(30 * time.Second))
	c, err := totp.GenerateCodeCustom(u.totp, f.now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

/*
C2h: the list and the replay need the audit-read grant and a change TOTP
code: a user with every other grant is refused, so is one with audit-read
and no or a wrong code. Every replay is in the executor's audit with its
session and device; past recording_views_per_hour replays are refused with
one high alert.
*/
func TestC2hReplayNeedsAuditReadAndTOTP(t *testing.T) {
	f := newFx(t)
	f.policy(t, "recording_views_per_hour: 2\n")
	id := f.session(t, 7)
	f.record(t, id, 7)
	params := map[string]any{"session_id": sid(id), "device_id": 7}
	for path, rd := range f.st.Reads() {
		if rd.Need.Kind != execadmin.KindAuditRead || len(rd.Need.Groups) != 0 {
			t.Fatalf("%s needs %+v", path, rd.Need)
		}
	}
	others := f.user(t, "write:core", execadmin.KindWriteAdmin, execadmin.KindUnmask)
	for _, path := range []string{"/x/recordings", "/x/recordings/replay"} {
		if _, err := f.read(t, others, path, f.code(t, others), params); !errors.Is(err, authz.ErrDenied) {
			t.Fatalf("%s without audit-read: %v", path, err)
		}
	}
	auditor := f.user(t, execadmin.KindAuditRead)
	if _, err := f.read(t, auditor, "/x/recordings/replay", "", params); err == nil {
		t.Fatal("replay without a code")
	}
	if _, err := f.read(t, auditor, "/x/recordings/replay", "000000", params); err == nil {
		t.Fatal("replay with a wrong code")
	}
	f.az.ResetUser(auditor.id)
	res, err := f.read(t, auditor, "/x/recordings", f.code(t, auditor), map[string]any{"device_id": 7})
	if items, _ := res.([]recording.Item); err != nil || len(items) != 1 || items[0].State != "complete" || items[0].Session != sid(id) {
		t.Fatalf("list: %v %+v", err, res)
	}
	res, err = f.read(t, auditor, "/x/recordings/replay", f.code(t, auditor), params)
	if r, _ := res.(recording.Replay); err != nil || len(r.Events) == 0 {
		t.Fatalf("replay: %v", err)
	}
	var views int
	if err := f.env.Pool("postgres").QueryRow(context.Background(), `SELECT count(*) FROM exec.audit_event
		WHERE action = 'recording.view' AND object = $1 AND result = 'ok'`,
		"session:"+sid(id)).Scan(&views); err != nil || views != 1 {
		t.Fatalf("audited views %d: %v", views, err)
	}
	for i := range 3 {
		_, err := f.read(t, auditor, "/x/recordings/replay", f.code(t, auditor), params)
		if want := i < 1; (err == nil) != want || !want && !errors.Is(err, recording.ErrViewLimit) {
			t.Fatalf("replay %d: %v", i+2, err)
		}
	}
	if f.alerted(recording.KindViews) != 1 {
		t.Fatalf("alerts %v", f.alerts)
	}
}

/*
Fuzz of the masker's boundary: device output with secrets, split anywhere
into pieces (as the device's answers come), is never buffered with a secret.
*/
func FuzzOutputBoundary(f *testing.F) {
	f.Add(uint16(30), uint16(200), uint16(7))
	f.Add(uint16(0), uint16(1), uint16(400))
	f.Fuzz(func(t *testing.T, a, b, c uint16) {
		cuts := []int{int(a) % (len(secretText) + 1), int(b) % (len(secretText) + 1), int(c) % (len(secretText) + 1)}
		slices.Sort(cuts)
		pieces := []string{secretText[:cuts[0]], secretText[cuts[0]:cuts[1]], secretText[cuts[1]:cuts[2]], secretText[cuts[2]:]}
		if w := leak([]byte(recording.Outputs(terminal.Clean, mask, pieces...))); w != "" {
			t.Fatalf("cuts %v: %s", cuts, w)
		}
	})
}
