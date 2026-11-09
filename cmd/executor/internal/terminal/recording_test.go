package terminal_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/terminal"
	"github.com/beekamai/network-scheme/internal/backup/open"
)

/* streams records every device of the fixture's session on its own recording.Stream, as session.Manager does. */
type streams struct {
	mu sync.Mutex
	s  map[int64]*recording.Stream
}

func (r *streams) get(d int64) *recording.Stream {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.s[d]
}

func (r *streams) RecordInput(ctx context.Context, _ *session.Session, d int64, l string) error {
	return r.get(d).Input(ctx, l)
}

func (r *streams) RecordOutput(ctx context.Context, _ *session.Session, d int64, t string) error {
	return r.get(d).Output(ctx, t)
}

func (r *streams) RecordMark(ctx context.Context, _ *session.Session, d int64, l string) error {
	return r.get(d).Mark(ctx, l)
}

/* Known test secrets: typed and in the device's answers. */
var secrets = []string{"Secr3tUserPw1", "EnablePw77Xq", "CommStr99Zz", "RadKey55Yy", "PskAsc66Vv", "UrlPw33Uu", "PemBody88Tt"}

const secretOut = "username admin privilege 15 password Secr3tUserPw1\nenable password EnablePw77Xq\n" +
	"snmp-server community CommStr99Zz ro\nradius-server host 192.0.2.5 key RadKey55Yy\n" +
	"security ike proposal p1\n pre-shared-key ascii-text PskAsc66Vv\nboot host sftp://bob:UrlPw33Uu@192.0.2.9/cfg\n" +
	"-----BEGIN RSA PRIVATE KEY-----\nPemBody88Tt\n-----END RSA PRIVATE KEY-----"

func leak(b []byte) string {
	for _, s := range secrets {
		for _, f := range []string{s, base64.StdEncoding.EncodeToString([]byte(s)), base64.RawStdEncoding.EncodeToString([]byte(s)),
			base64.RawURLEncoding.EncodeToString([]byte(s)), hex.EncodeToString([]byte(s)), strings.ToUpper(hex.EncodeToString([]byte(s)))} {
			if bytes.Contains(b, []byte(f)) {
				return s
			}
		}
	}
	return ""
}

/*
C8 end to end: lines typed through /x/ws (safe ones, and dangerous ones with
secrets confirmed by name and a new code) and the device's answers with
secrets are recorded; the replay equals the emulator's journal (what the
device got) and the answers the browser was shown, but for the masks, and
no known test secret is in any stored chunk (decrypted or not), as is, in
base64 or in hex, nor in the executor's audit or the alerts.
*/
func TestC8ReplayIsTheFactWithoutSecrets(t *testing.T) {
	t.Cleanup(terminal.Unlimited())
	rs := &streams{s: map[int64]*recording.Stream{}}
	f := newFxWith(t, rs)
	ctx := context.Background()
	keys, err := seal.Derive(&[32]byte{6})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st, err := recording.New(recording.Config{Pool: f.env.Pool("nms_executor"), MAC: keys.MAC(), Pub: pub, Priv: priv, Clean: terminal.Clean,
		Policy: f.pol.Current, Live: func([16]byte) bool { return false }, Audit: f.az.Record,
		Alert: func(context.Context, string, string, int64, string) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	sid := f.ss.s.ID
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES ($1, $2, now(), '{}', $3)`,
		sid, f.u.id, make([]byte, 32))
	for _, l := range lines {
		attacktest.Tamper(t, f.env, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
			VALUES ($1, $2, $3, 'x', 'x', $3)`, sid, l.id, make([]byte, 32))
		if rs.s[l.id], err = st.Open(ctx, sid, l.id, f.u.name, l.d.MaskSecrets); err != nil {
			t.Fatal(err)
		}
	}
	confirmed := 0
	for _, l := range lines {
		f.az.ResetUser(f.u.id)
		tm := f.terms[l.id]
		before := len(tm.Lines())
		tm.D.BeforeReply(func(line string) (string, time.Duration) {
			if line == "show clock" {
				return secretOut + "\n", 0
			}
			return "", 0
		})
		c := f.dial(t, l.id)
		var shown []string
		collect := func(res []map[string]any) {
			for _, m := range res {
				if m["type"] == "output" && m["text"] != "" {
					shown = append(shown, m["text"].(string)+"\n")
				}
			}
		}
		collect(c.do("keys", "show clock\r"))
		collect(c.do("keys", l.cfg+"\r"))
		for _, typed := range []string{"username admin password Secr3tUserPw1", "snmp-server community CommStr99Zz ro",
			"radius-server host 192.0.2.5 key RadKey55Yy"} {
			res := c.do("keys", typed+"\r")
			if len(res) != 1 || res[0]["type"] != "dangerous" {
				collect(res) /* refused or sent as is: whatever the device got is compared below */
				continue
			}
			res = f.confirm(t, c, f.issue(t, c), f.names[l.id], f.newCode(t))
			if !slices.ContainsFunc(res, func(m map[string]any) bool { return m["type"] == "output" }) {
				t.Fatalf("%s: %q not sent after its confirmation: %v", l.name, typed, res)
			}
			confirmed++
			collect(res)
		}
		collect(c.do("keys", "end\r"))
		if err := rs.get(l.id).Close(ctx, "session ended: closed"); err != nil {
			t.Fatal(err)
		}
		r, err := st.Replay(ctx, sid, l.id)
		if err != nil {
			t.Fatalf("%s: replay: %v", l.name, err)
		}
		var in, out []string
		marks := 0
		for _, e := range r.Events {
			switch e.Code {
			case "i":
				in = append(in, strings.TrimSuffix(e.Data, "\n"))
			case "o":
				out = append(out, e.Data)
			default:
				marks++
			}
		}
		var got []string
		for _, x := range tm.Lines()[before:] {
			got = append(got, l.d.MaskSecrets(x))
		}
		if !slices.Equal(in, got) {
			t.Fatalf("%s: recorded input %q, the device got (masked) %q", l.name, in, got)
		}
		if !slices.Equal(out, shown) || len(out) == 0 {
			t.Fatalf("%s: recorded output %q, shown %q", l.name, out, shown)
		}
		if !strings.Contains(strings.Join(out, ""), "sftp://***@192.0.2.9") {
			t.Fatalf("%s: the secrets' output is not recorded: %q", l.name, out)
		}
		rows, err := f.env.Pool("postgres").Query(ctx, `SELECT n, ct, dek_ct FROM exec.recording_chunk WHERE session_id = $1 AND device_id = $2 ORDER BY n`, sid, l.id)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			var ct, dek []byte
			if err := rows.Scan(&n, &ct, &dek); err != nil {
				t.Fatal(err)
			}
			pt, err := open.Open(priv, pub, ct, dek, recording.AAD(sid, l.id, n))
			if err != nil || leak(ct) != "" || leak(dek) != "" || leak(pt) != "" {
				t.Fatalf("%s: chunk %d: %v %q", l.name, n, err, leak(pt))
			}
		}
		rows.Close()
		if n < 5 {
			t.Fatalf("%s: %d chunks", l.name, n)
		}
	}
	if confirmed == 0 {
		t.Fatal("no dangerous line with a secret was confirmed and sent")
	}
	var audit, alerts []byte
	if err := f.env.Pool("postgres").QueryRow(ctx, `SELECT coalesce(string_agg(payload, ''), '') FROM exec.audit_event`).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if err := f.env.Pool("postgres").QueryRow(ctx, `SELECT coalesce(string_agg(text, ''), '') FROM execpub.alert`).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if w := leak(audit) + leak(alerts); w != "" {
		t.Fatalf("audit or alerts hold %s", w)
	}
}

/* A recorder that fails refuses the line: the device gets nothing, and every following line is refused too (fail closed). */
func TestRecorderFailureSendsNothing(t *testing.T) {
	f := newFx(t)
	f.rec.fail = recording.ErrFailed
	for _, l := range lines {
		c := f.dial(t, l.id)
		before := f.typed(l.id)
		for range 2 {
			res := c.do("keys", "show clock\r")
			if len(res) != 1 || res[0]["type"] != "refused" || res[0]["code"] != "recording_failed" {
				t.Fatalf("%s: %v", l.name, res)
			}
		}
		if f.typed(l.id) != before {
			t.Fatalf("%s: the device got %d lines", l.name, f.typed(l.id)-before)
		}
	}
	f.rec.fail = recording.ErrFull
	c := f.dial(t, lines[0].id)
	if res := c.do("keys", "show clock\r"); res[0]["code"] != "recording_full" || !errors.Is(f.rec.fail, recording.ErrFull) {
		t.Fatalf("full: %v", res)
	}
}
