package recording_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/internal/backup/open"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* replayed returns the events of a recording by code. */
func (f *fx) replayed(t *testing.T, id [16]byte, device int64) (in, out, marks []string) {
	t.Helper()
	r, err := f.st.Replay(context.Background(), id, device)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Events {
		switch e.Code {
		case "i":
			in = append(in, e.Data)
		case "o":
			out = append(out, e.Data)
		default:
			marks = append(marks, e.Data)
		}
	}
	return in, out, marks
}

/* stored is the plaintext of every chunk of a recording. */
func (f *fx) stored(t *testing.T, id [16]byte, device int64) []byte {
	t.Helper()
	var all []byte
	for _, r := range f.chunks(t, id, device) {
		pt, err := open.Open(f.priv, f.pub, r[1].([]byte), r[2].([]byte), recording.AAD(id, device, r[0].(int)))
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, pt...)
	}
	return all
}

/*
I1: an opener the device did not take hides nothing: after a rejected
"crypto ... import" line (input side) and an unclosed "-----BEGIN" line
(output side), every ordinary line is recorded as itself (masked only where
it carries a secret).
*/
func TestOpenerHidesNoLaterLine(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	id := f.session(t, 7)
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []func() error{
		func() error { return s.Input(ctx, "crypto certificate 1 import bogus") },
		func() error { return s.Output(ctx, "% Unrecognized command\n") },
		func() error { return s.Input(ctx, "hostname pwned") },
		func() error { return s.Input(ctx, "shutdown") },
		func() error { return s.Input(ctx, "username evil password x privilege 15") },
		func() error { return s.Output(ctx, "-----BEGIN junk\n") },
		func() error { return s.Output(ctx, "interface gi1/0/1 is up\n") },
		func() error { return s.Input(ctx, "show interfaces") },
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(ctx, "end"); err != nil {
		t.Fatal(err)
	}
	in, out, _ := f.replayed(t, id, 7)
	if !slices.Contains(in, "hostname pwned\n") || !slices.Contains(in, "shutdown\n") || !slices.Contains(in, "show interfaces\n") ||
		!slices.Contains(in, mask("username evil password x privilege 15")+"\n") || !strings.HasPrefix(in[3], "username evil ") {
		t.Fatalf("input %q", in)
	}
	if !slices.Contains(out, "interface gi1/0/1 is up\n") || !slices.Contains(out, "% Unrecognized command\n") {
		t.Fatalf("output %q", out)
	}
}

/*
I2: JSON without HTML escaping (an answer of '<' stores as about its size),
one answer is cut at maxAnswer with a marker, and the worst a device can
send (escapes, invalid UTF-8, a 10 MiB answer) keeps a recording within
replayBound of its limit, which the replay reads; the bound of the largest
limit the policy allows is what a replay accepts.
*/
func TestAnswerBoundAndEscaping(t *testing.T) {
	t.Cleanup(recording.SetMaxAnswer(64 << 10))
	f := newFx(t)
	f.policy(t, "recording_max_mib: 1\n")
	ctx := context.Background()
	id := f.session(t, 7)
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	lt := strings.Repeat(strings.Repeat("< ", 49)+"<\n", 500) /* 50 000 bytes of words, under the answer bound */
	if err := s.Input(ctx, "show a"); err != nil {
		t.Fatal(err)
	}
	if err := s.Output(ctx, lt); err != nil {
		t.Fatal(err)
	}
	if err := s.Mark(ctx, "stored"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.stored(t, id, 7)); n > len(lt)*11/10+4096 {
		t.Fatalf("an answer of %d bytes of '<' stored as %d", len(lt), n)
	}
	worst := strings.Repeat(strings.Repeat("\"\xff\\", 30)+"\n", 10<<20/91)
	for range 3 { /* fill to the limit, then one more line and its answer */
		if err := s.Input(ctx, "show b"); err != nil && !errors.Is(err, recording.ErrFull) {
			t.Fatal(err)
		}
		if err := s.Output(ctx, worst); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(ctx, "end"); err != nil {
		t.Fatal(err)
	}
	if n := len(f.stored(t, id, 7)); n > recording.ReplayBound(1) {
		t.Fatalf("%d bytes stored, bound %d", n, recording.ReplayBound(1))
	}
	_, out, marks := f.replayed(t, id, 7)
	for _, o := range out {
		if len(o) > 64<<10 {
			t.Fatalf("an answer of %d bytes recorded", len(o))
		}
	}
	if !slices.ContainsFunc(marks, func(m string) bool { return strings.HasPrefix(m, "the device's answer is cut here in the recording") }) {
		t.Fatalf("marks %q", marks)
	}
	if recording.ReplayBound(execpolicy.MaxRecordingMiB) < execpolicy.MaxRecordingMiB<<20+2*(64<<10) {
		t.Fatal("the replay bound is below the largest recording")
	}
}

/* m1: a line whose store fails is never recorded as sent, also when the end later stores what remains. */
func TestFailedLineIsNotRecorded(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	id := f.session(t, 7)
	s, err := f.st.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, f.env, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ($1, 7, 1, 'x', 'x', $2)`,
		id, make([]byte, 32))
	if err := s.Input(ctx, "configure"); !errors.Is(err, recording.ErrFailed) {
		t.Fatalf("input: %v", err)
	}
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.recording_chunk DISABLE TRIGGER recording_chunk_append_only`)
	attacktest.Tamper(t, f.env, `DELETE FROM exec.recording_chunk WHERE session_id = $1 AND n = 1`, id)
	attacktest.Tamper(t, f.env, `ALTER TABLE exec.recording_chunk ENABLE TRIGGER recording_chunk_append_only`)
	if err := s.Close(ctx, "end"); err != nil {
		t.Fatal(err)
	}
	if in, _, _ := f.replayed(t, id, 7); len(in) != 0 {
		t.Fatalf("recorded as sent: %q", in)
	}
}

/* m4: the replay cleans every event again: a chunk with escapes (a key holder's, or an older executor's) reaches the browser without them. */
func TestReplayCleansAgain(t *testing.T) {
	f := newFx(t)
	raw, err := recording.New(recording.Config{Pool: f.env.Pool("nms_executor"), MAC: f.mac, Pub: f.pub, Priv: f.priv,
		Clean: func(s string) string { return s }, Policy: f.pol.Current, Live: func([16]byte) bool { return false },
		Alert: func(context.Context, string, string, int64, string) error { return nil }, Audit: f.az.Record})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id := f.session(t, 7)
	s, err := raw.Open(ctx, id, 7, "tester", mask)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Input(ctx, "show clock"); err != nil {
		t.Fatal(err)
	}
	if err := s.Output(ctx, "a\x1b]52;c;ZXZpbA==\x07b\x1b[31mc\n"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(ctx, "end"); err != nil {
		t.Fatal(err)
	}
	_, out, _ := f.replayed(t, id, 7)
	if len(out) != 1 || strings.ContainsAny(out[0], "\x1b\x07") {
		t.Fatalf("output %q", out)
	}
}

/* m5: at most maxReplays replays at once: one more is refused (503 replays_busy) and audited. */
func TestConcurrentReplaysBounded(t *testing.T) {
	f := newFx(t)
	id := f.session(t, 7)
	f.record(t, id, 7)
	auditor := f.user(t, "audit-read")
	release := f.st.Busy()
	_, err := f.read(t, auditor, "/x/recordings/replay", f.code(t, auditor), map[string]any{"session_id": sid(id), "device_id": 7})
	release()
	var st interface{ HTTPStatus() int }
	if !errors.Is(err, recording.ErrBusy) || !errors.As(err, &st) || st.HTTPStatus() != 503 {
		t.Fatalf("busy: %v", err)
	}
	if _, err := f.read(t, auditor, "/x/recordings/replay", f.code(t, auditor), map[string]any{"session_id": sid(id), "device_id": 7}); err != nil {
		t.Fatalf("after: %v", err)
	}
}
