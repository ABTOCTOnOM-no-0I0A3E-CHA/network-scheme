package session_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
)

/* recordLines sends lines as the terminal does: recorded first (RecordInput), then sent, then the answer recorded. */
func (f *fx) recordLines(t *testing.T, o session.Opened, lines ...string) {
	t.Helper()
	if err := f.m.Use(o.ID, o.Token, func(s *session.Session) error {
		d := s.Devices[0]
		for _, l := range lines {
			v := d.Session.Classify(l)
			if v.Class != core.Safe {
				return fmt.Errorf("%q is %s", l, v.Class)
			}
			if err := f.m.RecordInput(ctx(t), s, d.ID, d.Driver.MaskSecrets(v.Line)); err != nil {
				return err
			}
			out, err := d.Session.Send(ctx(t), v)
			if err != nil {
				return err
			}
			if len(out.Lines) > 0 {
				if err := f.m.RecordOutput(ctx(t), s, d.ID, strings.Join(out.Lines, "\n")+"\n"); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

/*
A session's device is recorded from its open to its end: the opened marker,
the lines, diff, save and a form (its marker and each of its lines) and the
end; the manifest is written when the session closes and the replay
verifies (while the session is open: recording_open).
*/
func TestSessionIsRecorded(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	o := f.open(t, u)
	act := func(op, params string) (any, error) {
		return f.m.Act(ctx(t), o.ID, o.Token, op, json.RawMessage(params))
	}
	f.recordLines(t, o, "configure", "hostname edge-9", "end")
	res, err := act("diff", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	sum := res.([]session.DeviceDiff)[0].SHA256
	if _, err := act("save", `{"device_id":`+fmt.Sprint(f.id)+`,"sha256":"`+sum+`"}`); err != nil {
		t.Fatal(err)
	}
	form := `"form":{"kind":"interface-description","interface":"gi1/0/2","description":"nms-rec"}`
	res, err = act("form", `{"device_id":`+fmt.Sprint(f.id)+`,`+form+`}`)
	if err != nil {
		t.Fatal(err)
	}
	shown := res.(session.FormLines).Lines
	b, _ := json.Marshal(shown)
	if _, err := act("form-apply", `{"device_id":`+fmt.Sprint(f.id)+`,`+form+`,"lines":`+string(b)+`}`); err != nil {
		t.Fatal(err)
	}
	sid, _ := session.ParseID(o.ID)
	if _, err := f.rec.Replay(ctx(t), sid, f.id); !errors.Is(err, recording.ErrOpen) {
		t.Fatalf("replay of an open session: %v", err)
	}
	if err := f.m.Close(ctx(t), o.ID, o.Token); err != nil {
		t.Fatal(err)
	}
	r, err := f.rec.Replay(ctx(t), sid, f.id)
	if err != nil {
		t.Fatal(err)
	}
	var in, marks []string
	for _, e := range r.Events {
		switch e.Code {
		case "i":
			in = append(in, strings.TrimSuffix(e.Data, "\n"))
		case "m":
			marks = append(marks, e.Data)
		}
	}
	if want := append([]string{"configure", "hostname edge-9", "end"}, shown...); !slices.Equal(in, want) {
		t.Fatalf("input %q, want %q", in, want)
	}
	/* m8: the form's way back to the privileged prompt is marked before its lines */
	if len(marks) != 6 || !strings.HasPrefix(marks[0], "session opened by "+u.name) || marks[1] != "diff" ||
		marks[2] != "save (startup configuration)" || !strings.HasPrefix(marks[3], "form interface-description") ||
		!strings.HasPrefix(marks[4], "the executor returns to the privileged prompt") || marks[5] != "session ended: closed" {
		t.Fatalf("marks %q", marks)
	}
}

/*
A form whose recording fails is refused before its first line (its marker),
and a form on a full recording (markers still recorded) has its first line
refused: either way the device gets nothing.
*/
func TestFormRefusedWhenTheRecordingFails(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	f.policy(t, "recording_max_mib: 1\n")
	full := f.open(t, u)
	if err := f.m.Use(full.ID, full.Token, func(s *session.Session) error {
		return f.m.RecordOutput(ctx(t), s, f.id, strings.Repeat("z\n", 1<<19))
	}); err != nil {
		t.Fatal(err)
	}
	fform := `"form":{"kind":"interface-description","interface":"gi1/0/2","description":"nms-rec"}`
	fres, err := f.m.Act(ctx(t), full.ID, full.Token, "form", json.RawMessage(`{"device_id":`+fmt.Sprint(f.id)+`,`+fform+`}`))
	if err != nil {
		t.Fatal(err)
	}
	fb, _ := json.Marshal(fres.(session.FormLines).Lines)
	flines := len(f.d.Lines())
	if _, err := f.m.Act(ctx(t), full.ID, full.Token, "form-apply", json.RawMessage(`{"device_id":`+fmt.Sprint(f.id)+`,`+fform+`,"lines":`+string(fb)+`}`)); !errors.Is(err, recording.ErrFull) {
		t.Fatalf("form-apply on a full recording: %v", err)
	}
	if got := f.d.Lines()[flines:]; slices.ContainsFunc(got, func(l string) bool { return l != "show running-config" }) {
		t.Fatalf("the device got %q", got)
	}
	if err := f.m.Close(ctx(t), full.ID, full.Token); err != nil {
		t.Fatal(err)
	}
	f.policy(t, "")
	o := f.open(t, u)
	var next int
	if err := f.env.Pool("postgres").QueryRow(ctx(t), `SELECT count(*) FROM exec.recording_chunk WHERE session_id = $1::uuid AND device_id = $2`, o.ID, f.id).Scan(&next); err != nil {
		t.Fatal(err)
	}
	attacktest.Tamper(t, f.env, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac) VALUES ($1::uuid, $2, $3, 'x', 'x', $4)`,
		o.ID, f.id, next, make([]byte, 32))
	form := `"form":{"kind":"interface-description","interface":"gi1/0/2","description":"nms-rec"}`
	res, err := f.m.Act(ctx(t), o.ID, o.Token, "form", json.RawMessage(`{"device_id":`+fmt.Sprint(f.id)+`,`+form+`}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res.(session.FormLines).Lines)
	lines := len(f.d.Lines())
	if _, err := f.m.Act(ctx(t), o.ID, o.Token, "form-apply", json.RawMessage(`{"device_id":`+fmt.Sprint(f.id)+`,`+form+`,"lines":`+string(b)+`}`)); !errors.Is(err, recording.ErrFailed) {
		t.Fatalf("form-apply: %v", err)
	}
	if got := f.d.Lines()[lines:]; len(got) != 0 {
		t.Fatalf("the device got %q", got)
	}
	if f.alerts(t, recording.KindFailed) == 0 {
		t.Fatal("no alert")
	}
}

/*
m2: a device whose open fails after its session_device row (here its Write
connection) still has a complete recording: replayed with its abort, no
tamper alert.
*/
func TestAbortedOpenLeavesAReplayableRecording(t *testing.T) {
	f := newFx(t)
	u := f.user(t, "core")
	f.dialsOK.Store(1) /* the pre-session snapshot connects, the Write connection does not */
	if _, err := f.m.Open(ctx(t), f.req(t, u), []int64{f.id}); err == nil {
		t.Fatal("opened without its Write connection")
	}
	var sid [16]byte
	if err := f.env.Pool("postgres").QueryRow(ctx(t), `SELECT session_id FROM exec.session_device WHERE device_id = $1`, f.id).Scan(&sid); err != nil {
		t.Fatal(err)
	}
	r, err := f.rec.Replay(ctx(t), sid, f.id)
	if err != nil || r.Events[len(r.Events)-1].Data != "session ended: aborted" {
		t.Fatalf("replay %+v: %v", r, err)
	}
	if n := f.alerts(t, recording.KindTamper); n != 0 {
		t.Fatalf("%d tamper alerts", n)
	}
}
