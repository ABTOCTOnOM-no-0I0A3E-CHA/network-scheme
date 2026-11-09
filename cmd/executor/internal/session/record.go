package session

import (
	"context"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/recording"
	"github.com/beekamai/network-scheme/cmd/executor/internal/transport"
)

/*
The session's recording (Task 4c.5): every device of a session has its
recording.Stream from its open (after its exec.session_device row) to its
end (the manifest). The terminal records through RecordInput, RecordOutput
and RecordMark (terminal.Recorder); the actions mark diff, save, commit,
form and rollback, and a form's lines are recorded as the terminal's are.
A device without a recording refuses every line (fail closed).
*/

/* Recordings is what a session needs of recording.Store. */
type Recordings interface {
	Open(ctx context.Context, session [16]byte, device int64, username string, mask func(string) string) (*recording.Stream, error)
	Recover(ctx context.Context, session [16]byte, device int64, opened time.Time) error
}

func (s *Session) rec(device int64) *recording.Stream {
	if d := s.Device(device); d != nil {
		return d.rec
	}
	return nil
}

/* RecordInput records a line before it is sent to device (terminal.Recorder): an error means it must not be sent. */
func (m *Manager) RecordInput(ctx context.Context, s *Session, device int64, line string) error {
	r := s.rec(device)
	if r == nil {
		return recording.ErrFailed
	}
	return r.Input(ctx, line)
}

/* RecordOutput records the device's answer (terminal.Recorder). */
func (m *Manager) RecordOutput(ctx context.Context, s *Session, device int64, text string) error {
	r := s.rec(device)
	if r == nil {
		return recording.ErrFailed
	}
	return r.Output(ctx, text)
}

/* RecordMark records a marker of the executor on device (terminal.Recorder). */
func (m *Manager) RecordMark(ctx context.Context, s *Session, device int64, label string) error {
	r := s.rec(device)
	if r == nil {
		return recording.ErrFailed
	}
	return r.Mark(ctx, label)
}

/* Live reports whether session id is open in this process (its recordings have no manifest yet). */
func (m *Manager) Live(id [16]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id] != nil
}

/*
recorded is a driver session whose Send records the line first (refused
when it cannot be) and the answer after: what a form sends goes through it.
*/
type recorded struct {
	drivers.Session
	m *Manager
	s *Session
	d *Device
}

func (r recorded) Send(ctx context.Context, v core.Verdict) (transport.Output, error) {
	if err := r.m.RecordInput(ctx, r.s, r.d.ID, r.d.Driver.MaskSecrets(v.Line)); err != nil {
		return transport.Output{}, err
	}
	out, err := r.Session.Send(ctx, v)
	if text := append(append([]string(nil), out.Async...), out.Lines...); len(text) > 0 {
		if rerr := r.m.RecordOutput(ctx, r.s, r.d.ID, strings.Join(text, "\n")+"\n"); rerr != nil && err == nil {
			err = rerr
		}
	}
	return out, err
}

/* ToRoot is the driver session's (forms.Apply needs the privileged prompt). */
func (r recorded) ToRoot(ctx context.Context) error {
	if rr, ok := r.Session.(rooter); ok {
		return rr.ToRoot(ctx)
	}
	return ErrNotApplicable
}
