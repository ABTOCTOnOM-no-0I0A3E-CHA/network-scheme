package session

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/*
Service sessions of a changeset's run (Phase 5, task 5.5): one session per
device, opened by the run of an approved changeset for its author, without a
bearer token or a terminal. A device opens exactly as in a change session
(openDevice: lease, device_busy, the pre-session snapshot in
exec.session_device, the recording, the Write connection, the policy's
rules, the management context, the driver session), so the rollback, the
recording, Recover and execpub.session_summary are the sessions' own. The
changeset package decides what is sent; every line still goes through the
session's own Classify (Safe only, and exactly the line the dry-run
planned) and is recorded before it is sent.
*/

/* ErrNotPlanned refuses a line of a run that is not Safe in the session, or not the line the dry-run planned. */
const ErrNotPlanned Refusal = "line_not_planned"

/* RunDevice is what a run needs to know of its device: the registry's address, group and line, the pre-session hash. */
type RunDevice struct {
	ID                   int64
	Address, Group, Line string
	Pre                  [32]byte
	Session              [16]byte
}

/* RunOpen opens a service session of user on device for a run (see above); the caller ends it with RunEnd. */
func (m *Manager) RunOpen(ctx context.Context, user int64, username string, device int64) (*Session, RunDevice, error) {
	pol := m.cfg.Policy()
	if !pol.Enabled() {
		return nil, RunDevice{}, authz.ErrDisabled
	}
	if frozen, _ := m.cfg.Gate.Frozen(); frozen {
		return nil, RunDevice{}, authz.ErrFrozen
	}
	s := &Session{User: user, Username: username, Opened: m.cfg.Now().UTC().Truncate(time.Microsecond)}
	if _, err := randID(s); err != nil {
		return nil, RunDevice{}, err
	}
	if err := m.insertSession(ctx, s, pol); err != nil {
		return nil, RunDevice{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	m.mu.Lock()
	m.runs[s.ID] = s
	m.mu.Unlock()
	d, err := m.openDevice(ctx, s, device, pol.Policy)
	if d != nil {
		s.Devices = append(s.Devices, d)
	}
	if err == nil {
		err = m.cfg.Pub.SessionOpened(ctx, s.ID, s.User, d.ID, s.Opened)
		if err == nil {
			d.summary = true
		}
	}
	if err != nil {
		m.RunEnd(ctx, s, "aborted")
		return nil, RunDevice{}, deviceRefusal(err)
	}
	m.event(ctx, s.ID, "run", map[string]any{"device_id": device})
	return s, RunDevice{ID: d.ID, Address: d.Address, Group: d.Group, Line: string(d.Line), Pre: d.Pre, Session: s.ID}, nil
}

/* randID gives s a random UUID v4. */
func randID(s *Session) ([16]byte, error) {
	tok, err := newToken()
	if err != nil {
		return s.ID, err
	}
	b, _ := hex.DecodeString(tok[:32])
	copy(s.ID[:], b)
	s.ID[6], s.ID[8] = s.ID[6]&0x0f|0x40, s.ID[8]&0x3f|0x80
	return s.ID, nil
}

/* RunSend sends line on the run's device when the session classifies it Safe as exactly want (the planned, normalized line). */
func (m *Manager) RunSend(ctx context.Context, s *Session, line, want string) error {
	ctx, cancel := context.WithTimeout(ctx, actionTime)
	defer cancel()
	d := s.Devices[0]
	if err := m.allowed(ctx, d.ID); err != nil {
		return err
	}
	v := d.Session.Classify(line)
	if v.Class != core.Safe || v.Line != want {
		m.cfg.Log.Info("session: a run's line is not the planned one", "device_id", d.ID, "class", v.Class.String(), "reason", string(v.Reason),
			"same_line", v.Line == want)
		return ErrNotPlanned
	}
	_, err := recorded{Session: d.Session, m: m, s: s, d: d}.Send(ctx, v)
	return err
}

/* RunHealth is the health check: the session reads the running configuration and a new connection logs in. */
func (m *Manager) RunHealth(ctx context.Context, s *Session) error {
	ctx, cancel := context.WithTimeout(ctx, actionTime)
	defer cancel()
	d := s.Devices[0]
	if _, err := d.Session.Snapshot(ctx); err != nil {
		return ErrHealth
	}
	if err := m.login(ctx, d.ID); err != nil {
		return ErrHealth
	}
	return nil
}

/* RunCommit commits an ESR device's candidate with the policy's confirm timer, then the health check (a failure restores the commit). */
func (m *Manager) RunCommit(ctx context.Context, s *Session) error {
	_, err := m.commit(ctx, s, s.Devices[0])
	return err
}

/* RunSave saves the run's device (MES: the startup configuration; ESR: the confirm of its pending commit), naming its running configuration now. */
func (m *Manager) RunSave(ctx context.Context, s *Session) error {
	d := s.Devices[0]
	cctx, cancel := context.WithTimeout(ctx, actionTime)
	_, cur, err := m.diff(cctx, d)
	cancel()
	if err != nil {
		return err
	}
	_, err = m.save(ctx, s, d.ID, hex.EncodeToString(cur.SHA256[:]))
	return err
}

/* RollbackRun rolls the run's device back to its pre-session snapshot (as session.rollback does for a device). */
func (m *Manager) RollbackRun(ctx context.Context, s *Session) RolledBack {
	d := s.Devices[0]
	/* a run stopped in the middle of a device's plan leaves it in a configuration mode: back to the privileged prompt first */
	if r, ok := d.Session.(rooter); ok && m.RecordMark(ctx, s, d.ID, "the run stopped: back to the privileged prompt for the rollback") == nil {
		rctx, cancel := context.WithTimeout(ctx, actionTime)
		_ = r.ToRoot(rctx)
		cancel()
	}
	to, err := m.snapshot(ctx, s.ID, d)
	if err != nil {
		r := RolledBack{ID: d.ID, Error: string(ErrSnapshotBad)}
		var rf Refusal
		if errors.As(err, &rf) {
			r.Error = string(rf)
		}
		return r
	}
	return m.rollbackDevice(ctx, s, d, to)
}

/* RunEnd ends a run's service session (closed, or aborted when it never opened): the device, its summary, device_busy and lease. */
func (m *Manager) RunEnd(ctx context.Context, s *Session, why string) {
	m.finish(ctx, s, why, nil)
	m.mu.Lock()
	delete(m.runs, s.ID)
	m.mu.Unlock()
}
