package changeset

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

/*
The run of an approved changeset (task 5.5, security.md 5.4 D6, D8). Every
device is a service session of package session (RunOpen: lease,
device_busy, the pre-session snapshot, the recording, the Write connection,
the management context, the driver session), so a device's rollback,
recording and summary are a session's. The order: the canary
(Devices[0]), settle_s, the health check, then batches of batch_size
devices in parallel; on MES every device is saved at the end of the whole
changeset, ESR commits with the policy's timer, checks health and confirms
on each device (D8).

Per device: drift first (its pre-session hash must be the dry-run's
pre_sha256, its registry address, group and line the plan's), then every
line of its plan exactly as planned (the session's Classify: Safe and the
same normalized line), then the health check. The first error, a drift,
a failed health check or "stop" stops the run: no further line is sent,
and every device that got at least one line is rolled back with its line's
Phase 4 strategy (D6); the outcome is rolled_back or rollback_failed (high
alert). A restart in the middle leaves the run interrupted (Recover: high
alert, no automatic rollback: the driver sessions are gone).
*/

/* Runner is the service sessions of a run: *session.Manager. */
type Runner interface {
	RunOpen(ctx context.Context, user int64, username string, device int64) (*session.Session, session.RunDevice, error)
	RunSend(ctx context.Context, s *session.Session, line, want string) error
	RunHealth(ctx context.Context, s *session.Session) error
	RunSnapshot(ctx context.Context, s *session.Session) ([32]byte, error)
	RunCommit(ctx context.Context, s *session.Session) error
	RunSave(ctx context.Context, s *session.Session) error
	RollbackRun(ctx context.Context, s *session.Session) session.RolledBack
	RunEnd(ctx context.Context, s *session.Session, why string)
}

/* Alert kinds of runs (internal/triggers, high). */
const (
	KindFailed         = "changeset_failed"
	KindRollbackFailed = "changeset_rollback_failed"
	KindInterrupted    = "changeset_interrupted"
)

/* Bounds and pace of a run (variables for the tests). */
var (
	runTime = 4 * time.Hour
	/* settle waits settle_s after the canary (the tests replace it) */
	settle = func(ctx context.Context, d time.Duration) {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
)

/* Device states of a run. */
const (
	devPending    = "pending"
	devOpened     = "opened"
	devApplied    = "applied"
	devFailed     = "failed"
	devRolledBack = "rolled_back"
	devRBFailed   = "rollback_failed"
	devSaved      = "saved"
	devSkipped    = "not_started"
)

/* runDevice is one device of a run. */
type runDevice struct {
	plan  PlanDevice
	ver   *backups.Version /* restore: the version, opened and checked at the start */
	lines []Rendered
	want  []string
	s     *session.Session
	sent  int
	state string
	err   string
}

/* run is a changeset's run in this process. */
type run struct {
	st      Started
	name    string
	mu      sync.Mutex
	devs    []*runDevice
	stop    bool
	reason  string
	failed  int64
	phase   string
	result  string
	stopped int64 /* the user who stopped it */
	done    chan struct{}
}

func (r *run) halted() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stop
}

func (r *run) set(d *runDevice, state, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d.state = state
	if why != "" {
		d.err = why
	}
}

/* startRun is Config.Start with a Runner: the run goes on in the background, its progress in memory and in the events. */
func (m *Manager) startRun(ctx context.Context, st Started) error {
	r := &run{st: st, name: st.AuthorName, phase: "starting", done: make(chan struct{})}
	for _, p := range st.Plan {
		r.devs = append(r.devs, &runDevice{plan: p, state: devPending})
	}
	m.mu.Lock()
	if old := m.runs[st.ID]; old != nil && old.result == "" {
		m.mu.Unlock()
		return refuse("running")
	}
	m.runs[st.ID] = r
	m.mu.Unlock()
	go func() {
		defer close(r.done)
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runTime)
		defer cancel()
		m.execute(rctx, r)
	}()
	return nil
}

/* event records a run event (a failure is logged: the run goes on, its outcome is in the terminal event). */
func (m *Manager) runEvent(ctx context.Context, r *run, kind string, device int64, sid *[16]byte, payload map[string]any) {
	if _, err := m.cfg.Store.Event(ctx, r.st.ID, r.st.Rev, kind, device, sid, payload); err != nil {
		m.cfg.Log.Error("changeset: run event not recorded", slog.String("changeset", IDString(r.st.ID)), slog.String("kind", kind),
			slog.String("err", err.Error()))
	}
}

func (m *Manager) runAlert(ctx context.Context, kind string, device int64, text string) {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
	defer cancel()
	if err := m.cfg.Pub.Alert(actx, kind, "high", device, text); err != nil {
		m.cfg.Log.Warn("changeset: alert not published", slog.String("kind", kind), slog.String("err", err.Error()))
	}
}

/* fail stops the run on d (the first failure names the run's failed device) with why. */
func (m *Manager) fail(ctx context.Context, r *run, d *runDevice, why string) {
	r.mu.Lock()
	first := !r.stop
	r.stop = true
	if first {
		r.reason, r.failed = why, d.plan.ID
	}
	d.state, d.err = devFailed, why
	r.mu.Unlock()
	var sid *[16]byte
	if d.s != nil {
		sid = &d.s.ID
	}
	m.runEvent(ctx, r, "failed", d.plan.ID, sid, map[string]any{"reason": why, "sent": d.sent})
	if first {
		m.runAlert(ctx, KindFailed, d.plan.ID, fmt.Sprintf("changeset %s stopped on device %d: %s; the devices it changed are rolled back",
			IDString(r.st.ID), d.plan.ID, why))
	}
}

/*
prepare renders every device's plan and normalizes it as the dry-run did:
its hash must be the plan's (else nothing is sent). A restore opens every
version first (its hash must be the dry-run's); its lines are planned per
device from the pre-session snapshot (device).
*/
func (m *Manager) prepare(ctx context.Context, r *run) (*runDevice, string) {
	for _, d := range r.devs {
		drv, ok := drivers.For(strategy.Line(d.plan.Line))
		if !ok {
			return d, "plan_changed"
		}
		if r.st.Content.Kind() == ContentRestore {
			v, code := m.openVersion(ctx, r.st.ID, d.plan.ID, d.plan.Version, d.plan.VersionSHA)
			if code != "" {
				return d, code
			}
			d.ver = &v
			continue
		}
		lines, err := r.st.Content.Render(d.plan.ID, drv)
		if err != nil || setLines(drv, d, lines) != nil {
			return d, "plan_changed"
		}
	}
	return nil, ""
}

/* setLines sets d's lines, normalized from the privileged prompt; their hash must be the dry-run's. */
func setLines(drv drivers.WriteDriver, d *runDevice, lines []Rendered) error {
	g, mode := drv.Grammar(), drv.Grammar().Root()
	want := make([]string, len(lines))
	for i, l := range lines {
		n, err := drv.Normalize(l.Line, mode)
		if err != nil {
			return err
		}
		want[i], mode = n, g.Next(n, mode)
	}
	if sum := linesHash(want); hex.EncodeToString(sum[:]) != d.plan.Lines {
		return errors.New("changeset: the lines are not the dry-run's")
	}
	d.lines, d.want = lines, want
	return nil
}

/* execute is the run (see the comment above). */
func (m *Manager) execute(ctx context.Context, r *run) {
	if d, why := m.prepare(ctx, r); d != nil {
		m.fail(ctx, r, d, why)
	}
	if !r.halted() {
		m.phase(r, "canary")
		m.device(ctx, r, r.devs[0])
	}
	if !r.halted() && r.st.Content.SettleS > 0 {
		settle(ctx, time.Duration(r.st.Content.SettleS)*time.Second)
	}
	if !r.halted() {
		if err := m.cfg.Runner.RunHealth(ctx, r.devs[0].s); err != nil {
			m.fail(ctx, r, r.devs[0], "health_failed")
		}
	}
	rest := r.devs[1:]
	for b := 0; !r.halted() && b*r.st.Content.BatchSize < len(rest); b++ {
		m.phase(r, "batch "+strconv.Itoa(b+1))
		batch := rest[b*r.st.Content.BatchSize : min(len(rest), (b+1)*r.st.Content.BatchSize)]
		var wg sync.WaitGroup
		for _, d := range batch {
			wg.Add(1)
			go func() {
				defer wg.Done()
				m.device(ctx, r, d)
			}()
		}
		wg.Wait()
	}
	if !r.halted() {
		m.phase(r, "saving")
		m.saveAll(ctx, r)
		m.endAll(ctx, r)
		m.finishRun(ctx, r, StatusDone)
		return
	}
	m.phase(r, "rolling_back")
	ok := m.rollbackAll(ctx, r)
	m.endAll(ctx, r)
	if ok {
		m.finishRun(ctx, r, StatusRolledBack)
		return
	}
	m.runAlert(ctx, KindRollbackFailed, r.failed, fmt.Sprintf("changeset %s: the rollback of a device did not restore its pre-session "+
		"configuration; check the devices and restore their pre_session versions", IDString(r.st.ID)))
	m.finishRun(ctx, r, StatusRollbackFailed)
}

func (m *Manager) phase(r *run, p string) {
	r.mu.Lock()
	r.phase = p
	r.mu.Unlock()
}

/* device opens, checks and changes one device of the run (see the comment above). */
func (m *Manager) device(ctx context.Context, r *run, d *runDevice) {
	if r.halted() {
		return
	}
	s, rd, err := m.cfg.Runner.RunOpen(ctx, r.st.Author, r.name, d.plan.ID)
	if err != nil {
		m.fail(ctx, r, d, classOf(err))
		return
	}
	r.mu.Lock()
	d.s, d.state = s, devOpened
	r.mu.Unlock()
	m.runEvent(ctx, r, "device_opened", d.plan.ID, &s.ID, map[string]any{"pre_sha256": hex.EncodeToString(rd.Pre[:])})
	switch {
	case hex.EncodeToString(rd.Pre[:]) != d.plan.Pre:
		m.fail(ctx, r, d, "config_changed") /* drift: the configuration is not the one the dry-run read */
		return
	case rd.Address != d.plan.Address || rd.Group != d.plan.Group || rd.Line != d.plan.Line:
		m.fail(ctx, r, d, "registry_changed")
		return
	}
	if d.ver != nil {
		drv, _ := drivers.For(strategy.Line(d.plan.Line))
		lines, err := restorePlan(drv, rd.PreText, d.ver.Text)
		if err != nil || setLines(drv, d, lines) != nil {
			m.fail(ctx, r, d, "plan_changed")
			return
		}
	}
	for i, l := range d.lines {
		if r.halted() {
			return
		}
		r.mu.Lock()
		d.sent++ /* before the send: a line the device may have taken is rolled back */
		r.mu.Unlock()
		if err := m.cfg.Runner.RunSend(ctx, s, l.Line, d.want[i]); err != nil {
			m.fail(ctx, r, d, "line "+strconv.Itoa(i+1)+": "+classOf(err))
			return
		}
	}
	esr := strategy.Line(d.plan.Line) == strategy.ESR
	if esr {
		if err := m.cfg.Runner.RunCommit(ctx, s); err != nil {
			m.fail(ctx, r, d, "commit: "+classOf(err))
			return
		}
	}
	if d.ver != nil { /* a restore ends where the version is, or not at all */
		if sum, err := m.cfg.Runner.RunSnapshot(ctx, s); err != nil || sum != d.ver.SHA256 {
			m.fail(ctx, r, d, "restore_mismatch")
			return
		}
	}
	if esr {
		if err := m.cfg.Runner.RunSave(ctx, s); err != nil {
			m.fail(ctx, r, d, "confirm: "+classOf(err))
			return
		}
	} else if err := m.cfg.Runner.RunHealth(ctx, s); err != nil {
		m.fail(ctx, r, d, "health_failed")
		return
	}
	r.set(d, devApplied, "")
	m.runEvent(ctx, r, "applied", d.plan.ID, &s.ID, map[string]any{"lines": d.sent})
}

/* saveAll saves every MES device at the end of the changeset (D8); a failed save is alerted, the run stays done (the running configuration is the target). */
func (m *Manager) saveAll(ctx context.Context, r *run) {
	for _, d := range r.devs {
		if d.s == nil || strategy.Line(d.plan.Line) == strategy.ESR {
			continue
		}
		if err := m.cfg.Runner.RunSave(ctx, d.s); err != nil {
			r.set(d, d.state, "save: "+classOf(err))
			m.runEvent(ctx, r, "save_failed", d.plan.ID, &d.s.ID, map[string]any{"reason": classOf(err)})
			m.runAlert(ctx, KindFailed, d.plan.ID, fmt.Sprintf("changeset %s: device %d was changed but its startup configuration "+
				"was not saved (%s); save it from a session", IDString(r.st.ID), d.plan.ID, classOf(err)))
			continue
		}
		r.set(d, devSaved, "")
		m.runEvent(ctx, r, "saved", d.plan.ID, &d.s.ID, map[string]any{})
	}
}

/* rollbackAll rolls back every device that got a line; it reports whether every rollback restored its pre-session hash. */
func (m *Manager) rollbackAll(ctx context.Context, r *run) bool {
	ok := true
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, d := range r.devs {
		switch {
		case d.s == nil:
			if d.state == devPending {
				r.set(d, devSkipped, "")
			}
			continue
		case d.sent == 0:
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res := m.cfg.Runner.RollbackRun(ctx, d.s)
			state := devRolledBack
			if res.Error != "" {
				state = devRBFailed
				mu.Lock()
				ok = false
				mu.Unlock()
			}
			r.set(d, state, res.Error)
			m.runEvent(ctx, r, state, d.plan.ID, &d.s.ID, map[string]any{"sha256": res.SHA256, "error": res.Error})
		}()
	}
	wg.Wait()
	return ok
}

/* endAll ends every device's service session (closing the driver session, its summary, device_busy, the lease). */
func (m *Manager) endAll(ctx context.Context, r *run) {
	for _, d := range r.devs {
		if d.s != nil {
			m.cfg.Runner.RunEnd(ctx, d.s, "closed")
		}
	}
}

/* finishRun records the run's terminal event and publishes the status. */
func (m *Manager) finishRun(ctx context.Context, r *run, result string) {
	r.mu.Lock()
	r.result, r.phase = result, "finished"
	reason, failed, by := r.reason, r.failed, r.stopped
	r.mu.Unlock()
	m.runEvent(ctx, r, result, failed, nil, map[string]any{"reason": reason, "stopped_by": by})
	if cs, err := m.cfg.Store.Load(ctx, r.st.ID); err == nil {
		m.publish(ctx, cs)
	}
	uid := r.st.Author
	m.cfg.Auth.Record(ctx, audit.Event{UserID: &uid, Action: "changeset.run", Object: "changeset:" + IDString(r.st.ID), Result: auditResult(result),
		Details: map[string]any{"result": result, "reason": reason, "failed_device": failed, "revision": r.st.Rev}})
}

func auditResult(result string) string {
	if result == StatusDone {
		return audit.OK
	}
	return audit.Error
}

/* RunState is a run in this process, as progress shows it. */
type RunState struct {
	Phase   string           `json:"phase"`
	Result  string           `json:"result,omitempty"`
	Reason  string           `json:"reason,omitempty"`
	Failed  int64            `json:"failed_device_id,omitempty"`
	Devices []RunDeviceState `json:"devices"`
}

/* RunDeviceState is one device of a run. */
type RunDeviceState struct {
	ID      int64  `json:"device_id"`
	State   string `json:"state"`
	Sent    int    `json:"lines_sent"`
	Error   string `json:"error,omitempty"`
	Session string `json:"session_id,omitempty"`
}

/* runState is the run of id in this process (nil: none). */
func (m *Manager) runState(id [16]byte, rev int) *RunState {
	m.mu.Lock()
	r := m.runs[id]
	m.mu.Unlock()
	if r == nil || r.st.Rev != rev {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := &RunState{Phase: r.phase, Result: r.result, Reason: r.reason, Failed: r.failed}
	for _, d := range r.devs {
		ds := RunDeviceState{ID: d.plan.ID, State: d.state, Sent: d.sent, Error: d.err}
		if d.s != nil {
			ds.Session = session.IDString(d.s.ID)
		}
		st.Devices = append(st.Devices, ds)
	}
	return st
}

/* stopOp stops a running changeset: anyone with write on every group of its devices (the author and the second person have it). */
func (m *Manager) stopOp(ctx context.Context, ws workspace, params json.RawMessage) (any, error) {
	var p idParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	cs, err := m.load(ctx, ws, p.ID)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	r := m.runs[cs.ID]
	m.mu.Unlock()
	if r == nil {
		return nil, refuse(CodeState)
	}
	r.mu.Lock()
	running := r.result == ""
	if running && !r.stop {
		r.stop, r.reason, r.stopped = true, "stopped", ws.user
	}
	r.mu.Unlock()
	if !running {
		return nil, refuse(CodeState)
	}
	m.runEvent(ctx, r, "stopped", 0, nil, map[string]any{"by": ws.user})
	m.record(ctx, ws, "changeset.stop", p.ID, audit.OK, map[string]any{"revision": cs.Rev})
	return map[string]bool{"stopping": true}, nil
}

/*
Recover runs once at start, after the sessions' Recover and before /x
serves: every changeset whose newest revision started a run without a
terminal event ends as interrupted, with the high alert naming its devices
and their pre_session configuration versions (a restore changeset brings
them back). Nothing goes on and nothing is rolled back: the driver
sessions of the previous process are gone (D6).
*/
func (m *Manager) Recover(ctx context.Context) error {
	ids, err := m.cfg.Store.Started(ctx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		cs, err := m.cfg.Store.Load(ctx, id)
		if errors.Is(err, ErrTampered) {
			continue /* alerted by Load */
		}
		if err != nil {
			return err
		}
		if st, _ := status(cs); st != StatusRunning {
			continue
		}
		var since time.Time
		for _, e := range cs.Events {
			if e.Rev == cs.Rev && e.Kind == EventRunStarted {
				since = e.At
			}
		}
		versions, err := m.cfg.Store.PreSessionVersions(ctx, cs.Content.Devices, since)
		if err != nil {
			return err
		}
		e, err := m.cfg.Store.Event(ctx, cs.ID, cs.Rev, StatusInterrupted, 0, nil, map[string]any{"reason": "restart", "pre_session_versions": versions})
		if err != nil {
			return err
		}
		cs.Events = append(cs.Events, e)
		m.publish(ctx, cs)
		var parts []string
		for _, d := range cs.Content.Devices {
			v := "none"
			if n, ok := versions[strconv.FormatInt(d, 10)]; ok {
				v = strconv.FormatInt(n, 10)
			}
			parts = append(parts, fmt.Sprintf("%d (pre_session version %s)", d, v))
		}
		m.runAlert(ctx, KindInterrupted, 0, fmt.Sprintf("changeset %s was interrupted by an executor restart; nothing was rolled back. "+
			"Devices: %s; restore them with a restore changeset", IDString(cs.ID), strings.Join(parts, ", ")))
	}
	return nil
}
