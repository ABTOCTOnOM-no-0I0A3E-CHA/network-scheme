package changeset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/internal/execpolicy"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
The dry-run (task 5.3, security.md 5.4). The executor reads every device
itself, over a ReadOnly connection (the read allowlist only: nothing is
written to a device), under the device's connection lease and
execpub.device_busy (the poller keeps off): the running configuration and
its hash (pre_sha256, what the run checks for drift), then show arp and
show mac address-table for the management context a session would have.
The device's plan (variables replaced, forms rendered by its driver) is
walked through its line's grammar from the privileged prompt with the
policy's rules: every line must be Safe (D2: a dangerous line belongs to a
session, where it is confirmed on that device alone), the mode never
unsure, and on MES 6.x every line must have an inverse in the journal a
rollback inverts. The outcome is an event dry_run under the executor's MAC:
per device its registry address, group and line, pre_sha256 and the
SHA-256 of its normalized lines, and plan_sha256 over all of them in the
order of the run (what approval's H covers). Up to changeset_max_batch
devices are read at once; a user starts at most changeset_dry_runs_per_hour
dry-runs an hour.
*/

/* Reader is the dry-run's read of a device: *backups.Scheduler. */
type Reader interface {
	Current(ctx context.Context, le *backups.Lease, extra ...ssh.ShowCommand) (backups.Current, error)
}

/* reversible is the MES 6.x driver's check that a plan can be rolled back (mes6.Driver.Reversible). */
type reversible interface {
	Reversible(pre string, lines []string, c core.Context) error
}

/* Bounds of a dry-run (variables for the tests). */
var (
	dryRunTime   = 10 * time.Minute
	previewLines = 40 /* lines of a context block shown */
)

/* Kind of the policy alert (as session's). */
const kindPolicyInvalid = "executor_policy_invalid"

/* DeviceResult is one device's outcome of a dry-run. */
type DeviceResult struct {
	ID      int64          `json:"device_id"`
	Address string         `json:"address"`
	Group   string         `json:"write_group"`
	Line    string         `json:"line"`
	Pre     string         `json:"pre_sha256,omitempty"`
	OK      bool           `json:"ok"`
	Refused *DeviceRefusal `json:"refused,omitempty"`
	Preview *Preview       `json:"-"`
	lines   [32]byte
}

/* DeviceRefusal is why a device fails the dry-run: a code, and for a line its step, place in the plan, class and reason. */
type DeviceRefusal struct {
	Code   string `json:"code"`
	Step   int    `json:"step,omitempty"`
	N      int    `json:"line,omitempty"` /* 1-based, in the device's plan */
	Class  string `json:"class,omitempty"`
	Reason string `json:"reason,omitempty"`
}

/* Preview is what a device's run would do, masked, shown only as text. */
type Preview struct {
	Lines    []string       `json:"lines"`
	Contexts []ContextBlock `json:"contexts"`
}

/* ContextBlock is a context the plan enters and its current lines on the device. */
type ContextBlock struct {
	Line    string   `json:"line"`
	Current []string `json:"current"`
}

/* PreviewGroup is a preview shared by devices (identical previews are shown once). */
type PreviewGroup struct {
	Devices []int64 `json:"device_ids"`
	Preview
}

/* DryRun is a dry-run's outcome. */
type DryRun struct {
	Rev     int            `json:"revision"`
	OK      bool           `json:"ok"`
	Plan    string         `json:"plan_sha256"`
	Devices []DeviceResult `json:"devices"`
	Preview []PreviewGroup `json:"preview"`
}

/* dryState is a changeset's dry-run in this process: running, or its outcome (for the preview). */
type dryState struct {
	rev    int
	done   chan struct{}
	result *DryRun
	err    error
}

/* planDevice is a device of the stored plan (short keys: 200 devices fit the event's 64 KiB). */
type planDevice struct {
	ID      int64          `json:"id"`
	Address string         `json:"a"`
	Group   string         `json:"g"`
	Line    string         `json:"l"`
	Pre     string         `json:"pre,omitempty"`
	Lines   string         `json:"sha,omitempty"`
	OK      bool           `json:"ok"`
	Refused *DeviceRefusal `json:"r,omitempty"`
}

/* dryRunEvent is the payload of the dry_run event. */
type dryRunEvent struct {
	OK      bool         `json:"ok"`
	Plan    string       `json:"plan_sha256"`
	By      int64        `json:"by"`
	Devices []planDevice `json:"devices"`
}

/* linesHash is the SHA-256 of a device's normalized lines (length-prefixed, in order). */
func linesHash(lines []string) [32]byte {
	h := sha256.New()
	h.Write([]byte("nms/changeset-lines/v1"))
	for _, l := range lines {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(l)))) // #nosec G115 -- lines are bounded
		h.Write([]byte(l))
	}
	return [32]byte(h.Sum(nil))
}

/*
planHash is plan_sha256 (security.md 5.4 D3): over every device in the
order of the run, length-prefixed: id, address:port, write group, line,
pre_sha256 and the SHA-256 of its normalized lines.
*/
func planHash(devs []planDevice) string {
	h := sha256.New()
	str := func(s string) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s)))) // #nosec G115 -- bounded
		h.Write([]byte(s))
	}
	str("nms/changeset-plan/v1")
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(devs)))) // #nosec G115 -- at most 200
	for _, d := range devs {
		h.Write(i64(d.ID))
		str(d.Address)
		str(d.Group)
		str(d.Line)
		str(d.Pre)
		str(d.Lines)
	}
	return hex.EncodeToString(h.Sum(nil))
}

type dryRunParams struct {
	ID  string `json:"changeset_id"`
	Rev int    `json:"revision"`
}

/* dryRunOp starts the dry-run of the newest revision (the one the user edited) in the background; progress shows it. */
func (m *Manager) dryRunOp(ctx context.Context, ws workspace, params json.RawMessage) (any, error) {
	var p dryRunParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	cs, err := m.load(ctx, ws, p.ID)
	if err != nil {
		return nil, err
	}
	st, _ := status(cs)
	switch {
	case !slices.Contains(editable, st):
		return nil, refuse(CodeState)
	case p.Rev != cs.Rev:
		return nil, refuse(CodeConflict)
	case cs.Kind != KindLines:
		return nil, refuse("restore_unavailable") /* task 5.6 */
	case m.cfg.Reader == nil || m.cfg.Locks == nil:
		return nil, refuse("dry_run_unavailable")
	}
	pol := m.cfg.Policy().Policy
	now := m.cfg.Now()
	m.mu.Lock()
	if d := m.dry[cs.ID]; d != nil && d.result == nil && d.err == nil {
		m.mu.Unlock()
		return nil, refuse("dry_run_running")
	}
	runs := m.dryRuns[ws.user][:0]
	for _, at := range m.dryRuns[ws.user] {
		if now.Sub(at) < time.Hour {
			runs = append(runs, at)
		}
	}
	if len(runs) >= pol.ChangesetDryRunsPerHour {
		m.dryRuns[ws.user] = runs
		m.mu.Unlock()
		m.record(ctx, ws, "changeset.dry_run", p.ID, audit.Denied, map[string]any{"class": "dry_run_limit"})
		return nil, refuse("dry_run_limit")
	}
	m.dryRuns[ws.user] = append(runs, now)
	d := &dryState{rev: cs.Rev, done: make(chan struct{})}
	m.dry[cs.ID] = d
	m.mu.Unlock()
	m.record(ctx, ws, "changeset.dry_run", p.ID, audit.OK, map[string]any{"revision": cs.Rev})
	go func() {
		defer close(d.done)
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dryRunTime)
		defer cancel()
		res, err := m.dryRun(rctx, ws, cs, pol)
		m.mu.Lock()
		d.result, d.err = res, err
		m.mu.Unlock()
		if err != nil {
			m.cfg.Log.Warn("changeset: dry-run failed", slog.String("changeset", p.ID), slog.String("err", err.Error()))
		}
	}()
	return map[string]any{"started": true, "revision": cs.Rev}, nil
}

/*
dryRun reads every device of cs (see the comment above) and records the
dry_run event of cs.Rev; the result keeps the previews (never stored).
*/
func (m *Manager) dryRun(ctx context.Context, ws workspace, cs Changeset, pol execpolicy.Policy) (*DryRun, error) {
	var run [16]byte /* the dry-run's id in execpub.device_busy */
	if _, err := rand.Read(run[:]); err != nil {
		return nil, err
	}
	run[6], run[8] = run[6]&0x0f|0x40, run[8]&0x3f|0x80
	results := make([]DeviceResult, len(cs.Content.Devices))
	sem := make(chan struct{}, max(1, pol.ChangesetMaxBatch))
	var wg sync.WaitGroup
	for i, id := range cs.Content.Devices {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = m.dryDevice(ctx, ws, cs.Content, id, run, pol)
		}()
	}
	wg.Wait()
	out := &DryRun{Rev: cs.Rev, OK: true, Devices: results}
	plan := make([]planDevice, len(results))
	for i, r := range results {
		out.OK = out.OK && r.OK
		plan[i] = planDevice{ID: r.ID, Address: r.Address, Group: r.Group, Line: r.Line, Pre: r.Pre, OK: r.OK, Refused: r.Refused}
		if r.OK {
			plan[i].Lines = hex.EncodeToString(r.lines[:])
		}
	}
	out.Plan = planHash(plan)
	out.Preview = group(results)
	e, err := m.cfg.Store.Event(ctx, cs.ID, cs.Rev, EventDryRun, 0, nil, dryRunEvent{OK: out.OK, Plan: out.Plan, By: ws.user, Devices: plan})
	if err != nil {
		return nil, err
	}
	cs.Events = append(cs.Events, e)
	m.publish(ctx, cs)
	return out, nil
}

/* group shows identical previews once, with every device they belong to. */
func group(results []DeviceResult) []PreviewGroup {
	var out []PreviewGroup
	for _, r := range results {
		if r.Preview == nil {
			continue
		}
		i := slices.IndexFunc(out, func(g PreviewGroup) bool {
			a, _ := json.Marshal(g.Preview)
			b, _ := json.Marshal(*r.Preview)
			return string(a) == string(b)
		})
		if i < 0 {
			out = append(out, PreviewGroup{Preview: *r.Preview})
			i = len(out) - 1
		}
		out[i].Devices = append(out[i].Devices, r.ID)
	}
	return out
}

/* refusalOf is a device's result refused with code (and its reason). */
func refusalOf(r DeviceResult, code, reason string) DeviceResult {
	r.Refused, r.OK = &DeviceRefusal{Code: code, Reason: reason}, false
	return r
}

/* dryDevice dry-runs one device (see the comment above). */
func (m *Manager) dryDevice(ctx context.Context, ws workspace, c Content, id int64, run [16]byte, pol execpolicy.Policy) DeviceResult {
	res := DeviceResult{ID: id}
	var (
		row     registry.Row
		address netip.Addr
	)
	err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		if r := deviceRefusal(s, id); r != nil {
			return r
		}
		if !granted(s, ws, groupsOf(s, []int64{id})) {
			return &Refusal{Code: "no_grant", Device: id}
		}
		row, _ = s.Get("write_device", id)
		address, _ = row.Get("address").(netip.Addr)
		port, _ := row.Get("port").(int64)
		if !address.IsValid() || port < 1 || port > 65535 {
			return &Refusal{Code: "device_unknown", Device: id}
		}
		res.Address = netip.AddrPortFrom(address, uint16(port)).String() // #nosec G115 -- checked above
		res.Group, _ = row.Get("write_group").(string)
		res.Line, _ = row.Get("write_driver").(string)
		return nil
	})
	var rf *Refusal
	switch {
	case errors.As(err, &rf):
		return refusalOf(res, rf.Code, "")
	case err != nil:
		return refusalOf(res, "unavailable", "")
	}
	line := strategy.Line(res.Line)
	drv, ok := drivers.For(line)
	if !ok {
		return refusalOf(res, "line_unknown", "")
	}
	le, ok := m.cfg.Locks.TryLock(id)
	if !ok {
		return refusalOf(res, "device_busy", "another connection of the executor holds the device")
	}
	defer le.Release()
	switch err := m.cfg.Pub.Busy(ctx, row, run); {
	case errors.Is(err, pub.ErrDeviceBusy):
		return refusalOf(res, "device_busy", "the device is in a change session")
	case err != nil:
		return refusalOf(res, "unavailable", "")
	}
	defer func() {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
		defer cancel()
		if err := m.cfg.Pub.Free(fctx, id, run); err != nil {
			m.cfg.Log.Error("changeset: device_busy not freed (Recover frees it at the next start)", slog.Int64("device_id", id))
		}
	}()
	cur, err := m.cfg.Reader.Current(ctx, le, ssh.ShowCommand{Name: "show arp"}, ssh.ShowCommand{Name: "show mac address-table", LongOutput: true})
	if err != nil {
		/* err may carry device text: debug level only */
		m.cfg.Log.Debug("changeset: dry-run read failed", slog.Int64("device_id", id), slog.String("err", err.Error()))
		return refusalOf(res, "device_failed", "the device could not be read")
	}
	if cur.Line != line || len(cur.Out) != 2 {
		return refusalOf(res, "line_mismatch", "")
	}
	res.Pre = hex.EncodeToString(cur.SHA256[:])
	rules, err := core.NewRules(drv.Grammar(), string(line), pol.ClassOverrides)
	if err != nil {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
		_ = m.cfg.Pub.Alert(actx, kindPolicyInvalid, "high", id, "the policy's class overrides do not fit the "+string(line)+" grammar: "+err.Error())
		cancel()
		return refusalOf(res, "policy_invalid", "")
	}
	mgmt, err := session.MgmtTargets(drv, cur.Text, address, cur.Local, cur.Out[0], cur.Out[1])
	if err != nil {
		return refusalOf(res, "mgmt_unknown", "the management interface of the device cannot be determined")
	}
	cctx := core.Context{Mgmt: mgmt, Rules: rules}
	plan, err := c.Render(id, drv)
	if err != nil {
		return refusalOf(res, CodeBadLine, err.Error())
	}
	lines, pv, ref := walk(drv, plan, cctx, cur.Text)
	if ref != nil {
		res.Refused = ref
		return res
	}
	if rv, ok := drv.(reversible); ok {
		if err := rv.Reversible(cur.Text, lines, cctx); err != nil {
			return refusalOf(res, "no_inverse", drivers.Mask(err.Error()))
		}
	}
	res.OK, res.lines, res.Preview = true, linesHash(lines), pv
	return res
}

/*
walk classifies a device's plan from the privileged prompt as the device
would take it, line after line (core.Next): every line Safe in the mode and
context it is typed in (a line naming an executor snapshot nms-pre-* is
Denied, as in a session), the mode never unsure. It returns the normalized
lines and the masked preview (config is the device's configuration, for the
contexts the plan enters), or the first line refused.
*/
func walk(drv drivers.WriteDriver, plan []Rendered, cctx core.Context, config string) ([]string, *Preview, *DeviceRefusal) {
	g := drv.Grammar()
	mode := g.Root()
	var lines []string
	pv := &Preview{Lines: []string{}, Contexts: []ContextBlock{}}
	for i, r := range plan {
		v := drv.Classify(r.Line, mode, cctx)
		if (v.Class == core.Safe || v.Class == core.Dangerous) && strings.Contains(strings.ToLower(v.Line), "nms-pre-") {
			v = core.Verdict{Class: core.Denied, Line: v.Line, Reason: drivers.ReasonSnapshot}
		}
		if v.Class != core.Safe {
			return nil, nil, &DeviceRefusal{Code: "not_safe", Step: r.Step, N: i + 1, Class: v.Class.String(), Reason: string(v.Reason)}
		}
		next := g.Next(v.Line, mode)
		if next.Unsure() {
			return nil, nil, &DeviceRefusal{Code: "mode_unsure", Step: r.Step, N: i + 1, Class: v.Class.String()}
		}
		if next.Name() != mode.Name() && next.Name() != "config" && next.Name() != g.Root().Name() {
			pv.Contexts = append(pv.Contexts, ContextBlock{Line: drivers.Mask(v.Line), Current: block(config, v.Line)})
		}
		mode = next
		lines = append(lines, v.Line)
		pv.Lines = append(pv.Lines, drivers.Mask(v.Line))
	}
	return lines, pv, nil
}

/* block is the current lines of the context line ctx in config (its indented body), masked and bounded. */
func block(config, ctx string) []string {
	out := []string{}
	in := false
	for _, l := range strings.Split(config, "\n") {
		l = strings.TrimRight(l, "\r ")
		switch {
		case !in && strings.EqualFold(strings.TrimSpace(l), ctx):
			in = true
			out = append(out, drivers.Mask(strings.TrimSpace(l)))
		case in && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")):
			if len(out) < previewLines {
				out = append(out, drivers.Mask(l))
			}
		case in:
			return out
		}
	}
	return out
}

/* DryRunState is a changeset's dry-run in this process, as progress shows it. */
type DryRunState struct {
	Running bool    `json:"running"`
	Result  *DryRun `json:"result,omitempty"`
	Error   string  `json:"error,omitempty"`
}

/* dryRunState is the in-memory dry-run of revision rev of id (nil: none in this process). */
func (m *Manager) dryRunState(id [16]byte, rev int) *DryRunState {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.dry[id]
	if d == nil || d.rev != rev {
		return nil
	}
	st := &DryRunState{Running: d.result == nil && d.err == nil, Result: d.result}
	if d.err != nil {
		st.Error = "unavailable"
	}
	return st
}
