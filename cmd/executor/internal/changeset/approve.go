package changeset

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/approval"
	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/*
Approval (task 5.4, security.md 5.4 D3, D4). The action changeset.approve
is described through /x/confirm/issue (Describe: from the newest revision,
its verified dry_run event and the registry now; the grant is write on
every group of the changeset's devices) and confirmed only on its own
route, POST /x/changesets/{id}/approve/{count}, where count is the number of
devices the user typed (it is not in H: it is typed, not read). Run builds
the description again (anything changed since the challenge: refused), then
checks the count, the policy, the freeze and the change window, and:

  - the author, no second person needed: the run starts;
  - the author, a second person needed (a group of two_person_groups, or
    outside every window with outside_window: second_person): the author's
    approval waits second_person_minutes in memory (approval.Store), status
    approved; the author confirming again is same_person;
  - anyone else: a live approval of the author with the same H is needed,
    the confirming user neither the author's id nor name; the run starts.

The run is run.go's (Config.Start); without one nothing starts and the
approval is refused before anything is recorded (fail closed).
*/

/* ApproveAction is the confirm(H) action of approving a changeset (web.Confirmed). */
const ApproveAction = "changeset.approve"

/* approvalKind is the changesets' kind in approval.Store. */
const approvalKind = "changeset"

/* Started is what a run starts with: the approved revision, its plan and who approved it. */
type Started struct {
	ID         [16]byte
	Rev        int
	Content    Content
	Plan       []PlanDevice
	PlanHash   string
	H          [32]byte
	Author     int64
	AuthorName string
	Second     int64 /* the second person (0: none needed) */
}

/* PlanDevice is a device of the dry-run's plan as the run checks it (drift: Pre; lines: the hash of the normalized lines). */
type PlanDevice struct {
	ID      int64
	Address string
	Group   string
	Line    string
	Pre     string
	Lines   string
}

/* described is a changeset's approval description and what it was built from. */
type described struct {
	cs     Changeset
	need   authz.Need
	d      confirm.Description
	plan   []planDevice
	hash   string
	groups []string
}

type approveParams struct {
	ID string `json:"changeset_id"`
}

/* Describe is changeset.approve's Describe (web.Action): any user with write on every group may ask (author or second person). */
func (m *Manager) Describe(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	var p approveParams
	if err := strict(params, &p); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	if err := m.active(); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	x, err := m.describe(ctx, workspace{user: by.UserID, username: by.Username}, p.ID)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	return x.need, x.d, nil
}

/*
describe builds the description (D3) from the newest revision, its dry_run
event (verified by Load) and the registry now: the dry-run must have passed
for every device in the content's order, and the plan with the registry's
addresses and groups of now must hash as the dry-run's (else the dry-run is
stale: run it again).
*/
func (m *Manager) describe(ctx context.Context, ws workspace, id string) (described, error) {
	cs, err := m.load(ctx, ws, id)
	if err != nil {
		return described{}, err
	}
	if st, _ := status(cs); st != StatusDryRunOK && st != StatusApproved {
		return described{}, refuse(CodeState)
	}
	var ev *dryRunEvent
	for _, e := range cs.Events {
		if e.Rev == cs.Rev && e.Kind == EventDryRun {
			var p dryRunEvent
			if err := json.Unmarshal(e.Payload, &p); err != nil {
				return described{}, refuse(CodeTampered)
			}
			ev = &p
		}
	}
	if ev == nil || !ev.OK || len(ev.Devices) != len(cs.Content.Devices) || planHash(ev.Devices) != ev.Plan {
		return described{}, refuse("dry_run_required")
	}
	now := slices.Clone(ev.Devices)
	var groups []string
	if err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		for i, d := range now {
			if d.ID != cs.Content.Devices[i] || !d.OK {
				return refuse("dry_run_required")
			}
			if r := deviceRefusal(s, d.ID); r != nil {
				return r
			}
			row, _ := s.Get("write_device", d.ID)
			a, _ := row.Get("address").(netip.Addr)
			port, _ := row.Get("port").(int64)
			if !a.IsValid() || port < 1 || port > 65535 {
				return &Refusal{Code: "device_unknown", Device: d.ID}
			}
			now[i].Address = netip.AddrPortFrom(a, uint16(port)).String() // #nosec G115 -- checked above
			now[i].Group, _ = row.Get("write_group").(string)
			now[i].Line, _ = row.Get("write_driver").(string)
			groups = append(groups, now[i].Group)
		}
		return nil
	}); err != nil {
		return described{}, viewErr(err)
	}
	if planHash(now) != ev.Plan {
		return described{}, refuse("dry_run_stale") /* an address, group or line changed in the registry since the dry-run */
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	c := cs.Content
	fields := []confirm.Field{
		{Key: "author", Value: strconv.FormatInt(cs.Author, 10) + " " + cs.AuthorName},
		{Key: "batch_size", Value: strconv.Itoa(c.BatchSize)},
		{Key: "canary", Value: strconv.FormatInt(c.Devices[0], 10)},
		{Key: "changeset", Value: IDString(cs.ID)},
		{Key: "groups", Value: strings.Join(groups, ",")},
		{Key: "kind", Value: cs.Kind},
		{Key: "plan_sha256", Value: ev.Plan},
		{Key: "revision", Value: strconv.Itoa(cs.Rev)},
		{Key: "settle_s", Value: strconv.Itoa(c.SettleS)},
		{Key: "title", Value: c.Title},
	}
	return described{cs: cs, need: authz.Need{Kind: execadmin.KindWrite, Groups: groups},
		d: confirm.Description{Action: ApproveAction, Fields: fields}, plan: now, hash: ev.Plan, groups: groups}, nil
}

/* classOf is the audit class of a refusal (its code) or "error". */
func classOf(err error) string {
	var r interface{ RefusalCode() string }
	if errors.As(err, &r) {
		return r.RefusalCode()
	}
	return "error"
}

/* field is the value of key in d. */
func field(d confirm.Description, key string) string {
	for _, f := range d.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return ""
}

/* Approved is the answer of the approve route. */
type Approved struct {
	Status  string     `json:"status"` /* awaiting_second_person, running */
	Expires *time.Time `json:"second_person_until,omitempty"`
}

/* RunApprove is the approve route's Run (web.Confirmed): objs are the changeset id and the typed device count. */
func (m *Manager) RunApprove(ctx context.Context, c confirm.Challenge, by authz.Decision, objs []string) (any, error) {
	ws := workspace{user: by.UserID, username: by.Username}
	if len(objs) != 2 || c.Action != ApproveAction || c.User != by.UserID || field(c.Description, "changeset") != objs[0] {
		return nil, refuse("changed")
	}
	deny := func(class string, err error) error {
		m.record(ctx, ws, ApproveAction, objs[0], audit.Denied, map[string]any{"class": class, "challenge": c.ID})
		return err
	}
	if err := m.active(); err != nil {
		return nil, err
	}
	x, err := m.describe(ctx, ws, objs[0])
	if err != nil {
		return nil, deny(classOf(err), err)
	}
	if x.d.Action != c.Description.Action || !slices.Equal(x.d.Fields, c.Description.Fields) {
		return nil, deny("changed", refuse("changed")) /* the revision, its dry-run or the registry changed since the challenge */
	}
	if n, err := strconv.Atoi(objs[1]); err != nil || n != len(x.cs.Content.Devices) {
		return nil, deny("device_count", refuse("device_count"))
	}
	pol := m.cfg.Policy().Policy
	second, err := m.needSecond(ctx, pol, x)
	if err != nil {
		return nil, deny("outside_window", err)
	}
	if m.cfg.Start == nil || m.cfg.Approvals == nil {
		return nil, deny("run_unavailable", refuse("run_unavailable"))
	}
	object := "changeset:" + objs[0]
	author := by.UserID == x.cs.Author && strings.EqualFold(by.Username, x.cs.AuthorName)
	if author {
		if pending, ok := m.cfg.Approvals.Find(approvalKind, object); ok && pending.User == by.UserID {
			return nil, deny(string(approval.ErrSamePerson), approval.ErrSamePerson)
		}
		if !second {
			return m.start(ctx, ws, x, c, nil)
		}
		id, err := approval.NewID()
		if err != nil {
			return nil, err
		}
		a, err := m.cfg.Approvals.Request(approval.Approval{ID: id, Kind: approvalKind, User: by.UserID, Username: x.cs.AuthorName,
			Object: object, Groups: x.groups, H: c.H, Challenge: c.ID}, time.Duration(pol.SecondPersonMinutes)*time.Minute)
		if err != nil {
			return nil, deny(classOf(err), err)
		}
		e, err := m.cfg.Store.Event(ctx, x.cs.ID, x.cs.Rev, EventApproved, 0, nil, map[string]any{"by": by.UserID, "h": hex.EncodeToString(c.H[:]),
			"challenge": c.ID, "until": a.Expires.UTC()})
		if err != nil {
			m.cfg.Approvals.Drop(approvalKind, object)
			return nil, err
		}
		x.cs.Events = append(x.cs.Events, e)
		m.publish(ctx, x.cs)
		m.record(ctx, ws, ApproveAction, objs[0], audit.OK, map[string]any{"stage": "author", "challenge": c.ID,
			"h": hex.EncodeToString(c.H[:]), "revision": x.cs.Rev})
		until := a.Expires.UTC()
		return Approved{Status: "awaiting_second_person", Expires: &until}, nil
	}
	pending, ok := m.cfg.Approvals.Find(approvalKind, object)
	if !ok || pending.User != x.cs.Author {
		return nil, deny("author_approval_required", refuse("author_approval_required"))
	}
	if _, err := m.cfg.Approvals.Approve(pending.ID, by, c.H, c.ID); err != nil {
		return nil, deny(classOf(err), err)
	}
	a, err := m.cfg.Approvals.Take(pending.ID, x.cs.Author, object)
	if err != nil {
		return nil, deny(classOf(err), err)
	}
	return m.start(ctx, ws, x, c, &a)
}

/*
needSecond reports whether a second person must approve: a group of
two_person_groups, or outside every change window with outside_window:
second_person (deny refuses, with the warning alert).
*/
func (m *Manager) needSecond(ctx context.Context, p execpolicy.Policy, x described) (bool, error) {
	second := slices.ContainsFunc(x.groups, func(g string) bool { return slices.Contains(p.TwoPersonGroups, g) })
	if !session.InWindow(m.cfg.Now(), p) {
		if p.OutsideWindow != execpolicy.OutsideSecondPerson {
			actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
			defer cancel()
			_ = m.cfg.Pub.Alert(actx, session.KindOutsideWindow, "warning", 0,
				fmt.Sprintf("changeset %s was approved outside the change windows; refused", IDString(x.cs.ID)))
			return false, refuse("outside_window")
		}
		second = true
	}
	return second, nil
}

/* start records run_started (the author, the second person, H and both challenges) and hands the run to Config.Start. */
func (m *Manager) start(ctx context.Context, ws workspace, x described, c confirm.Challenge, a *approval.Approval) (any, error) {
	st := Started{ID: x.cs.ID, Rev: x.cs.Rev, Content: x.cs.Content, PlanHash: x.hash, H: c.H, Author: x.cs.Author, AuthorName: x.cs.AuthorName}
	for _, d := range x.plan {
		st.Plan = append(st.Plan, PlanDevice{ID: d.ID, Address: d.Address, Group: d.Group, Line: d.Line, Pre: d.Pre, Lines: d.Lines})
	}
	payload := map[string]any{"author": x.cs.Author, "h": hex.EncodeToString(c.H[:]), "plan_sha256": x.hash, "challenge": c.ID}
	if a != nil {
		st.Second = a.By
		payload["second"], payload["author_challenge"] = a.By, a.Challenge
	}
	e, err := m.cfg.Store.Event(ctx, x.cs.ID, x.cs.Rev, EventRunStarted, 0, nil, payload)
	if err != nil {
		return nil, err
	}
	x.cs.Events = append(x.cs.Events, e)
	m.publish(ctx, x.cs)
	m.record(ctx, ws, ApproveAction, IDString(x.cs.ID), audit.OK, map[string]any{"stage": "start", "challenge": c.ID,
		"h": hex.EncodeToString(c.H[:]), "second": st.Second, "revision": x.cs.Rev})
	if err := m.cfg.Start(ctx, st); err != nil {
		return nil, err
	}
	return Approved{Status: "running"}, nil
}
