package session

import (
	"context"
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
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/*
Sessions that need a second person (security.md 5.4 D5, Phase 5): a group
of two_person_groups, or outside every change window with outside_window:
second_person. The author asks (Request: ticket + change TOTP, the
devices); another user with write on every group approves with their own
change TOTP through confirm(H) of session.approve, H over the request, the
author, the devices with their registry addresses, the groups and the
reason; the author then opens with the approval's id, once, for the same
devices, within second_person_minutes (OpenApproved). Approvals live only
in memory (approval.Store): a restart forgets them.
*/

/* ApproveAction is the confirm(H) action of the second person's approval of a session (web.Action). */
const ApproveAction = "session.approve"

/* ErrNotNeeded refuses a request for a session that needs no second person. */
const ErrNotNeeded Refusal = "second_person_not_needed"

/* approvalKind is the sessions' kind in approval.Store. */
const approvalKind = "session"

/* requestObject is the approval's object: the devices, sorted (the same set opens, in any order). */
func requestObject(ids []int64) string { return object(slices.Sorted(slices.Values(ids))) }

/* refusalCode is the audit class of a refusal. */
func refusalCode(err error) string {
	var r interface{ RefusalCode() string }
	if errors.As(err, &r) {
		return r.RefusalCode()
	}
	return "error"
}

/*
secondReason is why a session on groups needs a second person now:
two_person, outside_window or none (""); outside every window with
outside_window: deny it refuses (with the warning alert).
*/
func (m *Manager) secondReason(ctx context.Context, user int64, obj string, p execpolicy.Policy, groups []string) (string, error) {
	two := slices.ContainsFunc(groups, func(g string) bool { return slices.Contains(p.TwoPersonGroups, g) })
	if !inWindow(m.cfg.Now(), p) {
		if p.OutsideWindow != execpolicy.OutsideSecondPerson {
			m.alert(ctx, KindOutsideWindow, "warning", 0, fmt.Sprintf("user %d asked for a change session on %s outside the change windows; refused", user, obj))
			return "", ErrOutsideWindow
		}
		if !two {
			return "outside_window", nil
		}
	}
	if two {
		return "two_person", nil
	}
	return "", nil
}

/*
approvalDescription is session.approve's description of request id of
author for ids: the registry's address:port and write group of every
device (a device the registry does not have refuses), and the reason.
*/
func (m *Manager) approvalDescription(ctx context.Context, id string, author int64, name string, ids []int64, reason string) (authz.Need, confirm.Description, error) {
	ids = slices.Sorted(slices.Values(ids))
	var groups []string
	fields := []confirm.Field{{Key: "author", Value: strconv.FormatInt(author, 10) + " " + name}}
	strs := make([]string, len(ids))
	if err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		for i, d := range ids {
			r, ok := s.Get("write_device", d)
			if !ok {
				return authz.ErrDenied
			}
			a, _ := r.Get("address").(netip.Addr)
			port, _ := r.Get("port").(int64)
			if !a.IsValid() || port < 1 || port > 65535 {
				return authz.ErrDenied
			}
			g, _ := r.Get("write_group").(string)
			groups = append(groups, g)
			strs[i] = strconv.FormatInt(d, 10)
			fields = append(fields, confirm.Field{Key: "address_" + strs[i], Value: netip.AddrPortFrom(a, uint16(port)).String()}) // #nosec G115 -- checked above
		}
		return nil
	}); err != nil {
		return authz.Need{}, confirm.Description{}, viewErr(err)
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	fields = append(fields, confirm.Field{Key: "devices", Value: strings.Join(strs, ",")}, confirm.Field{Key: "groups", Value: strings.Join(groups, ",")},
		confirm.Field{Key: "reason", Value: reason}, confirm.Field{Key: "request", Value: id})
	slices.SortFunc(fields, func(a, b confirm.Field) int { return strings.Compare(a.Key, b.Key) })
	return authz.Need{Kind: execadmin.KindWrite, Groups: groups}, confirm.Description{Action: ApproveAction, Fields: fields}, nil
}

/* takeApproval spends the approval of a session that needs one: it must be the user's, for these devices, given, and its H still the description of now. */
func (m *Manager) takeApproval(ctx context.Context, id string, by authz.Decision, ids []int64, reason string) (approval.Approval, error) {
	if id == "" || m.cfg.Approvals == nil {
		return approval.Approval{}, ErrTwoPerson
	}
	a, err := m.cfg.Approvals.Take(id, by.UserID, requestObject(ids))
	if err != nil {
		return approval.Approval{}, err
	}
	_, d, err := m.approvalDescription(ctx, a.ID, a.User, a.Username, ids, reason)
	if err != nil {
		return approval.Approval{}, err
	}
	if h, err := d.Hash(); err != nil || h != a.H {
		return approval.Approval{}, approval.ErrMismatch /* the registry, the reason or the policy changed since the approval */
	}
	return a, nil
}

/* Requested is the answer of a request: its id, until when it waits, and the description the second person confirms. */
type Requested struct {
	ID      string          `json:"request_id"`
	Expires time.Time       `json:"expires"`
	Fields  []confirm.Field `json:"fields"`
}

/*
Request asks for a second person's approval of a session on ids (ticket and
change TOTP of the author, as Open; a session that needs none is refused).
*/
func (m *Manager) Request(ctx context.Context, req authz.Request, ids []int64) (Requested, error) {
	obj := object(ids)
	if len(ids) == 0 || len(ids) > maxDevices || slices.ContainsFunc(ids, func(id int64) bool { return id <= 0 }) ||
		len(slices.Compact(slices.Sorted(slices.Values(ids)))) != len(ids) {
		return Requested{}, ErrBadDevices
	}
	pol := m.cfg.Policy()
	if !pol.Enabled() {
		return Requested{}, authz.ErrDisabled
	}
	if frozen, _ := m.cfg.Gate.Frozen(); frozen {
		return Requested{}, authz.ErrFrozen
	}
	var groups []string
	if err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		for _, id := range ids {
			g := noGroup
			if r, ok := s.Get("write_device", id); ok {
				g, _ = r.Get("write_group").(string)
			}
			groups = append(groups, g)
		}
		return nil
	}); err != nil {
		return Requested{}, viewErr(err)
	}
	slices.Sort(groups)
	req.Need = authz.Need{Kind: execadmin.KindWrite, Groups: slices.Compact(groups)}
	req.Action, req.Object = "session.request", obj
	by, err := m.cfg.Auth.Authorize(ctx, req)
	if err != nil {
		return Requested{}, err
	}
	p := pol.Policy
	if len(ids) > p.MaxDevicesPerSession {
		return Requested{}, m.refuse(ctx, req, by.UserID, obj, ErrTooManyDevices, "too_many_devices")
	}
	reason, err := m.secondReason(ctx, by.UserID, obj, p, req.Need.Groups)
	switch {
	case err != nil:
		return Requested{}, m.refuse(ctx, req, by.UserID, obj, err, "outside_window")
	case reason == "" || m.cfg.Approvals == nil:
		return Requested{}, m.refuse(ctx, req, by.UserID, obj, ErrNotNeeded, string(ErrNotNeeded))
	}
	if err := m.preflight(ctx, ids, p); err != nil {
		return Requested{}, err
	}
	id, err := approval.NewID()
	if err != nil {
		return Requested{}, err
	}
	need, d, err := m.approvalDescription(ctx, id, by.UserID, by.Username, ids, reason)
	if err != nil {
		return Requested{}, err
	}
	h, err := d.Hash()
	if err != nil {
		return Requested{}, err
	}
	a, err := m.cfg.Approvals.Request(approval.Approval{ID: id, Kind: approvalKind, User: by.UserID, Username: by.Username,
		Object: requestObject(ids), Groups: need.Groups, H: h}, time.Duration(p.SecondPersonMinutes)*time.Minute)
	if err != nil {
		return Requested{}, err
	}
	uid := by.UserID
	m.cfg.Auth.Record(ctx, audit.Event{UserID: &uid, Action: "session.request", Object: obj, Result: audit.OK, IP: req.IP, UA: req.UA,
		Details: map[string]any{"request": id, "reason": reason}})
	return Requested{ID: id, Expires: a.Expires.UTC(), Fields: d.Fields}, nil
}

type approveParams struct {
	Request string `json:"request_id"`
}

/* pendingRequest is the live, not yet approved session request id and its devices. */
func (m *Manager) pendingRequest(id string) (approval.Approval, []int64, error) {
	if m.cfg.Approvals == nil {
		return approval.Approval{}, nil, approval.ErrExpired
	}
	a, ok := m.cfg.Approvals.Get(id)
	if !ok || a.Kind != approvalKind || a.Approved {
		return approval.Approval{}, nil, approval.ErrExpired
	}
	var ids []int64
	for _, s := range strings.Split(strings.TrimPrefix(a.Object, "devices:"), ",") {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return approval.Approval{}, nil, approval.ErrMismatch
		}
		ids = append(ids, n)
	}
	return a, ids, nil
}

/* reasonNow is the request's reason under the policy of now (a changed policy changes H). */
func (m *Manager) reasonNow(ctx context.Context, a approval.Approval, ids []int64) (string, error) {
	return m.secondReason(ctx, a.User, object(ids), m.cfg.Policy().Policy, a.Groups)
}

/* DescribeApprove is session.approve's Describe (web.Action): another user than the author, with write on every group. */
func (m *Manager) DescribeApprove(ctx context.Context, by authz.Decision, params json.RawMessage) (authz.Need, confirm.Description, error) {
	var p approveParams
	if err := strict(params, &p); err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	a, ids, err := m.pendingRequest(p.Request)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	if by.UserID == a.User || strings.EqualFold(by.Username, a.Username) {
		uid := by.UserID
		m.cfg.Auth.Record(ctx, audit.Event{UserID: &uid, Action: ApproveAction, Object: "request:" + a.ID, Result: audit.Denied,
			Details: map[string]any{"class": string(approval.ErrSamePerson)}})
		return authz.Need{}, confirm.Description{}, approval.ErrSamePerson
	}
	reason, err := m.reasonNow(ctx, a, ids)
	if err != nil {
		return authz.Need{}, confirm.Description{}, err
	}
	return m.approvalDescription(ctx, a.ID, a.User, a.Username, ids, reason)
}

/*
RunApprove is session.approve's Run: the description built again must be
the confirmed one, and the store records the approval (another user than
the author, the request's H).
*/
func (m *Manager) RunApprove(ctx context.Context, c confirm.Challenge, by authz.Decision) (any, error) {
	var id string
	for _, f := range c.Description.Fields {
		if f.Key == "request" {
			id = f.Value
		}
	}
	uid := by.UserID
	deny := func(err error) error {
		m.cfg.Auth.Record(ctx, audit.Event{UserID: &uid, Action: ApproveAction, Object: "request:" + id, Result: audit.Denied,
			Details: map[string]any{"class": refusalCode(err), "challenge": c.ID}})
		return err
	}
	a, ids, err := m.pendingRequest(id)
	if err != nil {
		return nil, deny(err)
	}
	reason, err := m.reasonNow(ctx, a, ids)
	if err != nil {
		return nil, deny(err)
	}
	_, d, err := m.approvalDescription(ctx, a.ID, a.User, a.Username, ids, reason)
	if err != nil {
		return nil, deny(err)
	}
	if c.Action != ApproveAction || c.User != by.UserID || !slices.Equal(d.Fields, c.Description.Fields) {
		return nil, deny(ErrDescription)
	}
	if _, err := m.cfg.Approvals.Approve(a.ID, by, c.H, c.ID); err != nil {
		return nil, deny(err)
	}
	m.cfg.Auth.Record(ctx, audit.Event{UserID: &uid, Action: ApproveAction, Object: "request:" + id, Result: audit.OK,
		Details: map[string]any{"author": a.User, "devices": object(ids), "challenge": c.ID}})
	return map[string]bool{"approved": true}, nil
}
