package admin

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/devices"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/pub"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* TOTPIssuer names the change TOTP in authenticator apps, apart from the panel's login TOTP. */
const TOTPIssuer = "NMS changes"

/*
Admin runs the commands of the administration socket. Every command, also
a refused or failed one, writes a row of the executor's audit chain: a
registry change declares it in the change's own transaction, anything else
appends it alone. Registry changes go through Guard.HostWrite (verified,
allowed while frozen: the host must be able to revoke during an incident);
core.user is read for display and refusal only (D10).
*/
type Admin struct {
	Guard  *freeze.Guard
	Reg    *registry.Registry
	Keys   *seal.Keys
	Policy *policy.Holder
	Log    *slog.Logger
	/* Lockouts, if set, hears of every committed enroll, unlock and registry reset, so the in-memory TOTP guards follow the host. */
	Lockouts Lockouts
	/* Panel, if set, reports the panel's pending freeze request to freeze off and registry reset (pub.Publisher). */
	Panel PanelRequests
	/* Devices runs the device commands (nil: refused). */
	Devices *devices.Service
	/* writeHook, if set, replaces the result of every host registry write (test seam: an error after a COMMIT). */
	writeHook func(error) error
}

/* PanelRequests reads the panel's pending freeze request (count, the api's claimed requester, time). */
type PanelRequests interface {
	Pending(ctx context.Context) (n int64, by *int64, at *time.Time, err error)
}

/*
panelNote reports a pending panel freeze request before freeze off or
registry reset (into details): without --drop-panel-request it would freeze
the executor again within seconds, so the host is told.
*/
func (a *Admin) panelNote(ctx context.Context, req execadmin.Request, details map[string]any) string {
	if a.Panel == nil || req.DropPanel {
		return ""
	}
	n, by, at, err := a.Panel.Pending(ctx)
	switch {
	case err != nil:
		details["panel_pending"] = "unknown"
		return "\nWARNING: whether the panel asked for a freeze could not be read; a pending request would freeze the executor again (--drop-panel-request discards one)."
	case n == 0:
		return ""
	}
	details["panel_pending"], details["panel_claimed_user_id"], details["panel_requested_at"] = n, by, at
	who := "unknown"
	if by != nil {
		who = fmt.Sprintf("#%d", *by)
	}
	return fmt.Sprintf("\nWARNING: a freeze request from the panel is pending (panel user %s as claimed by the api, at %s): the executor freezes again within seconds. Run again with --drop-panel-request to discard it.",
		who, at.UTC().Format(time.RFC3339))
}

/*
withDrop runs next (the command's audit row) after deleting the panel's
pending freeze requests in the same transaction when the host asked for it
(--drop-panel-request): what was dropped goes into details, hence into the
row. A consumption on its way then finds nothing and freezes nothing.
*/
func withDrop(req execadmin.Request, details map[string]any, next func() registry.Appender) registry.Appender {
	if !req.DropPanel {
		return next()
	}
	return func(ctx context.Context, tx pgx.Tx, head state.AuditHead) (state.AuditHead, error) {
		n, by, at, err := pub.DropRequests(ctx, tx)
		if err != nil {
			return head, err
		}
		details["panel_requests_dropped"], details["panel_claimed_user_id"], details["panel_requested_at"] = n, by, at
		return next()(ctx, tx, head)
	}
}

/* dropText reports the requests withDrop dropped. */
func dropText(req execadmin.Request, details map[string]any) string {
	if !req.DropPanel {
		return ""
	}
	return fmt.Sprintf("\npanel freeze requests dropped: %v", details["panel_requests_dropped"])
}

/*
Lockouts are the in-memory change TOTP guards (authz.Authorizer). Exclusive
runs its function with no decision in progress; ResetUser and ResetGlobal
are called only inside it.
*/
type Lockouts interface {
	Exclusive(fn func())
	ResetUser(id int64)
	ResetGlobal()
}

/*
exclusive runs a command that changes lockouts (enroll, unlock, registry
reset) with no change TOTP decision in progress, so its registry change and
the reset of the in-memory guards are one step for the decisions: none
evaluates the new registry against the old memory and writes a lock back.
*/
func (a *Admin) exclusive(fn func() execadmin.Response) execadmin.Response {
	if a.Lockouts == nil {
		return fn()
	}
	var resp execadmin.Response
	a.Lockouts.Exclusive(func() { resp = fn() })
	return resp
}

/* resetUser and resetGlobal tell Lockouts, if set, that the host reset a user's lockout or the global window (inside exclusive). */
func (a *Admin) resetUser(id int64) {
	if a.Lockouts != nil {
		a.Lockouts.ResetUser(id)
	}
}

func (a *Admin) resetGlobal() {
	if a.Lockouts != nil {
		a.Lockouts.ResetGlobal()
	}
}

/* hostWrite is Guard.HostWrite, through writeHook. */
func (a *Admin) hostWrite(ctx context.Context, fn func(ctx context.Context, s *registry.Snapshot, tx *registry.Tx) error) error {
	err := a.Guard.HostWrite(ctx, fn)
	if a.writeHook != nil {
		err = a.writeHook(err)
	}
	return err
}

/* refusal is a command refused by a rule (audit result "denied"), not a failure. */
type refusal struct{ msg string }

func (r refusal) Error() string { return r.msg }

func deny(format string, a ...any) error { return refusal{fmt.Sprintf(format, a...)} }

/* event is the audit row of a command. */
func (a *Admin) event(req execadmin.Request, object, result string, details map[string]any) audit.Event {
	d := map[string]any{"operator": req.Operator}
	for k, v := range details {
		d[k] = v
	}
	action := "admin." + req.Cmd
	if req.Action != "" {
		action += "." + req.Action
	}
	return audit.Event{UA: "nmsctl", Action: action, Object: object, Result: result, Details: d}
}

/* record appends ev alone; tampering with the chain freezes. */
func (a *Admin) record(ctx context.Context, ev audit.Event) error {
	err := a.Reg.Append(ctx, audit.Append(ev))
	if errors.Is(err, registry.ErrTampered) {
		a.Guard.Trigger(ctx, freeze.KindTamper, err.Error())
	}
	if err != nil {
		a.Log.Error("executor audit: cannot record", slog.String("action", ev.Action), slog.Any("err", err))
	}
	return err
}

/* done records a command that did not change the registry and answers with text. */
func (a *Admin) done(ctx context.Context, req execadmin.Request, object, text string, details map[string]any) execadmin.Response {
	if err := a.record(ctx, a.event(req, object, audit.OK, details)); err != nil {
		return execadmin.Response{Text: text, Error: "the command ran but its audit row was not written: " + err.Error()}
	}
	return execadmin.Response{OK: true, Text: text}
}

/* refuse records a refused (rule) or failed (anything else) command and answers with the error. */
func (a *Admin) refuse(ctx context.Context, req execadmin.Request, object string, err error, details map[string]any) execadmin.Response {
	result := audit.Error
	if errors.As(err, new(refusal)) || errors.Is(err, freeze.ErrFrozen) {
		result = audit.Denied
	}
	d := map[string]any{"error": state.Reason(err.Error())}
	for k, v := range details {
		d[k] = v
	}
	_ = a.record(ctx, a.event(req, object, result, d))
	return execadmin.Response{Error: err.Error()}
}

/* Refused records a connection the server refused before reading a request. */
func (a *Admin) Refused(ctx context.Context, reason string, uid int) {
	_ = a.record(ctx, audit.Event{UA: "nmsctl", Action: "admin.connection", Object: "socket", Result: audit.Denied,
		Details: map[string]any{"error": reason, "peer_uid": uid}})
}

/*
PolicyChanged records a change of the enforced policy (start, reload by
mtime) and alerts when the new file is invalid: the executor is disabled
until a valid one appears (security.md 5.5).
*/
func (a *Admin) PolicyChanged(ctx context.Context, cause string, old, cur policy.State) {
	result := audit.OK
	details := map[string]any{"cause": cause, "sha256": hex.EncodeToString(cur.Sum[:]), "valid": cur.Err == nil,
		"enabled": cur.Enabled(), "old_sha256": hex.EncodeToString(old.Sum[:]), "old_enabled": old.Enabled()}
	if cur.Err != nil {
		result, details["error"] = audit.Error, cur.Err.Error()
		a.Guard.Alert(ctx, freeze.KindPolicyInvalid, "high", "executor policy invalid, executor disabled: "+cur.Err.Error())
	}
	_ = a.record(ctx, audit.Event{Action: "executor.policy", Object: "policy", Result: result, Details: details})
}

/* Handle runs one request. */
func (a *Admin) Handle(ctx context.Context, req execadmin.Request) execadmin.Response {
	if err := req.Validate(); err != nil {
		cmd, op := req.Cmd, req.Operator
		if len(cmd) > 64 || !utf8.ValidString(cmd) {
			cmd = "?"
		}
		if (execadmin.Request{V: execadmin.Version, Cmd: execadmin.CmdAuditVerify, Operator: op}).Validate() != nil {
			op = "?"
		}
		return a.refuse(ctx, execadmin.Request{Cmd: "request", Operator: op}, "", deny("%v", err), map[string]any{"cmd": cmd})
	}
	switch req.Cmd {
	case execadmin.CmdPolicyShow, execadmin.CmdPolicyCheck, execadmin.CmdPolicyReload:
		return a.policyCmd(ctx, req)
	case execadmin.CmdEnroll:
		return a.exclusive(func() execadmin.Response { return a.enroll(ctx, req) })
	case execadmin.CmdGrant:
		return a.grant(ctx, req)
	case execadmin.CmdRevoke:
		return a.revoke(ctx, req)
	case execadmin.CmdFreezeOn:
		a.Guard.Trigger(ctx, freeze.KindHostFreeze, "host: "+req.Reason)
		return a.done(ctx, req, "executor", "executor frozen", map[string]any{"reason": req.Reason})
	case execadmin.CmdFreezeOff:
		return a.freezeOff(ctx, req)
	case execadmin.CmdUnlock:
		return a.exclusive(func() execadmin.Response { return a.unlock(ctx, req) })
	case execadmin.CmdModelVerify:
		return a.modelVerify(ctx, req)
	case execadmin.CmdRegistryVerify:
		return a.registryVerify(ctx, req)
	case execadmin.CmdRegistryReset:
		return a.exclusive(func() execadmin.Response { return a.registryReset(ctx, req) })
	case execadmin.CmdAuditVerify:
		return a.auditVerify(ctx, req)
	default: /* execadmin.CmdDevice */
		return a.device(ctx, req)
	}
}

/* policyCmd shows, checks or (after the host changed the file) reloads the policy. */
func (a *Admin) policyCmd(ctx context.Context, req execadmin.Request) execadmin.Response {
	old, cur, changed := a.Policy.Reload(req.Cmd != execadmin.CmdPolicyShow)
	if changed {
		a.PolicyChanged(ctx, req.Cmd, old, cur)
	}
	details := map[string]any{"sha256": hex.EncodeToString(cur.Sum[:]), "valid": cur.Err == nil, "enabled": cur.Enabled(),
		"old_sha256": hex.EncodeToString(old.Sum[:]), "old_enabled": old.Enabled()}
	body, err := execpolicy.Marshal(cur.Policy)
	if err != nil {
		return a.refuse(ctx, req, "policy", err, details)
	}
	text := fmt.Sprintf("policy sha256 %x\nvalid: %v\nexecutor enabled: %v\n", cur.Sum, cur.Err == nil, cur.Enabled())
	if cur.Err != nil {
		text += "error: " + cur.Err.Error() + "\n"
	}
	if req.Cmd == execadmin.CmdPolicyShow {
		text += "---\n" + string(body)
	}
	switch {
	case cur.Err != nil && req.Cmd != execadmin.CmdPolicyShow:
		return a.refuse(ctx, req, "policy", fmt.Errorf("the executor reads an invalid policy (it is disabled): %w", cur.Err), details)
	case req.Action == "enable" && !cur.Enabled(), req.Action == "disable" && cur.Enabled():
		return a.refuse(ctx, req, "policy", fmt.Errorf("the executor still reads enabled=%v (is deploy/policies mounted as a directory?)", cur.Enabled()), details)
	}
	return a.done(ctx, req, "policy", text, details)
}

/* panelUser reads one panel user by id or by name (core.user: display and refusal only). */
func (a *Admin) panelUser(ctx context.Context, id int64, name string) (execadmin.User, bool, error) {
	var u execadmin.User
	found := false
	err := a.Reg.Read(ctx, registry.OpTimeout, func(ctx context.Context, tx pgx.Tx) error {
		q, arg := `SELECT id, username, created_at, disabled FROM core."user" WHERE username = $1`, any(name)
		if id != 0 {
			q, arg = `SELECT id, username, created_at, disabled FROM core."user" WHERE id = $1`, id
		}
		err := tx.QueryRow(ctx, q, arg).Scan(&u.ID, &u.Username, &u.CreatedAt, &u.Disabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		found = err == nil
		return err
	})
	return u, found, err
}

/*
bindUser resolves the user of a binding command (enroll, grant). Without
UserID it is the preview: the user found by name or #id. With UserID it is
the confirmation: that id must still carry the confirmed name and creation
date (D10: the api may rename users or re-create one under the same id; the
host confirmed id, name and creation date). A missing or disabled user, or a
name a snapshot cannot hold, is refused.
*/
func (a *Admin) bindUser(ctx context.Context, req execadmin.Request) (execadmin.User, error) {
	id, name, _ := req.UserRef()
	if req.UserID != 0 {
		if name == "" {
			return execadmin.User{}, deny("the confirmation must name the user")
		}
		id = req.UserID
	}
	u, ok, err := a.panelUser(ctx, id, name)
	switch {
	case err != nil:
		return u, err
	case !ok:
		return u, deny("no panel user %s", req.User)
	case req.UserID != 0 && (u.Username != name || !u.CreatedAt.Equal(req.UserCreated)):
		return u, deny("user #%d is now %q created %s, not the confirmed %q: run the command again", u.ID, u.Username,
			u.CreatedAt.UTC().Format(time.RFC3339), name)
	case u.Disabled:
		return u, deny("panel user %q is disabled", u.Username)
	case utf8.RuneCountInString(u.Username) > 64:
		return u, deny("panel user names longer than 64 characters cannot be bound")
	}
	return u, nil
}

/* view reads the verified registry (also while frozen); tampering freezes. */
func (a *Admin) view(ctx context.Context, fn func(*registry.Snapshot) error) error {
	err := a.Reg.View(ctx, fn)
	if errors.Is(err, registry.ErrTampered) {
		a.Guard.Trigger(ctx, freeze.KindTamper, err.Error())
		return fmt.Errorf("%w: %v", freeze.ErrFrozen, err)
	}
	return err
}

func userObject(id int64) string { return fmt.Sprintf("user:%d", id) }

/*
after answers a host registry write that returned err. A refusal or a
freeze is answered as such. Any other error leaves the outcome unknown
(registry.Write: the COMMIT may have succeeded), so the registry is read
again and applied says whether the change is there: then the command
succeeded (ok, and the answer is recorded as such), else it is refused; if
the registry cannot be read now, the answer says the outcome is unknown.
*/
func (a *Admin) after(ctx context.Context, req execadmin.Request, obj string, err error, details map[string]any,
	applied func(*registry.Snapshot) bool) (execadmin.Response, bool) {
	if errors.As(err, new(refusal)) || errors.Is(err, freeze.ErrFrozen) {
		return a.refuse(ctx, req, obj, err, details), false
	}
	there := false
	if verr := a.view(ctx, func(s *registry.Snapshot) error { there = applied(s); return nil }); verr != nil {
		return a.refuse(ctx, req, obj, fmt.Errorf("outcome unknown (%v): the registry cannot be read now: %v", err, verr), details), false
	}
	if !there {
		return a.refuse(ctx, req, obj, fmt.Errorf("not applied: %w", err), details), false
	}
	details["confirmed_after"] = state.Reason(err.Error())
	return a.done(ctx, req, obj, "", details), true
}

func userDetails(u execadmin.User) map[string]any {
	return map[string]any{"user_id": u.ID, "username": u.Username, "created_at": u.CreatedAt}
}

/*
enroll binds a new change TOTP secret to a panel user (security.md 5.2): the
daemon generates it, seals it with AAD user_id|change-totp|key_version and
answers once with the otpauth URI. An enrolled user is re-enrolled only with
Replace.
*/
func (a *Admin) enroll(ctx context.Context, req execadmin.Request) execadmin.Response {
	u, err := a.bindUser(ctx, req)
	if err != nil {
		return a.refuse(ctx, req, "user", err, map[string]any{"user": req.User})
	}
	obj, details := userObject(u.ID), userDetails(u)
	details["replace"] = req.Replace
	enrolled := func(s *registry.Snapshot) error {
		if _, ok := s.Get("change_totp", u.ID); ok && !req.Replace {
			return deny("panel user %q already has a change TOTP: --replace overwrites it", u.Username)
		}
		return nil
	}
	if req.UserID == 0 {
		if err := a.view(ctx, enrolled); err != nil {
			return a.refuse(ctx, req, obj, err, details)
		}
		details["step"] = "preview"
		resp := a.done(ctx, req, obj, "", details)
		resp.Confirm = &u
		return resp
	}
	sec, uri, err := auth.NewTOTPSecret(TOTPIssuer, u.Username)
	if err != nil {
		return a.refuse(ctx, req, obj, err, details)
	}
	defer sec.Wipe()
	ct, err := a.Keys.SealTOTP(u.ID, seal.KeyVersion, []byte(sec.Reveal()))
	if err != nil {
		return a.refuse(ctx, req, obj, err, details)
	}
	err = a.hostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		if err := enrolled(s); err != nil {
			return err
		}
		_, existed := s.Get("change_totp", u.ID)
		details["existed"] = existed
		tx.Audit(audit.Append(a.event(req, obj, audit.OK, details)))
		return tx.Put("change_totp", map[string]any{"user_id": u.ID, "username_snapshot": u.Username, "ciphertext": ct,
			"key_version": seal.KeyVersion, "last_step": 0, "failures": 0, "lock_until": nil, "lock_count": 0})
	})
	resp := execadmin.Response{OK: true}
	if err != nil {
		var ok bool
		if resp, ok = a.after(ctx, req, obj, err, details, func(s *registry.Snapshot) bool {
			r, ok := s.Get("change_totp", u.ID)
			if !ok {
				return false
			}
			got, _ := r.Get("ciphertext").([]byte)
			return bytes.Equal(got, ct)
		}); !ok {
			return resp
		}
	}
	a.resetUser(u.ID)
	resp.Text = fmt.Sprintf("change TOTP enrolled for %q (#%d)", u.Username, u.ID)
	resp.Enrollment = &execadmin.Enrollment{URI: uri, Secret: sec.Reveal()}
	return resp
}

/* grantKey is the key of a write_grant row (the group only for write). */
func grantKey(req execadmin.Request) (kind string, group any) {
	if req.Kind == execadmin.KindWrite {
		return req.Kind, req.Group
	}
	return req.Kind, nil
}

/* grant gives a panel user a grant (two steps, as enroll); an existing grant gets the new name snapshot. */
func (a *Admin) grant(ctx context.Context, req execadmin.Request) execadmin.Response {
	u, err := a.bindUser(ctx, req)
	if err != nil {
		return a.refuse(ctx, req, "user", err, map[string]any{"user": req.User, "kind": req.Kind, "group": req.Group})
	}
	obj, details := userObject(u.ID), userDetails(u)
	details["kind"], details["group"] = req.Kind, req.Group
	if req.UserID == 0 {
		details["step"] = "preview"
		resp := a.done(ctx, req, obj, "", details)
		resp.Confirm = &u
		return resp
	}
	kind, group := grantKey(req)
	err = a.hostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		_, existed := s.Get("write_grant", u.ID, kind, group)
		details["existed"] = existed
		tx.Audit(audit.Append(a.event(req, obj, audit.OK, details)))
		return tx.Put("write_grant", map[string]any{"user_id": u.ID, "kind": kind, "write_group": group, "username_snapshot": u.Username})
	})
	resp := execadmin.Response{OK: true}
	if err != nil {
		var ok bool
		if resp, ok = a.after(ctx, req, obj, err, details, func(s *registry.Snapshot) bool {
			r, ok := s.Get("write_grant", u.ID, kind, group)
			return ok && r.Get("username_snapshot") == u.Username
		}); !ok {
			return resp
		}
	}
	what := kind
	if group != nil {
		what += " " + req.Group
	}
	resp.Text = fmt.Sprintf("granted %s to %q (#%d)", what, u.Username, u.ID)
	return resp
}

/*
target finds the user a revoke or unlock means without binding anyone: "#id",
or the one id whose rows in table carry the name snapshot, or (panel, for a
revoke only: removing a right) that core.user gives the name. An unlock
gives something back, so it never trusts the api's name for an id. Two ids
for one name are ambiguous.
*/
func (a *Admin) target(ctx context.Context, req execadmin.Request, table string, panel bool) (int64, error) {
	id, name, _ := req.UserRef()
	if id != 0 {
		return id, nil
	}
	var ids []int64
	if err := a.view(ctx, func(s *registry.Snapshot) error {
		for _, r := range s.Rows(table) {
			if uid, _ := r.Get("user_id").(int64); r.Get("username_snapshot") == name && !slices.Contains(ids, uid) {
				ids = append(ids, uid)
			}
		}
		return nil
	}); err != nil {
		return 0, err
	}
	if panel {
		if u, ok, err := a.panelUser(ctx, 0, name); err == nil && ok && !slices.Contains(ids, u.ID) {
			ids = append(ids, u.ID)
		}
	}
	switch len(ids) {
	case 0:
		return 0, deny("no user %q in the registry", name)
	case 1:
		return ids[0], nil
	}
	slices.Sort(ids)
	return 0, deny("%q names several users %v: give #id", name, ids)
}

/*
revoke removes one grant or all of a user's. An error other than tampering
leaves the outcome unknown (registry.Write): the registry is read again and
the answer says what it holds now, never "still granted" from the error alone.
*/
func (a *Admin) revoke(ctx context.Context, req execadmin.Request) execadmin.Response {
	id, err := a.target(ctx, req, "write_grant", true)
	if err != nil {
		return a.refuse(ctx, req, "user", err, map[string]any{"user": req.User})
	}
	obj := userObject(id)
	kind, group := grantKey(req)
	matches := func(r registry.Row) bool {
		return r.Get("user_id") == id && (req.All || (r.Get("kind") == kind && r.Get("write_group") == group))
	}
	details := map[string]any{"user_id": id, "kind": req.Kind, "group": req.Group, "all": req.All}
	var revoked []string
	err = a.hostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		revoked = nil
		for _, r := range s.Rows("write_grant") {
			if !matches(r) {
				continue
			}
			k, g := r.Get("kind").(string), r.Get("write_group")
			if err := tx.Delete("write_grant", id, k, g); err != nil {
				return err
			}
			if g != nil {
				k += " " + g.(string)
			}
			revoked = append(revoked, k)
		}
		if len(revoked) == 0 {
			return deny("user #%d has no such grant", id)
		}
		details["revoked"] = revoked
		tx.Audit(audit.Append(a.event(req, obj, audit.OK, details)))
		return nil
	})
	switch {
	case err == nil:
		return execadmin.Response{OK: true, Text: fmt.Sprintf("revoked from #%d: %s", id, strings.Join(revoked, ", "))}
	case errors.As(err, new(refusal)), errors.Is(err, freeze.ErrFrozen):
		return a.refuse(ctx, req, obj, err, details)
	}
	left := -1
	if verr := a.view(ctx, func(s *registry.Snapshot) error {
		left = 0
		for _, r := range s.Rows("write_grant") {
			if matches(r) {
				left++
			}
		}
		return nil
	}); verr != nil {
		err = fmt.Errorf("revoke: outcome unknown (%v); the registry cannot be read now: %v", err, verr)
	} else if left == 0 {
		details["confirmed_after"] = err.Error()
		return a.done(ctx, req, obj, fmt.Sprintf("revoked from #%d (confirmed after an error: %v)", id, err), details)
	} else {
		err = fmt.Errorf("revoke failed (%v): the registry still holds %d matching grant(s)", err, left)
	}
	return a.refuse(ctx, req, obj, err, details)
}

/*
freezeOff lifts the freeze only if the whole audit chain verifies against
its anchor and then the registry verifies (freeze.Guard.FreezeOff); the
audit row goes with exec_state. A broken chain cannot be repaired (append
only): only a registry reset gets out of that freeze.
*/
func (a *Admin) freezeOff(ctx context.Context, req execadmin.Request) execadmin.Response {
	_, reason := a.Guard.Frozen()
	details := map[string]any{"reason": req.Reason, "was": reason, "drop_panel_request": req.DropPanel}
	note := a.panelNote(ctx, req, details)
	check := func(ctx context.Context) error {
		res, _, err := a.chain(ctx)
		switch {
		case err != nil:
			return fmt.Errorf("the audit chain cannot be verified now: %w", err)
		case res.Break != nil:
			return a.broken(ctx, res.Break)
		}
		return nil
	}
	err := a.Guard.FreezeOff(ctx, check, func(tx *registry.Tx) error {
		tx.Audit(withDrop(req, details, func() registry.Appender { return audit.Append(a.event(req, "executor", audit.OK, details)) }))
		return nil
	})
	if err != nil {
		return a.refuse(ctx, req, "executor", err, details)
	}
	return execadmin.Response{OK: true, Text: "freeze lifted: the audit chain and the registry verified" + dropText(req, details) + note}
}

/* unlock clears a user's change TOTP failures and lockouts, or (Global) the global failure window. */
func (a *Admin) unlock(ctx context.Context, req execadmin.Request) execadmin.Response {
	if req.Global {
		details := map[string]any{"global": true}
		err := a.hostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
			st, ok := s.Get("exec_state", true)
			if !ok {
				return deny("exec_state missing")
			}
			tx.Audit(audit.Append(a.event(req, "executor", audit.OK, details)))
			return tx.Put("exec_state", map[string]any{"singleton": true, "freeze": st.Get("freeze"),
				"freeze_reason": st.Get("freeze_reason"), "global_fail_window": []byte("[]")})
		})
		resp := execadmin.Response{OK: true}
		if err != nil {
			var ok bool
			if resp, ok = a.after(ctx, req, "executor", err, details, func(s *registry.Snapshot) bool {
				st, ok := s.Get("exec_state", true)
				if !ok {
					return false
				}
				w, _ := st.Get("global_fail_window").(json.RawMessage)
				return string(w) == "[]"
			}); !ok {
				return resp
			}
		}
		a.resetGlobal()
		resp.Text = "global change TOTP failure window cleared"
		return resp
	}
	id, err := a.target(ctx, req, "change_totp", false)
	if err != nil {
		return a.refuse(ctx, req, "user", err, map[string]any{"user": req.User})
	}
	obj, details := userObject(id), map[string]any{"user_id": id}
	err = a.hostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		r, ok := s.Get("change_totp", id)
		if !ok {
			return deny("user #%d has no change TOTP", id)
		}
		details["failures"], details["lock_count"] = r.Get("failures"), r.Get("lock_count")
		tx.Audit(audit.Append(a.event(req, obj, audit.OK, details)))
		return tx.Put("change_totp", map[string]any{"user_id": id, "username_snapshot": r.Get("username_snapshot"),
			"ciphertext": r.Get("ciphertext"), "key_version": r.Get("key_version"), "last_step": r.Get("last_step"),
			"failures": 0, "lock_until": nil, "lock_count": 0})
	})
	resp := execadmin.Response{OK: true}
	if err != nil {
		var ok bool
		if resp, ok = a.after(ctx, req, obj, err, details, func(s *registry.Snapshot) bool {
			r, ok := s.Get("change_totp", id)
			return ok && r.Get("failures") == int64(0) && r.Get("lock_count") == int64(0) && r.Get("lock_until") == nil
		}); !ok {
			return resp
		}
	}
	a.resetUser(id)
	resp.Text = fmt.Sprintf("change TOTP of #%d unlocked", id)
	return resp
}

/* maxStrategies bounds the strategies document (the CHECK of the model profiles table). */
const maxStrategies = 16384

/* anchored makes a pattern match the whole model or firmware string, never a part of it. */
func anchored(re string) string { return "^(?:" + re + ")$" }

/*
modelVerify records a model and firmware line confirmed on the stand (the
model profiles of the registry, security.md 5.1a). Both patterns are stored
anchored (^(?:RE)$): they match the whole string show version gives, so
"MES2424" never also covers "MES2424P". The same driver and patterns
replace their profile, anything else is a new one. It only records; the
transport applies profiles and refuses unknown strategy keys (task 4b.5).
*/
func (a *Admin) modelVerify(ctx context.Context, req execadmin.Request) execadmin.Response {
	model, firmware := anchored(req.Model), anchored(req.Firmware)
	details := map[string]any{"driver": req.Driver, "model": model, "firmware": firmware, "note": req.Note, "strategies": req.Strategies}
	for _, re := range []string{model, firmware} {
		if _, err := regexp.Compile(re); err != nil {
			return a.refuse(ctx, req, "model_profile", deny("bad pattern %q: %v", re, err), details)
		}
	}
	strategies := map[string]string{}
	for k, v := range req.Strategies {
		strategies[k] = v
	}
	doc, err := json.Marshal(strategies)
	if err != nil || len(doc) > maxStrategies {
		return a.refuse(ctx, req, "model_profile", deny("strategies: at most %d bytes", maxStrategies), details)
	}
	var id int64
	err = a.hostWrite(ctx, func(_ context.Context, s *registry.Snapshot, tx *registry.Tx) error {
		id = 1
		for _, r := range s.Rows("model_profile") {
			pid, _ := r.Get("id").(int64)
			if r.Get("write_driver") == req.Driver && r.Get("model_re") == model && r.Get("firmware_re") == firmware {
				id = pid
				break
			}
			id = max(id, pid+1)
		}
		details["id"] = id
		tx.Audit(audit.Append(a.event(req, fmt.Sprintf("model_profile:%d", id), audit.OK, details)))
		return tx.Put("model_profile", map[string]any{"id": id, "write_driver": req.Driver, "model_re": model,
			"firmware_re": firmware, "strategies": json.RawMessage(doc), "note": req.Note})
	})
	resp := execadmin.Response{OK: true}
	if err != nil {
		var ok bool
		if resp, ok = a.after(ctx, req, "model_profile", err, details, func(s *registry.Snapshot) bool {
			r, ok := s.Get("model_profile", id)
			if !ok {
				return false
			}
			got, _ := r.Get("strategies").(json.RawMessage)
			return r.Get("model_re") == model && r.Get("firmware_re") == firmware && r.Get("note") == req.Note && bytes.Equal(got, doc)
		}); !ok {
			return resp
		}
	}
	resp.Text = fmt.Sprintf("model profile #%d recorded for %s (%s / %s)", id, req.Driver, model, firmware)
	return resp
}

/* registryVerify verifies the whole registry now and reports it; tampering freezes. */
func (a *Admin) registryVerify(ctx context.Context, req execadmin.Request) execadmin.Response {
	rep, err := a.Reg.Verify(ctx)
	latched, why := a.Guard.Frozen()
	details := map[string]any{"seq": rep.Seq, "frozen": rep.Frozen || latched}
	if errors.Is(err, registry.ErrTampered) {
		a.Guard.Trigger(ctx, freeze.KindTamper, err.Error())
		return a.refuse(ctx, req, "registry", fmt.Errorf("%w: the registry does not verify: %v", freeze.ErrFrozen, err), details)
	}
	if err != nil {
		return a.refuse(ctx, req, "registry", fmt.Errorf("the registry cannot be verified now: %w", err), details)
	}
	text := fmt.Sprintf("registry verified at counter %d", rep.Seq)
	switch {
	case rep.Frozen:
		text += fmt.Sprintf("; frozen: %s", rep.Reason)
	case latched:
		text += fmt.Sprintf("; frozen in this process: %s", why)
	default:
		text += "; not frozen"
	}
	return a.done(ctx, req, "registry", text, details)
}

/* registryReset is the way out of a freeze after tampering (registry.Reset); it needs IUnderstand. */
func (a *Admin) registryReset(ctx context.Context, req execadmin.Request) execadmin.Response {
	if !req.IUnderstand {
		return a.refuse(ctx, req, "registry", deny("registry reset revokes every grant, removes every change TOTP and model profile, disables writes and clears host keys on every device: confirm with --i-understand"), nil)
	}
	details := map[string]any{}
	note := a.panelNote(ctx, req, details)
	pending := details
	var plan audit.Plan
	rep, err := a.Guard.Reset(ctx, registry.ResetOptions{
		Plan: func(ctx context.Context, tx pgx.Tx, old state.Chain, known bool, tail state.AuditHead) (state.Chain, error) {
			var err error
			plan, err = audit.PlanReset(ctx, tx, old, known, tail)
			return plan.Chain, err
		},
		Audit: func(rep registry.ResetReport) registry.Appender {
			/* Hashes, not only ids: this row is itself chained, so what the reset vouched for cannot be rewritten later. */
			details = map[string]any{"seq": rep.Seq, "grants_revoked": rep.Grants, "totp_removed": rep.TOTPs,
				"devices": rep.Devices, "dropped": rep.Dropped, "profiles_removed": rep.Profiles, "write_credentials_removed": rep.Credentials,
				"state_file_readable": rep.Known, "audit_intact": plan.Intact, "audit_unanchored": plan.Unanchored,
				"audit_old_anchor": rep.OldAnchor.LastID, "audit_old_anchor_hash": hex.EncodeToString(rep.OldAnchor.Hash),
				"audit_vouched": vouchedDetails(plan.Vouched), "audit_may_be_forged": plan.Suspect,
				"audit_tail": rep.Tail.LastID, "audit_tail_hash": hex.EncodeToString(rep.Tail.Hash),
				"audit_base": rep.Chain.Base.LastID, "audit_sealed": len(rep.Chain.Sealed), "drop_panel_request": req.DropPanel}
			if plan.Break != nil {
				details["audit_break_id"], details["audit_break"] = plan.Break.ID, plan.Break.Reason
			}
			for k, v := range pending {
				details[k] = v
			}
			return withDrop(req, details, func() registry.Appender { return audit.Append(a.event(req, "registry", audit.OK, details)) })
		},
	})
	if err != nil {
		return a.refuse(ctx, req, "registry", err, details)
	}
	a.resetGlobal()
	return execadmin.Response{OK: true, Text: resetText(rep, plan) + dropText(req, details) + note}
}

/* vouchedDetails are the vouched ranges with their endpoint hashes, for the reset's audit row. */
func vouchedDetails(segs []state.Segment) []map[string]any {
	out := make([]map[string]any, 0, len(segs))
	for _, g := range segs {
		out = append(out, map[string]any{"after": g.From.LastID, "after_hash": hex.EncodeToString(g.From.Hash),
			"to": g.To.LastID, "to_hash": hex.EncodeToString(g.To.Hash)})
	}
	return out
}

/* resetText is the report of a registry reset for the host. */
func resetText(rep registry.ResetReport, plan audit.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "registry reset at counter %d: %d grant(s) revoked, %d change TOTP enrollment(s) removed (enroll again), %d model profile(s) removed; freeze lifted.\n",
		rep.Seq, rep.Grants, rep.TOTPs, rep.Profiles)
	switch {
	case !rep.Known:
		fmt.Fprintf(&b, "AUDIT: the state file was unreadable, so no trusted hash vouches for the audit history: every row up to #%d may be forged.\n", rep.Tail.LastID)
	case plan.Break != nil:
		fmt.Fprintf(&b, "AUDIT HISTORY REWRITTEN OR TRUNCATED (first at #%d: %s; the anchor was #%d).\n", plan.Break.ID, plan.Break.Reason, rep.OldAnchor.LastID)
	case plan.Unanchored == 0:
		fmt.Fprintf(&b, "Audit chain intact up to its anchor #%d.\n", rep.OldAnchor.LastID)
	}
	for _, r := range plan.Suspect {
		if rep.Known {
			fmt.Fprintf(&b, "  rows after #%d up to #%d may be forged (no trusted hash proves them)\n", r.From, r.To)
		}
	}
	for _, g := range plan.Vouched {
		fmt.Fprintf(&b, "  rows after #%d up to #%d are proven by the trusted hash of #%d and stay sealed\n", g.From.LastID, g.To.LastID, g.To.LastID)
	}
	if plan.Unanchored > 0 && rep.Known {
		fmt.Fprintf(&b, "AUDIT: %d row(s) after the anchor #%d are not anchored: nothing vouches for them.\n", plan.Unanchored, rep.OldAnchor.LastID)
	}
	fmt.Fprintf(&b, "The audit chain continues from #%d; its live part is verified from #%d on, %d sealed segment(s) before.\n",
		rep.Tail.LastID, rep.Chain.Base.LastID, len(rep.Chain.Sealed))
	if len(rep.Dropped) > 0 {
		fmt.Fprintf(&b, "Removed (MAC did not verify), register again: %s\n", strings.Join(rep.Dropped, ", "))
	}
	if len(rep.Credentials) > 0 {
		fmt.Fprintf(&b, "%d write credential(s) removed, enter each again through /x:\n", len(rep.Credentials))
		for _, c := range rep.Credentials {
			fmt.Fprintf(&b, "  write credential of device %d (created %s, not confirmed)\n", c.DeviceID, c.CreatedAt.UTC().Format(time.RFC3339))
		}
	}
	fmt.Fprintf(&b, "%d device(s) kept with writes disabled and no host key. None of these fields is confirmed: check each before the device is used again:\n", len(rep.Devices))
	for _, d := range rep.Devices {
		fmt.Fprintf(&b, "  device %d  address %s  port %d  protocol %s  group %s  driver %s\n", d.ID, d.Address, d.Port, d.Protocol, d.Group, d.Driver)
	}
	return b.String()
}

/* auditReadTimeout bounds one full verification of the audit chain. */
const auditReadTimeout = 10 * time.Minute

/* chain verifies the audit chain against what the state file says (sealed segments, base, anchor). */
func (a *Admin) chain(ctx context.Context) (audit.Result, state.AuditHead, error) {
	c, err := a.Reg.AuditChain()
	if errors.Is(err, registry.ErrTampered) {
		a.Guard.Trigger(ctx, freeze.KindTamper, err.Error())
	}
	if err != nil {
		return audit.Result{}, c.Anchor, err
	}
	var res audit.Result
	err = a.Reg.Read(ctx, auditReadTimeout, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		res, err = audit.Verify(ctx, tx, c)
		return err
	})
	return res, c.Anchor, err
}

/* broken freezes on a break of the audit chain and returns the refusal. */
func (a *Admin) broken(ctx context.Context, b *audit.Break) error {
	reason := fmt.Sprintf("executor audit chain broken at #%d: %s", b.ID, b.Reason)
	a.Guard.Trigger(ctx, freeze.KindTamper, reason)
	return fmt.Errorf("%w: %s (only nmsctl executor registry reset gets out of this freeze)", freeze.ErrFrozen, reason)
}

/* auditVerify verifies the whole audit chain against the anchor of the state file; a break freezes (security.md 10). */
func (a *Admin) auditVerify(ctx context.Context, req execadmin.Request) execadmin.Response {
	res, anchor, err := a.chain(ctx)
	if err != nil {
		return a.refuse(ctx, req, "audit", fmt.Errorf("the audit chain cannot be verified now: %w", err), nil)
	}
	details := map[string]any{"count": res.Count, "unanchored": res.Unanchored, "unverified": res.Unverified,
		"last_id": res.LastID, "anchor": anchor.LastID}
	if res.Break != nil {
		details["break_id"], details["break"] = res.Break.ID, res.Break.Reason
		return a.refuse(ctx, req, "audit", a.broken(ctx, res.Break), details)
	}
	text := fmt.Sprintf("executor audit chain intact: %d row(s) verified up to the state file's anchor #%d", res.Count, anchor.LastID)
	if res.Unanchored > 0 {
		text += fmt.Sprintf("; %d row(s) after the anchor not yet anchored (a change in flight, or rows nothing vouches for)", res.Unanchored)
	}
	if res.Unverified > 0 {
		text += fmt.Sprintf("; %d row(s) outside the verified ranges (cut off by a registry reset)", res.Unverified)
	}
	return a.done(ctx, req, "audit", text, details)
}
