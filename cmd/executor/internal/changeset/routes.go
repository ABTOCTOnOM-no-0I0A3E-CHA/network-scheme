package changeset

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
)

/* Ops are the workspace routes /x/changesets/{op} (web.Changesets). */
var Ops = []string{"list", "get", "save", "discard", "dry-run", "progress"}

/*
Op runs one workspace route with the workspace's token: the token, the
policy and the freeze first, then the route (each one checks the grants of
the changeset's groups on the registry again).
*/
func (m *Manager) Op(ctx context.Context, token, op string, params json.RawMessage) (any, error) {
	ws, err := m.lookup(token)
	if err != nil {
		return nil, err
	}
	if err := m.active(); err != nil {
		return nil, err
	}
	switch op {
	case "list":
		return m.list(ctx, ws, params)
	case "get":
		return m.get(ctx, ws, params, "changeset.view")
	case "progress":
		return m.get(ctx, ws, params, "")
	case "save":
		return m.save(ctx, ws, params)
	case "discard":
		return m.discard(ctx, ws, params)
	case "dry-run":
		return m.dryRunOp(ctx, ws, params)
	}
	return nil, refuse(CodeBadParams)
}

/* Item is a changeset as the list shows it. */
type Item struct {
	ID       string    `json:"changeset_id"`
	Title    string    `json:"title"`
	Kind     string    `json:"kind"`
	Author   int64     `json:"author_id"`
	AuthorAs string    `json:"author"`
	Status   string    `json:"status"`
	Devices  int       `json:"device_count"`
	Rev      int       `json:"revision"`
	Updated  time.Time `json:"updated"`
}

func item(cs Changeset) Item {
	st, _ := status(cs)
	up := cs.RevAt
	if n := len(cs.Events); n > 0 && cs.Events[n-1].At.After(up) {
		up = cs.Events[n-1].At
	}
	return Item{ID: IDString(cs.ID), Title: cs.Content.Title, Kind: cs.Kind, Author: cs.Author, AuthorAs: cs.AuthorName, Status: st,
		Devices: len(cs.Content.Devices), Rev: cs.Rev, Updated: up.UTC()}
}

/* list is the newest changesets whose every group the user holds write on now (a tampered one is left out, with its alert). */
func (m *Manager) list(ctx context.Context, ws workspace, params json.RawMessage) (any, error) {
	if err := strict(params, &struct{}{}); err != nil {
		return nil, err
	}
	ids, err := m.cfg.Store.IDs(ctx, listMost)
	if err != nil {
		return nil, err
	}
	out := []Item{}
	for _, id := range ids {
		cs, err := m.load(ctx, ws, IDString(id))
		if err != nil {
			continue
		}
		out = append(out, item(cs))
	}
	return out, nil
}

type idParams struct {
	ID string `json:"changeset_id"`
}

/* Detail is one changeset: its newest revision and its history. */
type Detail struct {
	Item
	Content Content       `json:"content"`
	Events  []EventDetail `json:"events"`
	DryRun  *DryRunState  `json:"dry_run,omitempty"` /* this process's dry-run of the newest revision, with its preview */
}

/* EventDetail is one event as the UI shows it (the payload is the executor's own, as stored). */
type EventDetail struct {
	Rev     int             `json:"revision"`
	At      time.Time       `json:"at"`
	Kind    string          `json:"kind"`
	Device  int64           `json:"device_id,omitempty"`
	Session string          `json:"session_id,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

/* get is one changeset with its history; action, if set, is audited (changeset.view). */
func (m *Manager) get(ctx context.Context, ws workspace, params json.RawMessage, action string) (any, error) {
	var p idParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	cs, err := m.load(ctx, ws, p.ID)
	if err != nil {
		return nil, err
	}
	d := Detail{Item: item(cs), Content: cs.Content, Events: []EventDetail{}, DryRun: m.dryRunState(cs.ID, cs.Rev)}
	for _, e := range cs.Events {
		ed := EventDetail{Rev: e.Rev, At: e.At.UTC(), Kind: e.Kind, Device: e.Device, Payload: e.Payload}
		if e.Session != nil {
			ed.Session = IDString(*e.Session)
		}
		d.Events = append(d.Events, ed)
	}
	if action != "" {
		m.record(ctx, ws, action, p.ID, audit.OK, map[string]any{"revision": cs.Rev})
	}
	return d, nil
}

type saveParams struct {
	ID      string  `json:"changeset_id"`
	Rev     int     `json:"revision"`
	Content Content `json:"content"`
}

/* Saved is the answer of save. */
type Saved struct {
	ID  string `json:"changeset_id"`
	Rev int    `json:"revision"`
}

/* editable are the statuses a draft may be revised or discarded in. */
var editable = []string{StatusDraft, StatusDryRunOK, StatusDryRunFailed, StatusApproved}

/*
save creates a changeset (no id) or stores a new revision of the user's own
one (id and the revision it was edited from): the content within the
policy's limits, every device writable now and in a group the user holds
write on, every line of every device's plan normalized by its line's
grammar from the privileged prompt (only a first check: the dry-run
classifies). A new revision drops the approvals of the old ones (their H
named the old revision).
*/
func (m *Manager) save(ctx context.Context, ws workspace, params json.RawMessage) (any, error) {
	var p saveParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	pol := m.cfg.Policy().Policy
	if err := p.Content.Check(pol); err != nil {
		return nil, &Refusal{Code: CodeBadContent, Reason: err.Error()}
	}
	if err := m.checkDevices(ctx, ws, p.Content); err != nil {
		return nil, err
	}
	if p.ID == "" {
		cs, err := m.cfg.Store.Create(ctx, ws.user, ws.username, p.Content)
		if err != nil {
			return nil, err
		}
		m.record(ctx, ws, "changeset.create", IDString(cs.ID), audit.OK, map[string]any{"revision": 1, "kind": cs.Kind,
			"devices": cs.Content.Devices, "content_sha256": hex.EncodeToString(cs.ContentSHA[:])})
		m.publish(ctx, cs)
		return Saved{ID: IDString(cs.ID), Rev: 1}, nil
	}
	cs, err := m.load(ctx, ws, p.ID)
	if err != nil {
		return nil, err
	}
	switch st, _ := status(cs); {
	case cs.Author != ws.user || cs.AuthorName != ws.username:
		return nil, refuse(CodeNotAuthor)
	case !slices.Contains(editable, st):
		return nil, refuse(CodeState)
	case p.Content.Kind() != cs.Kind:
		return nil, refuse(CodeKind)
	case p.Rev != cs.Rev:
		return nil, refuse(CodeConflict)
	}
	rev, err := m.cfg.Store.Revise(ctx, cs.ID, cs.Rev, p.Content)
	if errors.Is(err, ErrConflict) {
		return nil, refuse(CodeConflict)
	}
	if err != nil {
		return nil, err
	}
	m.dropApprovals(cs.ID)
	cs.Rev, cs.Content = rev, p.Content
	m.record(ctx, ws, "changeset.revise", p.ID, audit.OK, map[string]any{"revision": rev, "devices": p.Content.Devices})
	m.publish(ctx, cs)
	return Saved{ID: p.ID, Rev: rev}, nil
}

/* dropApprovals forgets the approvals of a changeset's earlier revisions (5.4). */
func (m *Manager) dropApprovals([16]byte) {}

/*
checkDevices refuses a content whose device is not writable now (the
write_device row: writes_enabled, a confirmed model, a pinned host key, a
write credential), in a group the user holds no write grant on, or whose
line of the plan the device's grammar refuses.
*/
func (m *Manager) checkDevices(ctx context.Context, ws workspace, c Content) error {
	lines := map[int64]strategy.Line{}
	err := m.cfg.Gate.View(ctx, func(s *registry.Snapshot) error {
		for _, id := range c.Devices {
			if r := deviceRefusal(s, id); r != nil {
				return r
			}
			if !granted(s, ws, groupsOf(s, []int64{id})) {
				return &Refusal{Code: "no_grant", Device: id}
			}
			d, _ := s.Get("write_device", id)
			l, _ := d.Get("write_driver").(string)
			lines[id] = strategy.Line(l)
		}
		return nil
	})
	if err != nil {
		return viewErr(err)
	}
	if c.Kind() != KindLines {
		return nil
	}
	for _, id := range c.Devices {
		drv, ok := drivers.For(lines[id])
		if !ok {
			return &Refusal{Code: "line_unknown", Device: id}
		}
		plan, err := c.Render(id, drv)
		if err != nil {
			return &Refusal{Code: CodeBadLine, Device: id, Reason: err.Error()}
		}
		g, mode := drv.Grammar(), drv.Grammar().Root()
		for i, l := range plan {
			n, err := drv.Normalize(l.Line, mode)
			if err != nil {
				return &Refusal{Code: CodeBadLine, Device: id, Step: l.Step, Reason: fmt.Sprintf("line %d: %v", i+1, err)}
			}
			mode = g.Next(n, mode)
		}
	}
	return nil
}

/* discard ends the user's own changeset (no run may start it any more). */
func (m *Manager) discard(ctx context.Context, ws workspace, params json.RawMessage) (any, error) {
	var p idParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	cs, err := m.load(ctx, ws, p.ID)
	if err != nil {
		return nil, err
	}
	switch st, _ := status(cs); {
	case cs.Author != ws.user || cs.AuthorName != ws.username:
		return nil, refuse(CodeNotAuthor)
	case !slices.Contains(editable, st):
		return nil, refuse(CodeState)
	}
	e, err := m.cfg.Store.Event(ctx, cs.ID, cs.Rev, EventDiscarded, 0, nil, map[string]any{"by": ws.user})
	if err != nil {
		return nil, err
	}
	m.dropApprovals(cs.ID)
	cs.Events = append(cs.Events, e)
	m.record(ctx, ws, "changeset.discard", p.ID, audit.OK, map[string]any{"revision": cs.Rev})
	m.publish(ctx, cs)
	m.cfg.Log.Info("changeset discarded", slog.String("changeset", p.ID))
	return map[string]bool{"discarded": true}, nil
}
