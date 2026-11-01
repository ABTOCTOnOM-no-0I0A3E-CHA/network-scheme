package authz

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
)

/*
The in-memory guards (per-user lockout state and the global failure window)
also live in a file of their own next to the state file, MACed with the
state subkey and replaced atomically: what only memory knew (a failure or a
used step whose registry write failed or whose outcome is unknown) survives
a restart, so restarting the executor never resets the guess budget. It is
written after every evaluated decision and every host reset, and merged
back at start the same strict way as memory and registry are.
*/
const (
	guardsLabel    = "authz-guards"
	guardsVersion  = 1
	maxGuardsBytes = 1 << 20
)

type guardUser struct {
	ID        int64 `json:"id"`
	LastStep  int64 `json:"last_step"`
	Failures  int64 `json:"failures"`
	LockCount int64 `json:"lock_count"`
	LockUntil int64 `json:"lock_until"` /* Unix microseconds, 0: none */
	/* PrevStep is set on the pessimistic record of an attempt still being decided: the last step before it. */
	PrevStep *int64 `json:"prev_step,omitempty"`
}

type guardsBody struct {
	V      int         `json:"v"`
	Users  []guardUser `json:"users"`
	Window []failure   `json:"window"`
}

/* loadGuards reads the guards file strictly; a missing file is an empty one, anything invalid is an error (the executor does not start). */
func loadGuards(path string, key *[32]byte) (map[int64]userState, []failure, error) {
	users := map[int64]userState{}
	raw, err := state.LoadSealed(path, key, guardsLabel, maxGuardsBytes)
	if errors.Is(err, os.ErrNotExist) {
		return users, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("authz: guards file %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b guardsBody
	if err := dec.Decode(&b); err != nil || b.V != guardsVersion || b.Users == nil || b.Window == nil {
		return nil, nil, fmt.Errorf("authz: guards file %s: %w", path, state.ErrInvalid)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("authz: guards file %s: %w", path, state.ErrInvalid)
	}
	seen := map[int64]bool{}
	for _, u := range b.Users {
		if u.ID <= 0 || u.LastStep < 0 || u.Failures < 0 || u.Failures >= MaxFailures || u.LockCount < 0 || u.LockCount > MaxLocks ||
			u.LockUntil < 0 || seen[u.ID] || (u.PrevStep != nil && (*u.PrevStep < 0 || *u.PrevStep > u.LastStep)) {
			return nil, nil, fmt.Errorf("authz: guards file %s: bad entry for user %d: %w", path, u.ID, state.ErrInvalid)
		}
		seen[u.ID] = true
		st := userState{lastStep: u.LastStep, failures: u.Failures, lockCount: u.LockCount}
		if u.PrevStep != nil {
			st.pending, st.prevStep = true, *u.PrevStep
		}
		if u.LockUntil != 0 {
			st.lockUntil = time.UnixMicro(u.LockUntil).UTC()
		}
		users[u.ID] = st
	}
	for _, f := range b.Window {
		if f.U <= 0 || f.T <= 0 {
			return nil, nil, fmt.Errorf("authz: guards file %s: bad window entry: %w", path, state.ErrInvalid)
		}
	}
	return users, b.Window, nil
}

/* pessimism is an attempt about to be evaluated, recorded as failed with its step window used. */
type pessimism struct {
	user int64
	st   userState
	fail failure
}

/* isUnsaved reports whether the last save of the guards failed. */
func (a *Authorizer) isUnsaved() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.unsaved
}

/*
saveGuards writes the in-memory guards, with over (if set) in place of its
user's state and its failure added (the caller holds sem, so saves are
ordered like the decisions). A failure latches: decide refuses every code
without evaluating it until a save succeeds, and a high alert is raised
once per latch.
*/
func (a *Authorizer) saveGuards(ctx context.Context, over *pessimism) error {
	a.mu.Lock()
	window := a.window
	if over != nil {
		window = append(slices.Clone(window), over.fail)
	}
	b := guardsBody{V: guardsVersion, Users: make([]guardUser, 0, len(a.users)+1), Window: mergeWindow(a.c.Now(), window)}
	users := a.users
	if over != nil {
		users = maps.Clone(users)
		users[over.user] = over.st
	}
	for id, st := range users {
		u := guardUser{ID: id, LastStep: st.lastStep, Failures: st.failures, LockCount: st.lockCount}
		if !st.lockUntil.IsZero() {
			u.LockUntil = st.lockUntil.UnixMicro()
		}
		if st.pending {
			u.PrevStep = &st.prevStep
		}
		b.Users = append(b.Users, u)
	}
	a.mu.Unlock()
	slices.SortFunc(b.Users, func(x, y guardUser) int { return cmp.Compare(x.ID, y.ID) })
	body, err := json.Marshal(b)
	if err == nil && len(body) > maxGuardsBytes-128 {
		err = errors.New("too many users")
	}
	if err == nil {
		err = state.SaveSealed(a.c.GuardsFile, a.c.Keys.State(), guardsLabel, body)
	}
	a.mu.Lock()
	first := err != nil && !a.unsaved
	a.unsaved = err != nil
	a.mu.Unlock()
	if err != nil {
		a.c.Log.Error("authz: cannot persist the lockout guards: decisions refused until it can", slog.Any("err", err))
	}
	if first {
		a.c.Guard.Alert(ctx, freeze.KindGuardsUnwritable, "high", "change TOTP guards cannot be saved, executor decisions refused: "+err.Error())
	}
	return err
}
