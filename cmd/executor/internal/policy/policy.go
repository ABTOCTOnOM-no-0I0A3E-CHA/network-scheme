/*
Package policy holds the policy the executor enforces: the host file
(read-only mount of deploy/policies, security.md 5.5), parsed by execpolicy
and reread whenever its mtime or size changes. A missing, unreadable or
invalid file disables the executor (fail closed) until a valid one appears;
the caller audits every change and alerts on an invalid file.
*/
package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/* State is the policy as last read: the parsed policy (Default when invalid), the file's SHA-256 and why it is invalid. */
type State struct {
	Policy execpolicy.Policy
	Sum    [32]byte
	Err    error
}

/* Enabled reports whether the executor may act: a valid policy that enables it. */
func (s State) Enabled() bool { return s.Err == nil && s.Policy.Enabled }

/* same reports whether two states enforce the same thing. */
func (s State) same(o State) bool {
	return s.Sum == o.Sum && (s.Err == nil) == (o.Err == nil) && (s.Err == nil || s.Err.Error() == o.Err.Error())
}

/* Holder holds the current State of one policy file. */
type Holder struct {
	path string

	mu    sync.Mutex
	cur   State
	mtime time.Time
	size  int64
	read  bool
}

/* New returns a holder of the file at path; nothing is read before the first Reload (until then: disabled). */
func New(path string) *Holder {
	return &Holder{path: path, cur: State{Policy: execpolicy.Default(), Err: errors.New("policy not read yet")}}
}

/* Current returns the state last read. */
func (h *Holder) Current() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

/*
Reload rereads the file when its mtime or size changed since the last read
(always with force) and returns the state before and after, and whether
what is enforced changed.
*/
func (h *Holder) Reload(force bool) (old, cur State, changed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	old = h.cur
	st, err := os.Stat(h.path)
	if err == nil && !force && h.read && st.ModTime().Equal(h.mtime) && st.Size() == h.size {
		return old, old, false
	}
	next := State{Policy: execpolicy.Default()}
	if err == nil {
		var data []byte
		var stable bool
		if data, stable, err = readFile(h.path); err == nil && !stable {
			return old, old, false /* written in place while read: the next poll reads it again */
		}
		h.mtime, h.size = st.ModTime(), st.Size()
		if err == nil {
			next.Sum = execpolicy.Sum(data)
			if p, perr := execpolicy.Parse(data); perr == nil {
				next.Policy = p
			} else {
				err = perr
			}
		}
	} else {
		h.mtime, h.size = time.Time{}, -1
	}
	if err != nil {
		next.Err, next.Policy.Enabled = err, false
	}
	h.cur, h.read = next, true
	return old, next, !next.same(old)
}

/*
readFile reads at most execpolicy.MaxSize+1 bytes (Parse refuses the
excess); stable is false when the file's mtime or size changed during the
read (an edit in place, not nmsctl's atomic replace).
*/
func readFile(path string) (data []byte, stable bool, err error) {
	f, err := os.Open(path) // #nosec G304 -- the policy file of the executor configuration
	if err != nil {
		return nil, false, fmt.Errorf("policy: %w", err)
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	if data, err = io.ReadAll(io.LimitReader(f, execpolicy.MaxSize+1)); err != nil {
		return nil, false, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	return data, before.ModTime().Equal(after.ModTime()) && before.Size() == after.Size(), nil
}

/* Run reloads every interval until ctx ends and calls changed(old, cur) whenever what is enforced changed. */
func (h *Holder) Run(ctx context.Context, every time.Duration, changed func(old, cur State)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if old, cur, ch := h.Reload(false); ch {
				changed(old, cur)
			}
		}
	}
}
