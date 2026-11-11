package changeset

import (
	"context"
	"time"
)

/* WaitDryRun waits for the dry-run of changeset id started in this process (none: returns at once). */
func (m *Manager) WaitDryRun(id string) {
	cid, _ := ParseID(id)
	m.mu.Lock()
	d := m.dry[cid]
	m.mu.Unlock()
	if d != nil {
		<-d.done
	}
}

/* WaitRun waits for the run of changeset id in this process (none: returns at once). */
func (m *Manager) WaitRun(id string) {
	cid, _ := ParseID(id)
	m.mu.Lock()
	r := m.runs[cid]
	m.mu.Unlock()
	if r != nil {
		<-r.done
	}
}

var settleIn = make(chan struct{}, 1)

/* HoldSettle makes the canary's settle time wait until release (WaitSettle: the run is in it). */
func HoldSettle() (release func()) {
	gate := make(chan struct{})
	old := settle
	settle = func(context.Context, time.Duration) {
		settleIn <- struct{}{}
		<-gate
	}
	return func() {
		close(gate)
		settle = old
	}
}

/* WaitSettle waits until a run is in its settle time. */
func WaitSettle() { <-settleIn }
