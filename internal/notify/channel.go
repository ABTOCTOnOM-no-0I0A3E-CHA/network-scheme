// Package notify carries problem notifications from the trigger engine to its channels.
package notify

import (
	"context"
	"time"
)

// ProblemEvent is what happened to a problem.
type ProblemEvent string

/* Problem events. */
const (
	EventOpened            ProblemEvent = "opened"
	EventAcknowledged      ProblemEvent = "acknowledged"
	EventResolved          ProblemEvent = "resolved"
	EventSuppressedChanged ProblemEvent = "suppressed_changed"
)

/* MessageTypeProblem is the Type of a problem message. */
const MessageTypeProblem = "problem"

/*
ProblemSummary is the part of a problem that notifications carry. It holds no
secrets; Name, Object and DeviceName may derive from device data and are
untrusted text that clients render as text only. DeviceID, DeviceName and
GroupID are nil/empty for system problems without a device (such a problem
is visible to global bindings only).
*/
type ProblemSummary struct {
	ID         int64      `json:"id"`
	DeviceID   *int64     `json:"device_id"`
	DeviceName string     `json:"device_name"`
	GroupID    *int64     `json:"group_id"` /* the group of the device: the scope check key */
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	Suppressed bool       `json:"suppressed"`
	Name       string     `json:"name"`
	SystemKind *string    `json:"system_kind"` /* set for engine-raised problems; clients translate the title by it */
	Object     string     `json:"object"`
	OpenedAt   time.Time  `json:"opened_at"`
	AckedAt    *time.Time `json:"acknowledged_at"`
	ResolvedAt *time.Time `json:"resolved_at"`
}

// Message is one notification: {"type":"problem","event":...,"problem":{...}}.
type Message struct {
	Type    string         `json:"type"`
	Event   ProblemEvent   `json:"event"`
	Problem ProblemSummary `json:"problem"`
}

// Channel delivers a notification somewhere. Deliver must not block for long.
type Channel interface {
	Name() string
	Deliver(ctx context.Context, m Message) error
}

/* Panel is the built-in "panel" channel: it hands messages to the hub's WebSocket subscribers. */
type Panel struct{ Hub *Hub }

// Name returns "panel".
func (Panel) Name() string { return "panel" }

// Deliver publishes m to the hub; it never fails and never blocks.
func (p Panel) Deliver(_ context.Context, m Message) error {
	if m.Type == "" {
		m.Type = MessageTypeProblem
	}
	p.Hub.Publish(m)
	return nil
}
