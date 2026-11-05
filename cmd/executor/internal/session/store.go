package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/backups"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/internal/execpolicy"
)

/*
The session rows (exec.session, exec.session_device, exec.session_event)
are append-only and not part of the registry: each carries its own
HMAC-SHA-256 under the registry's mac subkey, over a domain-separated,
length-prefixed encoding of the values the executor wrote (macOf). The
snapshot row covers the SHA-256 of its envelope parts, not the parts
themselves: a reader of the 4 MiB envelope hashes it in Go (4c.4), while
Recover needs only the device ids.
*/
const macDomain = "nms/session/v1"

func (m *Manager) macOf(table string, fields ...[]byte) []byte {
	h := hmac.New(sha256.New, m.cfg.MAC[:])
	h.Write([]byte(macDomain))
	for _, f := range append([][]byte{[]byte(table)}, fields...) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f)))) // #nosec G115 -- fields are far below 4 GiB
		h.Write(f)
	}
	return h.Sum(nil)
}

func i64(v int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) } // #nosec G115 -- encoding only

/* policySnapshot is exec.session.policy_snapshot: the policy file's hash and the policy as parsed. */
type policySnapshot struct {
	Sum    string            `json:"sum"`
	Policy execpolicy.Policy `json:"policy"`
}

/* sessionMAC covers id, user, opening time (microseconds) and the policy snapshot as Go encodes it (stable through jsonb). */
func (m *Manager) sessionMAC(id [16]byte, user int64, opened time.Time, snap []byte) []byte {
	return m.macOf("session", id[:], i64(user), i64(opened.UnixMicro()), snap)
}

/* MACs of the other rows (4c.4 and 4c.5 check them with these). */

/* DeviceMAC covers a session_device row: pre_ct and pre_dek_ct by their SHA-256. */
func (m *Manager) DeviceMAC(session [16]byte, device int64, pre [32]byte, ct, dekCT []byte) []byte {
	c, k := sha256.Sum256(ct), sha256.Sum256(dekCT)
	return m.macOf("session_device", session[:], i64(device), pre[:], c[:], k[:])
}

/* EventMAC covers a session_event row; payload is its JSON as Go encodes it. */
func (m *Manager) EventMAC(id int64, session [16]byte, at time.Time, kind string, payload []byte) []byte {
	return m.macOf("session_event", i64(id), session[:], i64(at.UnixMicro()), []byte(kind), payload)
}

func (m *Manager) insertSession(ctx context.Context, s *Session, pol policy.State) error {
	snap, err := json.Marshal(policySnapshot{Sum: fmt.Sprintf("%x", pol.Sum), Policy: pol.Policy})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	_, err = m.cfg.Pool.Exec(ctx, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES ($1, $2, $3, $4, $5)`,
		s.ID, s.User, s.Opened, snap, m.sessionMAC(s.ID, s.User, s.Opened, snap))
	return err
}

func (m *Manager) insertDevice(ctx context.Context, session [16]byte, device int64, pre backups.Pre) error {
	ctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	_, err := m.cfg.Pool.Exec(ctx, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac)
		VALUES ($1, $2, $3, $4, $5, $6)`, session, device, pre.SHA256[:], pre.CT, pre.DEKCT,
		m.DeviceMAC(session, device, pre.SHA256, pre.CT, pre.DEKCT))
	return err
}

/* event appends a session event (its id is taken first: the MAC covers it). A failure is logged: the session goes on. */
func (m *Manager) event(ctx context.Context, session [16]byte, kind string, payload map[string]any) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTime)
	defer cancel()
	err := func() error {
		p, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		var id int64
		if err := m.cfg.Pool.QueryRow(ctx, `SELECT nextval('exec.session_event_id_seq')`).Scan(&id); err != nil {
			return err
		}
		at := m.cfg.Now().UTC().Truncate(time.Microsecond)
		_, err = m.cfg.Pool.Exec(ctx, `INSERT INTO exec.session_event (id, session_id, at, kind, payload, mac) VALUES ($1, $2, $3, $4, $5, $6)`,
			id, session, at, kind, p, m.EventMAC(id, session, at, kind, p))
		return err
	}()
	if err != nil {
		m.cfg.Log.Error("session: event not recorded", slog.String("session", IDString(session)), slog.String("kind", kind),
			slog.String("err", err.Error()))
	}
}

/*
Recover runs once at start, before /x serves: every session of a previous
process without an end event (its MAC checked; a row that fails it is only
logged) ends as interrupted, with an alert per device (its pre-session
snapshot stays for a rollback), and every device_busy row and open summary
of the previous process goes (pub.Publisher.Recover).
*/
func (m *Manager) Recover(ctx context.Context) error {
	type row struct {
		id     [16]byte
		user   int64
		opened time.Time
		snap   []byte
		mac    []byte
		devs   []int64
	}
	qctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	rows, err := m.cfg.Pool.Query(qctx, `SELECT s.id, s.user_id, s.opened_at, s.policy_snapshot, s.mac,
			coalesce(array_agg(d.device_id ORDER BY d.device_id) FILTER (WHERE d.device_id IS NOT NULL), '{}')
		FROM exec.session s LEFT JOIN exec.session_device d ON d.session_id = s.id
		WHERE NOT EXISTS (SELECT 1 FROM exec.session_event e WHERE e.session_id = s.id AND e.kind IN ('closed', 'interrupted'))
		GROUP BY s.id ORDER BY s.opened_at DESC LIMIT $1`, recoverLimit)
	if err != nil {
		return err
	}
	var open []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.user, &r.opened, &r.snap, &r.mac, &r.devs); err != nil {
			rows.Close()
			return err
		}
		open = append(open, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range open {
		var ps policySnapshot
		err := json.Unmarshal(r.snap, &ps)
		var snap []byte
		if err == nil {
			snap, err = json.Marshal(ps)
		}
		if err != nil || !hmac.Equal(r.mac, m.sessionMAC(r.id, r.user, r.opened, snap)) {
			m.cfg.Log.Error("session: an unended session row fails its MAC; ignored", slog.String("session", IDString(r.id)))
			continue
		}
		m.event(ctx, r.id, "interrupted", map[string]any{"reason": "restart"})
		for _, d := range r.devs {
			if err := m.cfg.Pub.SessionClosed(ctx, r.id, d, StatusInterrupted, nil); err != nil {
				m.cfg.Log.Info("session: no open summary to interrupt", slog.Int64("device_id", d))
			}
			m.alert(ctx, KindInterrupted, "high", d, fmt.Sprintf("change session %s on device %d was interrupted by an executor restart; "+
				"a rollback to the pre-session snapshot is offered", IDString(r.id), d))
		}
	}
	return m.cfg.Pub.Recover(ctx)
}
