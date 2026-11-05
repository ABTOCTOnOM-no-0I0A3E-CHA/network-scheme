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

/* recovered is a session row of a previous process as Recover reads it. */
type recovered struct {
	id     [16]byte
	user   int64
	opened time.Time
	snap   []byte
	mac    []byte
	ended  bool
	devs   []int64 /* devices whose session_device row passes its MAC */
}

/*
Recover runs once at start, before /x serves. It reads every session row
in pages (no bound a flood of planted rows could starve) and checks every
MAC: the session's, its session_device rows' (over sha256(pre_ct) and
sha256(pre_dek_ct), computed by the database: the envelope never crosses
the wire) and its end events'. Any row that fails raises a high tamper
alert and counts as absent (a forged end event does not end a session).
A session with a valid row and no valid end event ends as interrupted,
with an alert per device (its pre-session snapshot stays for a rollback).
Then every device_busy row and open summary of the previous process goes
(pub.Publisher.Recover).
*/
func (m *Manager) Recover(ctx context.Context) error {
	var after [16]byte
	bad := 0
	for {
		page, read, n, err := m.recoverPage(ctx, after)
		if err != nil {
			return err
		}
		bad += n
		for _, r := range page {
			if r.ended {
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
		if len(read) < recoverPage {
			break
		}
		after = read[len(read)-1]
	}
	if bad > 0 {
		m.alert(ctx, KindTamper, "high", 0, fmt.Sprintf("%d change session rows fail their MAC; they were ignored", bad))
	}
	return m.cfg.Pub.Recover(ctx)
}

/* recoverPage reads the sessions after id (by id): the valid ones with their verified devices and end events, the ids read, and how many rows fail a MAC. */
func (m *Manager) recoverPage(ctx context.Context, after [16]byte) (page []recovered, ids [][16]byte, bad int, err error) {
	qctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	rows, err := m.cfg.Pool.Query(qctx, `SELECT id, user_id, opened_at, policy_snapshot, mac FROM exec.session
		WHERE id > $1 ORDER BY id LIMIT $2`, after, recoverPage)
	if err != nil {
		return nil, nil, 0, err
	}
	var all []recovered
	for rows.Next() {
		var r recovered
		if err := rows.Scan(&r.id, &r.user, &r.opened, &r.snap, &r.mac); err != nil {
			rows.Close()
			return nil, nil, 0, err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, 0, err
	}
	ids = make([][16]byte, len(all))
	byID := map[[16]byte]*recovered{}
	for i := range all {
		ids[i], byID[all[i].id] = all[i].id, &all[i]
	}
	valid := map[[16]byte]bool{}
	for i := range all {
		r := &all[i]
		var ps policySnapshot
		err := json.Unmarshal(r.snap, &ps)
		var snap []byte
		if err == nil {
			snap, err = json.Marshal(ps)
		}
		if err != nil || !hmac.Equal(r.mac, m.sessionMAC(r.id, r.user, r.opened, snap)) {
			bad++
			continue
		}
		valid[r.id] = true
	}
	drows, err := m.cfg.Pool.Query(qctx, `SELECT session_id, device_id, pre_sha256, sha256(pre_ct), sha256(pre_dek_ct), mac
		FROM exec.session_device WHERE session_id = ANY($1) ORDER BY session_id, device_id`, ids)
	if err != nil {
		return nil, nil, 0, err
	}
	for drows.Next() {
		var (
			sid             [16]byte
			dev             int64
			pre, ct, k, mac []byte
		)
		if err := drows.Scan(&sid, &dev, &pre, &ct, &k, &mac); err != nil {
			drows.Close()
			return nil, nil, 0, err
		}
		if len(pre) != 32 || len(ct) != 32 || len(k) != 32 ||
			!hmac.Equal(mac, m.macOf("session_device", sid[:], i64(dev), pre, ct, k)) {
			bad++
			continue
		}
		if r := byID[sid]; r != nil && valid[sid] {
			r.devs = append(r.devs, dev)
		}
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return nil, nil, 0, err
	}
	erows, err := m.cfg.Pool.Query(qctx, `SELECT id, session_id, at, kind, payload, mac FROM exec.session_event
		WHERE session_id = ANY($1) AND kind IN ('closed', 'interrupted')`, ids)
	if err != nil {
		return nil, nil, 0, err
	}
	for erows.Next() {
		var (
			id           int64
			sid          [16]byte
			at           time.Time
			kind         string
			payload, mac []byte
		)
		if err := erows.Scan(&id, &sid, &at, &kind, &payload, &mac); err != nil {
			erows.Close()
			return nil, nil, 0, err
		}
		var p map[string]any
		var enc []byte
		err := json.Unmarshal(payload, &p)
		if err == nil {
			enc, err = json.Marshal(p)
		}
		if err != nil || !hmac.Equal(mac, m.EventMAC(id, sid, at, kind, enc)) {
			bad++
			continue
		}
		if r := byID[sid]; r != nil {
			r.ended = true
		}
	}
	erows.Close()
	if err := erows.Err(); err != nil {
		return nil, nil, 0, err
	}
	for _, r := range all {
		if valid[r.id] {
			page = append(page, r)
		}
	}
	return page, ids, bad, nil
}

/*
sessionLeft reports whether sum is what a change session left on device
since its newest configuration version (a closed summary's post_sha256, as
the poller decides drift): then a pre-session snapshot that differs from the
newest version is not drift.
*/
func (m *Manager) sessionLeft(ctx context.Context, device int64, sum [32]byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	var ok bool
	err := m.cfg.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM execpub.session_summary
		WHERE device_id = $1 AND post_sha256 = $2 AND status <> 'open' AND closed_at IS NOT NULL
		  AND closed_at >= (SELECT max(taken_at) FROM backups.config_version WHERE device_id = $1))`, device, sum[:]).Scan(&ok)
	return ok, err
}
