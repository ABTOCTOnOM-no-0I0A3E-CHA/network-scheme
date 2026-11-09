package recording

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/internal/backup/open"
	"github.com/beekamai/network-scheme/internal/execadmin"
)

/* Actions of the reads (the audit's action of authz's decision). */
const (
	ActionList   = "recording.list"
	ActionReplay = "recording.replay"
	actionView   = "recording.view" /* the audit row of a replay's outcome, with the session and device */
)

/*
Read is an authorized read of web (web.Read): authz decides the ticket, the
change TOTP code and Need, and audits it, before Run.
*/
type Read struct {
	Action string
	Need   authz.Need
	Run    func(ctx context.Context, by authz.Decision, params json.RawMessage) (any, error)
}

/* Reads are POST /x/recordings (list) and /x/recordings/replay: grant audit-read and a change TOTP code (ruling R3). */
func (st *Store) Reads() map[string]Read {
	need := authz.Need{Kind: execadmin.KindAuditRead}
	return map[string]Read{
		"/x/recordings":        {Action: ActionList, Need: need, Run: st.list},
		"/x/recordings/replay": {Action: ActionReplay, Need: need, Run: st.replay},
	}
}

func strict(b json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrParams
	}
	if dec.More() {
		return ErrParams
	}
	return nil
}

/* parseID reads a session id in the form idString writes (lower-case UUID) only. */
func parseID(s string) ([16]byte, bool) {
	var id [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 || idString([16]byte(b)) != s {
		return id, false
	}
	return [16]byte(b), true
}

/* Item is one recording of a list. The list is only an index (database rows): the replay verifies. */
type Item struct {
	Session  string    `json:"session_id"`
	Device   int64     `json:"device_id"`
	User     int64     `json:"user_id"`
	OpenedAt time.Time `json:"opened_at"`
	State    string    `json:"state"` /* complete, open (the session is open), incomplete (no manifest: the replay refuses) */
}

type listParams struct {
	Session string `json:"session_id,omitempty"`
	Device  int64  `json:"device_id,omitempty"`
}

/* list returns the recordings of a session or of a device (the newest listMost). */
func (st *Store) list(ctx context.Context, _ authz.Decision, params json.RawMessage) (any, error) {
	var p listParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	var sid *[16]byte
	if p.Session != "" {
		id, ok := parseID(p.Session)
		if !ok {
			return nil, ErrParams
		}
		sid = &id
	}
	var dev *int64
	if p.Device != 0 {
		if p.Device < 0 {
			return nil, ErrParams
		}
		dev = &p.Device
	}
	if sid == nil && dev == nil {
		return nil, ErrParams
	}
	qctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	rows, err := st.c.Pool.Query(qctx, `SELECT sd.session_id, sd.device_id, s.user_id, s.opened_at, m.session_id IS NOT NULL
		FROM exec.session_device sd JOIN exec.session s ON s.id = sd.session_id
		LEFT JOIN exec.recording_manifest m ON m.session_id = sd.session_id AND m.device_id = sd.device_id
		WHERE ($1::uuid IS NULL OR sd.session_id = $1) AND ($2::bigint IS NULL OR sd.device_id = $2)
		ORDER BY s.opened_at DESC, sd.session_id, sd.device_id LIMIT $3`, sid, dev, listMost)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		var (
			id       [16]byte
			it       Item
			manifest bool
		)
		if err := rows.Scan(&id, &it.Device, &it.User, &it.OpenedAt, &manifest); err != nil {
			return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
		}
		it.Session, it.State = idString(id), "incomplete"
		switch {
		case manifest:
			it.State = "complete"
		case st.c.Live(id):
			it.State = "open"
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
	}
	return out, nil
}

/* Event is one asciicast event: T seconds from the start, Code i, o or m, Data the masked, cleaned text. */
type Event struct {
	T    float64 `json:"t"`
	Code string  `json:"code"`
	Data string  `json:"data"`
}

/* Replay is a verified recording. */
type Replay struct {
	Session string  `json:"session_id"`
	Device  int64   `json:"device_id"`
	Start   int64   `json:"timestamp"` /* the header's start, Unix seconds */
	Title   string  `json:"title"`
	Events  []Event `json:"events"`
}

type replayParams struct {
	Session string `json:"session_id"`
	Device  int64  `json:"device_id"`
}

/* replay is Run of /x/recordings/replay: the view limit, the verified recording, an audit row of the outcome. */
func (st *Store) replay(ctx context.Context, by authz.Decision, params json.RawMessage) (any, error) {
	var p replayParams
	if err := strict(params, &p); err != nil {
		return nil, err
	}
	sid, ok := parseID(p.Session)
	if !ok || p.Device <= 0 {
		return nil, ErrParams
	}
	user := by.UserID
	ev := audit.Event{UserID: &user, Action: actionView, Object: "session:" + idString(sid), Result: audit.OK,
		Details: map[string]any{"device_id": p.Device}}
	limit := st.c.Policy().Policy.RecordingViewsPerHour
	if ok, first := st.views.take(user, limit, st.c.Now()); !ok {
		if first {
			st.alert(ctx, KindViews, "high", 0, fmt.Sprintf("user %d asked for more than %d recording replays in an hour; refused", user, limit))
		}
		ev.Result, ev.Details["class"] = audit.Denied, "view_limit"
		st.c.Audit(ctx, ev)
		return nil, ErrViewLimit
	}
	r, err := st.Replay(ctx, sid, p.Device)
	if err != nil {
		ev.Result = audit.Denied
		var rf Refusal
		if errors.As(err, &rf) {
			ev.Details["class"] = string(rf)
		} else {
			ev.Result = audit.Error
		}
		st.c.Audit(ctx, ev)
		return nil, err
	}
	ev.Details["events"] = len(r.Events)
	st.c.Audit(ctx, ev)
	return r, nil
}

/* tampered raises the high tamper alert and refuses. */
func (st *Store) tampered(ctx context.Context, session [16]byte, device int64, what string) error {
	st.alert(ctx, KindTamper, "high", device, fmt.Sprintf("the recording of change session %s on device %d: %s; its replay is refused",
		idString(session), device, what))
	return ErrTampered
}

/*
Replay reads the recording of a device of a session and verifies it before
anything is returned: the manifest (its MAC), every chunk in order 0..n-1
(number, MAC, envelope under its AAD), their count and the total hash, and
the asciicast text. Any failure is tampering: a high alert, ErrTampered.
A session still open in this process has no manifest yet: ErrOpen.
*/
func (st *Store) Replay(ctx context.Context, session [16]byte, device int64) (Replay, error) {
	qctx, cancel := context.WithTimeout(ctx, 2*recordTime)
	defer cancel()
	var (
		chunks      int
		sum, rowMAC []byte
	)
	err := st.c.Pool.QueryRow(qctx, `SELECT chunks, sha256, mac FROM exec.recording_manifest WHERE session_id = $1 AND device_id = $2`,
		session, device).Scan(&chunks, &sum, &rowMAC)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		var known bool
		if err := st.c.Pool.QueryRow(qctx, `SELECT EXISTS (SELECT 1 FROM exec.session_device WHERE session_id = $1 AND device_id = $2)`,
			session, device).Scan(&known); err != nil {
			return Replay{}, fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
		}
		switch {
		case !known:
			return Replay{}, ErrNotFound
		case st.c.Live(session):
			return Replay{}, ErrOpen
		}
		return Replay{}, st.tampered(ctx, session, device, "its manifest is missing")
	case err != nil:
		return Replay{}, st.readErr(ctx, session, device, err)
	}
	if chunks < 0 || chunks > maxChunks || !hmac.Equal(rowMAC, st.manifestMAC(session, device, chunks, sum)) {
		return Replay{}, st.tampered(ctx, session, device, "its manifest fails its MAC")
	}
	rows, err := st.c.Pool.Query(qctx, `SELECT n, ct, dek_ct, mac FROM exec.recording_chunk WHERE session_id = $1 AND device_id = $2
		ORDER BY n LIMIT $3`, session, device, chunks+1)
	if err != nil {
		return Replay{}, st.readErr(ctx, session, device, err)
	}
	total := sha256.New()
	var pt []byte
	i, bad := 0, ""
	for rows.Next() {
		var (
			n            int
			ct, dek, mac []byte
		)
		if err := rows.Scan(&n, &ct, &dek, &mac); err != nil {
			rows.Close()
			return Replay{}, st.readErr(ctx, session, device, err)
		}
		c, k := sha256.Sum256(ct), sha256.Sum256(dek)
		if n != i || i >= chunks {
			bad = fmt.Sprintf("chunk %d where %d belongs (manifest: %d chunks)", n, i, chunks)
			break
		}
		if !hmac.Equal(mac, st.chunkMAC(session, device, n, c[:], k[:])) {
			bad = fmt.Sprintf("chunk %d fails its MAC", n)
			break
		}
		p, err := open.Open(st.c.Priv, st.c.Pub, ct, dek, AAD(session, device, n))
		if err != nil {
			bad = fmt.Sprintf("chunk %d does not open under its AAD", n)
			break
		}
		if len(pt)+len(p) > maxReplayBytes {
			rows.Close()
			return Replay{}, ErrTooLarge
		}
		pt = append(pt, p...)
		total.Write(c[:])
		total.Write(k[:])
		i++
	}
	rows.Close()
	if err := rows.Err(); err != nil && bad == "" {
		return Replay{}, st.readErr(ctx, session, device, err)
	}
	switch {
	case bad != "":
	case i != chunks:
		bad = fmt.Sprintf("%d chunks where its manifest has %d", i, chunks)
	case !hmac.Equal(total.Sum(nil), sum):
		bad = "its chunks do not hash to its manifest"
	}
	if bad != "" {
		return Replay{}, st.tampered(ctx, session, device, bad)
	}
	r, err := st.parse(pt)
	if err != nil {
		return Replay{}, st.tampered(ctx, session, device, "its text is not asciicast v2: "+err.Error())
	}
	r.Session, r.Device = idString(session), device
	return r, nil
}

/* readErr is a failed read: an oversized row is tampering (nothing the executor writes is that large), anything else unavailable. */
func (st *Store) readErr(ctx context.Context, session [16]byte, device int64, err error) error {
	var big *pgproto3.ExceededMaxBodyLenErr
	if errors.As(err, &big) {
		return st.tampered(ctx, session, device, "a row is oversized")
	}
	return fmt.Errorf("%w: %w", authz.ErrUnavailable, err)
}

/* parse reads the asciicast v2 text: the header, then events [t, code, data]; every data cleaned again for the browser. */
func (st *Store) parse(pt []byte) (Replay, error) {
	lines := bytes.Split(bytes.TrimSuffix(pt, []byte("\n")), []byte("\n"))
	var h struct {
		Version   int    `json:"version"`
		Timestamp int64  `json:"timestamp"`
		Title     string `json:"title"`
	}
	if err := json.Unmarshal(lines[0], &h); err != nil || h.Version != 2 {
		return Replay{}, errors.New("no header")
	}
	r := Replay{Start: h.Timestamp, Title: st.c.Clean(h.Title), Events: make([]Event, 0, len(lines)-1)}
	for k, l := range lines[1:] {
		var e []json.RawMessage
		var ev Event
		if json.Unmarshal(l, &e) != nil || len(e) != 3 || json.Unmarshal(e[0], &ev.T) != nil || json.Unmarshal(e[1], &ev.Code) != nil ||
			json.Unmarshal(e[2], &ev.Data) != nil || (ev.Code != "i" && ev.Code != "o" && ev.Code != "m") || ev.T < 0 {
			return Replay{}, errors.New("event " + strconv.Itoa(k+1))
		}
		ev.Data = st.c.Clean(ev.Data)
		r.Events = append(r.Events, ev)
	}
	return r, nil
}

/* views is recording_views_per_hour per user: replays asked for in the last hour, and when the user was last alerted. */
type views struct {
	mu    sync.Mutex
	users map[int64]*userViews
}

type userViews struct {
	at      []time.Time
	alerted time.Time
}

/* take counts a replay of user; ok is false past the limit, first is true for the first refusal of the hour (alert once). */
func (v *views) take(user int64, limit int, now time.Time) (ok, first bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	u := v.users[user]
	if u == nil {
		u = &userViews{}
		v.users[user] = u
	}
	k := 0
	for _, t := range u.at {
		if now.Sub(t) < time.Hour {
			u.at[k] = t
			k++
		}
	}
	u.at = u.at[:k]
	if len(u.at) >= limit {
		first = now.Sub(u.alerted) >= time.Hour
		if first {
			u.alerted = now
		}
		return false, first
	}
	u.at = append(u.at, now)
	return true, false
}
