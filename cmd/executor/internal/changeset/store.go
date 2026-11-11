package changeset

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

/*
The changeset rows (exec.changeset, exec.changeset_revision,
exec.changeset_event) are append-only (security.md 5.4 D1) and carry their
own HMAC-SHA-256 under the registry's mac subkey, over a domain-separated,
length-prefixed encoding of the values the executor wrote. A revision's MAC
covers its content's SHA-256; Load also checks that the content is the
canonical encoding of a Content and hashes to it. An event's MAC covers its
payload as Go encodes it after a round trip through JSON (keys sorted,
integers as written), which jsonb keeps.
*/
const macDomain = "nms/changeset/v1"

/* KindTamper is the alert of a changeset row that fails its MAC (high; no freeze: the registry is not involved). */
const KindTamper = "executor_changeset_tamper"

/* Bounds of the stored rows. */
const (
	maxRevisions = 1000     /* as the CHECK of exec.changeset_revision.rev */
	maxEvents    = 20000    /* events read per changeset; Event refuses more */
	maxPayload   = 64 << 10 /* as the CHECK of exec.changeset_event.payload */
	opTime       = 10 * time.Second
)

/* Errors of the store. */
var (
	ErrTampered = errors.New("changeset: a stored row fails its MAC")
	ErrNotFound = errors.New("changeset: no such changeset")
	ErrConflict = errors.New("changeset: the revision changed meanwhile")
)

/* Store keeps the changeset rows. */
type Store struct {
	Pool  *pgxpool.Pool
	MAC   *[32]byte /* seal.Keys.MAC */
	Alert func(ctx context.Context, kind, severity string, deviceID int64, text string) error
	Log   *slog.Logger
	Now   func() time.Time
}

/* Changeset is a changeset as Load read and verified it: its newest revision and every event. */
type Changeset struct {
	ID         [16]byte
	Author     int64
	AuthorName string
	Kind       string
	Created    time.Time
	Rev        int
	RevAt      time.Time
	Content    Content
	ContentSHA [32]byte
	Events     []Event
}

/* Event is one event of a changeset; Payload is its JSON as the MAC covers it. */
type Event struct {
	ID      int64
	Rev     int
	At      time.Time
	Kind    string
	Device  int64
	Session *[16]byte
	Payload json.RawMessage
}

func (s *Store) macOf(table string, fields ...[]byte) []byte {
	h := hmac.New(sha256.New, s.MAC[:])
	h.Write([]byte(macDomain))
	for _, f := range append([][]byte{[]byte(table)}, fields...) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f)))) // #nosec G115 -- fields are far below 4 GiB
		h.Write(f)
	}
	return h.Sum(nil)
}

func i64(v int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) } // #nosec G115 -- encoding only

func (s *Store) changesetMAC(id [16]byte, author int64, name, kind string, created time.Time) []byte {
	return s.macOf("changeset", id[:], i64(author), []byte(name), []byte(kind), i64(created.UnixMicro()))
}

func (s *Store) revisionMAC(id [16]byte, rev int, at time.Time, sum []byte) []byte {
	return s.macOf("changeset_revision", id[:], i64(int64(rev)), i64(at.UnixMicro()), sum)
}

func (s *Store) eventMAC(e Event, id [16]byte) []byte {
	var sess []byte
	if e.Session != nil {
		sess = e.Session[:]
	}
	return s.macOf("changeset_event", i64(e.ID), id[:], i64(int64(e.Rev)), i64(e.At.UnixMicro()), []byte(e.Kind), i64(e.Device), sess, e.Payload)
}

func (s *Store) now() time.Time {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	return now().UTC().Truncate(time.Microsecond)
}

/* IDString is a changeset id as a UUID. */
func IDString(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

/* ParseID reads a changeset id written by IDString. */
func ParseID(s string) ([16]byte, bool) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 || IDString([16]byte(b)) != s {
		return [16]byte{}, false
	}
	return [16]byte(b), true
}

/* Create stores a new changeset of author with c as its revision 1. */
func (s *Store) Create(ctx context.Context, author int64, username string, c Content) (Changeset, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return Changeset{}, err
	}
	id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80 /* UUID v4 */
	now := s.now()
	content := c.Canonical()
	sum := sha256.Sum256(content)
	ctx, cancel := context.WithTimeout(ctx, opTime)
	defer cancel()
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO exec.changeset (id, author, author_username, kind, created_at, mac) VALUES ($1, $2, $3, $4, $5, $6)`,
			id, author, username, c.Kind(), now, s.changesetMAC(id, author, username, c.Kind(), now)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO exec.changeset_revision (changeset_id, rev, created_at, content, content_sha256, mac)
			VALUES ($1, 1, $2, $3, $4, $5)`, id, now, content, sum[:], s.revisionMAC(id, 1, now, sum[:]))
		return err
	})
	if err != nil {
		return Changeset{}, err
	}
	return Changeset{ID: id, Author: author, AuthorName: username, Kind: c.Kind(), Created: now, Rev: 1, RevAt: now, Content: c, ContentSHA: sum}, nil
}

/* Revise stores c as revision prev+1 of id; ErrConflict when prev is not the newest revision any more. */
func (s *Store) Revise(ctx context.Context, id [16]byte, prev int, c Content) (int, error) {
	if prev < 1 || prev >= maxRevisions {
		return 0, ErrConflict
	}
	now := s.now()
	content := c.Canonical()
	sum := sha256.Sum256(content)
	ctx, cancel := context.WithTimeout(ctx, opTime)
	defer cancel()
	/* only right after prev, the newest: a gap would read as tampering, a concurrent revision takes the key first */
	tag, err := s.Pool.Exec(ctx, `INSERT INTO exec.changeset_revision (changeset_id, rev, created_at, content, content_sha256, mac)
		SELECT $1, $2, $3, $4, $5, $6 WHERE (SELECT max(rev) FROM exec.changeset_revision WHERE changeset_id = $1) = $7`,
		id, prev+1, now, content, sum[:], s.revisionMAC(id, prev+1, now, sum[:]), prev)
	switch {
	case isUnique(err), err == nil && tag.RowsAffected() != 1:
		return 0, ErrConflict
	case err != nil:
		return 0, err
	}
	return prev + 1, nil
}

func isUnique(err error) bool {
	var pe interface{ SQLState() string }
	return errors.As(err, &pe) && pe.SQLState() == "23505"
}

/*
canonicalJSON is v as Go encodes it after a round trip through JSON
(object keys sorted, numbers as written): what an event's MAC covers, and
what the same bytes read back from jsonb encode to again.
*/
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	if _, ok := x.(map[string]any); !ok {
		return nil, errors.New("changeset: an event payload is a JSON object")
	}
	return json.Marshal(x)
}

/*
Event appends an event of revision rev (its id is taken first: the MAC
covers it). device and session may be 0 and nil.
*/
func (s *Store) Event(ctx context.Context, id [16]byte, rev int, kind string, device int64, session *[16]byte, payload any) (Event, error) {
	p, err := canonicalJSON(payload)
	if err != nil {
		return Event{}, err
	}
	if len(p) > maxPayload-1024 { /* jsonb's text adds a space after every ':' and ',' */
		return Event{}, fmt.Errorf("changeset: event %s too large (%d bytes)", kind, len(p))
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
	defer cancel()
	e := Event{Rev: rev, At: s.now(), Kind: kind, Device: device, Session: session, Payload: p}
	if err := s.Pool.QueryRow(ctx, `SELECT nextval('exec.changeset_event_id_seq')`).Scan(&e.ID); err != nil {
		return Event{}, err
	}
	var dev *int64
	if device > 0 {
		dev = &device
	}
	var sess any
	if session != nil {
		sess = *session
	}
	tag, err := s.Pool.Exec(ctx, `INSERT INTO exec.changeset_event (id, changeset_id, rev, at, kind, device_id, session_id, payload, mac)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 WHERE (SELECT count(*) FROM exec.changeset_event WHERE changeset_id = $2) < $10`,
		e.ID, id, rev, e.At, kind, dev, sess, p, s.eventMAC(e, id), maxEvents)
	if err == nil && tag.RowsAffected() != 1 {
		err = fmt.Errorf("changeset: more than %d events", maxEvents)
	}
	return e, err
}

/* tampered raises the tamper alert for changeset id and returns ErrTampered. */
func (s *Store) tampered(ctx context.Context, id [16]byte, what string) error {
	if s.Log != nil {
		s.Log.Error("changeset: tampered row", slog.String("changeset", IDString(id)), slog.String("what", what))
	}
	if s.Alert != nil {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTime)
		defer cancel()
		_ = s.Alert(actx, KindTamper, "high", 0, "changeset "+IDString(id)+": "+what+"; it is refused until the rows are restored")
	}
	return fmt.Errorf("%w: %s", ErrTampered, what)
}

/*
Load reads changeset id and verifies every row: the changeset's MAC, every
revision's MAC (revisions 1..n without a gap), the newest revision's
content (canonical, hashing to its content_sha256) and every event's MAC
(of an existing revision). Any failure refuses the whole changeset with
ErrTampered and the high executor_changeset_tamper alert.
*/
func (s *Store) Load(ctx context.Context, id [16]byte) (Changeset, error) {
	ctx, cancel := context.WithTimeout(ctx, opTime)
	defer cancel()
	cs := Changeset{ID: id}
	var mac []byte
	err := s.Pool.QueryRow(ctx, `SELECT author, author_username, kind, created_at, mac FROM exec.changeset WHERE id = $1`, id).
		Scan(&cs.Author, &cs.AuthorName, &cs.Kind, &cs.Created, &mac)
	if errors.Is(err, pgx.ErrNoRows) {
		return Changeset{}, ErrNotFound
	}
	if err != nil {
		return Changeset{}, err
	}
	if !hmac.Equal(mac, s.changesetMAC(id, cs.Author, cs.AuthorName, cs.Kind, cs.Created)) {
		return Changeset{}, s.tampered(ctx, id, "the changeset row fails its MAC")
	}
	rows, err := s.Pool.Query(ctx, `SELECT rev, created_at, content_sha256, mac FROM exec.changeset_revision
		WHERE changeset_id = $1 ORDER BY rev LIMIT $2`, id, maxRevisions+1)
	if err != nil {
		return Changeset{}, err
	}
	for rows.Next() {
		var (
			rev      int
			at       time.Time
			sum, mac []byte
		)
		if err := rows.Scan(&rev, &at, &sum, &mac); err != nil {
			rows.Close()
			return Changeset{}, err
		}
		if rev != cs.Rev+1 || len(sum) != sha256.Size || !hmac.Equal(mac, s.revisionMAC(id, rev, at, sum)) {
			rows.Close()
			return Changeset{}, s.tampered(ctx, id, fmt.Sprintf("revision %d fails its MAC or follows a gap", rev))
		}
		cs.Rev, cs.RevAt, cs.ContentSHA = rev, at, [32]byte(sum)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Changeset{}, err
	}
	if cs.Rev == 0 {
		return Changeset{}, s.tampered(ctx, id, "no revision")
	}
	var content []byte
	if err := s.Pool.QueryRow(ctx, `SELECT content FROM exec.changeset_revision WHERE changeset_id = $1 AND rev = $2`, id, cs.Rev).
		Scan(&content); err != nil {
		return Changeset{}, err
	}
	c, err := decodeContent(content)
	if err != nil || sha256.Sum256(c.Canonical()) != cs.ContentSHA || c.Kind() != cs.Kind {
		return Changeset{}, s.tampered(ctx, id, fmt.Sprintf("revision %d: the content is not the one its MAC covers", cs.Rev))
	}
	cs.Content = c
	if cs.Events, err = s.events(ctx, id, cs.Rev); err != nil {
		return Changeset{}, err
	}
	return cs, nil
}

/* events reads and verifies the events of id (of revisions up to newest), in order. */
func (s *Store) events(ctx context.Context, id [16]byte, newest int) ([]Event, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, rev, at, kind, coalesce(device_id, 0), session_id, payload, mac FROM exec.changeset_event
		WHERE changeset_id = $1 ORDER BY id LIMIT $2`, id, maxEvents+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var (
			e       Event
			sess    *[16]byte
			payload []byte
			mac     []byte
		)
		if err := rows.Scan(&e.ID, &e.Rev, &e.At, &e.Kind, &e.Device, &sess, &payload, &mac); err != nil {
			return nil, err
		}
		e.Session = sess
		var x any
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.UseNumber()
		err := dec.Decode(&x)
		if err == nil {
			e.Payload, err = json.Marshal(x)
		}
		if err != nil || e.Rev < 1 || e.Rev > newest || !hmac.Equal(mac, s.eventMAC(e, id)) {
			return nil, s.tampered(ctx, id, fmt.Sprintf("event %d fails its MAC", e.ID))
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

/* Started lists the changesets that have a run_started event (Recover reads and verifies each). */
func (s *Store) Started(ctx context.Context) ([][16]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, opTime)
	defer cancel()
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT changeset_id FROM exec.changeset_event WHERE kind = 'run_started'`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[[16]byte])
}

/* PreSessionVersions is, per device, the newest 'pre_session' configuration version taken since (what a restore changeset goes back to). */
func (s *Store) PreSessionVersions(ctx context.Context, devices []int64, since time.Time) (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, opTime)
	defer cancel()
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT ON (device_id) device_id, id FROM backups.config_version
		WHERE device_id = ANY($1) AND source = 'pre_session' AND taken_at >= $2 ORDER BY device_id, taken_at DESC, id DESC`, devices, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var dev, id int64
		if err := rows.Scan(&dev, &id); err != nil {
			return nil, err
		}
		out[strconv.FormatInt(dev, 10)] = id
	}
	return out, rows.Err()
}

/* IDs lists the newest changesets (by creation), at most limit. */
func (s *Store) IDs(ctx context.Context, limit int) ([][16]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, opTime)
	defer cancel()
	rows, err := s.Pool.Query(ctx, `SELECT id FROM exec.changeset ORDER BY created_at DESC, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[[16]byte])
}
