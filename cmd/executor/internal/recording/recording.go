/*
Package recording records change sessions and replays them (security.md 5.3,
FR-CHG-8, Task 4c.5).

A recording is one device of one session: an asciicast v2 text (a header,
then events "i" for a line sent to the device, "o" for the device's answer,
"m" for the executor's own markers: session opened and ended, a dangerous
line or a paste confirmed, diff, save, commit, form, rollback). Every event's
text is cleaned of escapes and controls (Config.Clean, the live terminal's)
and masked line by line before it is buffered: a line of key material
(mask.KeyMaterial) whole, any other by the driver's MaskSecrets on its own.
In the output a PEM or "crypto ... import" block one answer opens goes on in
the next (mask.Stream) only while its lines are key material: any other line
ends it, so an opener the device did not take hides nothing after it.
Device output without its line end is held unmasked only inside the Stream,
until the line ends (so a secret split across two answers is masked whole),
the next event or the end. Nothing unmasked is ever buffered beyond that,
stored or logged.

The masked text is stored in chunks of at most maxChunk bytes (below
registry.MaxMessage, so the normal pool reads them), each sealed with the
backup domain's envelope (internal/backup.Seal, AAD "recording|session|
device|n") in exec.recording_chunk under the executor's MAC; a manifest
(chunk count and the SHA-256 over every chunk's sha256(ct)||sha256(dek_ct))
under MAC in exec.recording_manifest when the device's session ends. Both
tables are append-only. Every line sent is stored before it is sent
(Input stores synchronously); a failure to store makes the Stream refuse
every further line (fail closed, high alert): a session never sends a line
it has not recorded, and a line whose store failed is dropped from the
buffer (it never appears as sent). Past recording_max_mib (policy) Input
refuses every further line too (warning alert); the answer to a line already
sent (at most maxAnswer of masked text, cut with a marker) and markers (at
most markerBudget) are still recorded: a recording stays within
replayBound(its limit).

A replay (POST /x/recordings/replay: grant audit-read and a change TOTP code
through authz, ruling R3; every view in the executor's audit; at most
recording_views_per_hour per user, more refused with a high alert; at most
maxReplays at once, more refused with 503: the answer is built in memory) verifies
the manifest's MAC, then every chunk's number (0, 1, ... in order), MAC and
AAD, their count and the total hash before anything is returned; any
failure refuses the replay with a high executor_recording_tamper alert. The events go
to the browser as JSON text, cleaned again.
*/
package recording

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/drivers/mask"
)

/* Alert kinds (internal/triggers). */
const (
	KindFailed = "executor_recording_failed" /* high: a recording could not be stored; the session sends no further line */
	KindFull   = "executor_recording_full"   /* warning: a recording reached recording_max_mib; the session sends no further line */
	KindViews  = "executor_recording_views"  /* high: a user asked for more replays than recording_views_per_hour */
	KindTamper = "executor_recording_tamper" /* high: a recording fails its MAC, AAD, order, count or hash (no freeze) */
)

/* Refusal is a refusal with the code the UI has a text for (web: 422). */
type Refusal string

func (r Refusal) Error() string { return "recording: refused (" + string(r) + ")" }

/* RefusalCode is the code the UI has a text for. */
func (r Refusal) RefusalCode() string { return string(r) }

/* Refusals. */
const (
	ErrFailed    Refusal = "recording_failed"   /* the recording could not be stored: nothing more is sent */
	ErrFull      Refusal = "recording_full"     /* recording_max_mib reached: nothing more is sent */
	ErrOpen      Refusal = "recording_open"     /* the session is still open: no manifest yet */
	ErrTampered  Refusal = "recording_tampered" /* the recording fails its verification */
	ErrViewLimit Refusal = "view_limit"
	ErrNotFound  Refusal = "not_found"
	ErrParams    Refusal = "bad_params"
)

/* Bounds (variables for the tests). */
var (
	maxChunk     = 1<<20 - 16<<10 /* plaintext bytes of a chunk: its row stays below registry.MaxMessage */
	maxCarry     = 64 << 10       /* device output without its line end held for the masker */
	maxChunks    = 999_000        /* chunks of a recording: Input refuses beyond (the table allows 0..1000000) */
	maxAnswer    = 4 << 20        /* masked text of one answer recorded; the rest is cut with a marker saying so */
	markerBudget = 64 << 10       /* bytes of markers recorded past recording_max_mib (the end marker always) */
	listMost     = 200            /* recordings a list returns */
	maxReplays   = 2              /* replays at once */
	recordTime   = 10 * time.Second
)

/*
replayBound is the most a recording under a limit of maxMiB can hold: the
limit, then one line sent just below it, its answer (at most maxAnswer of
masked text, at most twice that in JSON: escapes double a character at
most, no HTML escaping), the markers past the limit and the header and
end. A replay reads at most replayBound(execpolicy.MaxRecordingMiB): more
is tampering, never a recording the executor wrote.
*/
func replayBound(maxMiB int) int { return maxMiB<<20 + 2*maxAnswer + markerBudget + 512<<10 }

/* Config builds a Store; every field but Log and Now is required. */
type Config struct {
	Pool *pgxpool.Pool
	MAC  *[32]byte /* seal.Keys.MAC: the chunk and manifest rows */
	/* Pub seals the chunks; Priv and Pub open them for a replay (the backup domain's keys). */
	Pub, Priv *[32]byte
	/* Clean is what the live terminal does to device output (terminal.Clean): escapes and controls go. */
	Clean  func(string) string
	Policy func() policy.State
	/* Live reports whether a session is open in this process (its manifest is not written yet). */
	Live  func(session [16]byte) bool
	Alert func(ctx context.Context, kind, severity string, deviceID int64, text string) error
	Audit func(ctx context.Context, ev audit.Event) /* authz.Authorizer.Record */
	Log   *slog.Logger
	Now   func() time.Time
}

/* Store records and replays. */
type Store struct {
	c       Config
	views   views
	replays chan struct{} /* a slot per replay running */
}

/* New returns a Store. */
func New(c Config) (*Store, error) {
	if c.Pool == nil || c.MAC == nil || c.Pub == nil || c.Priv == nil || c.Clean == nil || c.Policy == nil || c.Live == nil ||
		c.Alert == nil || c.Audit == nil {
		return nil, errors.New("recording: incomplete configuration")
	}
	if c.Log == nil {
		c.Log = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return &Store{c: c, views: views{users: map[int64]*userViews{}}, replays: make(chan struct{}, maxReplays)}, nil
}

const macDomain = "nms/recording/v1"

func (st *Store) macOf(table string, fields ...[]byte) []byte {
	h := hmac.New(sha256.New, st.c.MAC[:])
	h.Write([]byte(macDomain))
	for _, f := range append([][]byte{[]byte(table)}, fields...) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f)))) // #nosec G115 -- fields are far below 4 GiB
		h.Write(f)
	}
	return h.Sum(nil)
}

func i64(v int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(v)) } // #nosec G115 -- encoding only

/* idString is a session id as text (UUID). */
func idString(id [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

/* AAD binds a chunk's envelope to its session, device and number. */
func AAD(session [16]byte, device int64, n int) []byte {
	return fmt.Appendf(nil, "recording|%s|%d|%d", idString(session), device, n)
}

/* chunkMAC covers a chunk row: its envelope parts by their SHA-256. */
func (st *Store) chunkMAC(session [16]byte, device int64, n int, ctSum, dekSum []byte) []byte {
	return st.macOf("recording_chunk", session[:], i64(device), i64(int64(n)), ctSum, dekSum)
}

func (st *Store) manifestMAC(session [16]byte, device int64, chunks int, total []byte) []byte {
	return st.macOf("recording_manifest", session[:], i64(device), i64(int64(chunks)), total)
}

func (st *Store) alert(ctx context.Context, kind, sev string, device int64, text string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTime)
	defer cancel()
	if err := st.c.Alert(ctx, kind, sev, device, text); err != nil {
		st.c.Log.Warn("recording: alert not published", slog.String("kind", kind), slog.String("err", err.Error()))
	}
}

/*
Stream is the recording of one device of a session. Its methods are safe
for concurrent use; after Close every call but Close fails.
*/
type Stream struct {
	st     *Store
	sid    [16]byte
	device int64
	mask   func(string) string /* the driver's MaskSecrets */
	start  time.Time
	limit  int64

	mu    sync.Mutex
	buf   []byte      /* masked asciicast text not stored yet */
	n     int         /* the next chunk's number */
	total hash.Hash   /* over every stored chunk's sha256(ct)||sha256(dek_ct) */
	size  int64       /* bytes recorded (stored and buffered) */
	out   mask.Stream /* the device output's PEM and import blocks */
	carry string      /* device output after its last line end: unmasked, never buffered or stored as is */
	err   error       /* the first failure to store: no line is sent any more */
	full  bool
	/* pastLimit counts the markers' bytes recorded past recording_max_mib (at most markerBudget) */
	pastLimit int64
	closed    bool
}

/*
Open starts the recording of a device of a session (its exec.session_device
row must exist): the header and the "opened" marker, stored at once. mask is
the driver's MaskSecrets.
*/
func (st *Store) Open(ctx context.Context, session [16]byte, device int64, username string, mask func(string) string) (*Stream, error) {
	if mask == nil {
		return nil, errors.New("recording: no masker")
	}
	s := &Stream{st: st, sid: session, device: device, mask: mask, start: st.c.Now(), total: sha256.New(),
		limit: int64(st.c.Policy().Policy.RecordingMaxMiB) << 20}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.header()
	s.event("m", s.label("session opened by "+username))
	if err := s.flush(ctx, false); err != nil {
		return nil, fmt.Errorf("recording: %w", err)
	}
	return s, nil
}

func (s *Stream) header() {
	h, _ := json.Marshal(map[string]any{"version": 2, "width": 80, "height": 24, "timestamp": s.start.Unix(),
		"title": fmt.Sprintf("change session %s, device %d", idString(s.sid), s.device)})
	s.buf = append(append(s.buf, h...), '\n')
	s.size += int64(len(h) + 1)
}

/* event appends one asciicast event of masked text (JSON without HTML escaping: at most twice its size). */
func (s *Stream) event(code, masked string) {
	t := max(s.st.c.Now().Sub(s.start), 0).Seconds()
	var d bytes.Buffer
	e := json.NewEncoder(&d)
	e.SetEscapeHTML(false)
	_ = e.Encode(masked)
	line := fmt.Appendf(nil, "[%s, %q, %s]\n", strconv.FormatFloat(t, 'f', 6, 64), code, bytes.TrimSuffix(d.Bytes(), []byte("\n")))
	s.buf = append(s.buf, line...)
	s.size += int64(len(line))
}

/* undo drops what was buffered since mark (an event whose store failed: it must not be stored later, the device never got it). */
func (s *Stream) undo(at int, size int64) {
	if len(s.buf) >= at {
		s.buf, s.size = s.buf[:at], size
	}
}

/* label is a marker's text as recorded: cleaned and masked (a marker names no secret, but nothing is recorded unmasked). */
func (s *Stream) label(l string) string { return s.mask(mask.Secrets(s.st.c.Clean(l))) }

/*
output masks device output line by line: cleaned, then a line inside a PEM
or import block, or one of key material, is masked whole (mask.Stream: the
block state goes across answers, but only key material stays in a block),
any other line by the driver's mask on its own (so no opener hides the
lines after it).
*/
func (s *Stream) output(text string) string {
	lines := strings.Split(s.st.c.Clean(text), "\n")
	for i, l := range lines {
		if s.out.Block(l) {
			lines[i] = mask.Mark
		} else if l != "" {
			lines[i] = s.mask(l)
		}
	}
	return strings.Join(lines, "\n")
}

/* input masks a line sent: whole when it is key material, else by the driver's mask (no state: a line never hides another). */
func (s *Stream) input(line string) string {
	l := s.st.c.Clean(line)
	if mask.KeyMaterial(strings.TrimSpace(l)) {
		return mask.Mark
	}
	return s.mask(l)
}

/* flushCarry records the output held without its line end. */
func (s *Stream) flushCarry() {
	if s.carry != "" {
		s.event("o", s.output(s.carry))
		s.carry = ""
	}
}

/*
flush stores the buffer in chunks (all of it, or with partial only the full
chunks). A failure latches: no line is sent any more (high alert).
*/
func (s *Stream) flush(ctx context.Context, partial bool) error {
	for len(s.buf) > 0 && (!partial || len(s.buf) >= maxChunk) {
		piece := s.buf[:min(len(s.buf), maxChunk)]
		if err := s.store(ctx, piece); err != nil {
			if s.err == nil {
				s.err = err
				s.st.c.Log.Error("recording: a chunk was not stored", slog.String("session", idString(s.sid)),
					slog.Int64("device_id", s.device), slog.String("err", err.Error()))
				s.st.alert(ctx, KindFailed, "high", s.device, fmt.Sprintf("the recording of change session %s on device %d could "+
					"not be stored; the session sends no further line to the device", idString(s.sid), s.device))
			}
			return ErrFailed
		}
		s.buf = s.buf[len(piece):]
	}
	return nil
}

/* store seals and inserts chunk s.n. */
func (s *Stream) store(ctx context.Context, pt []byte) error {
	ct, dek, err := backup.Seal(s.st.c.Pub, bytes.Clone(pt), AAD(s.sid, s.device, s.n)) /* Seal wipes its plaintext: a copy */
	if err != nil {
		return err
	}
	c, k := sha256.Sum256(ct), sha256.Sum256(dek)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTime)
	defer cancel()
	if _, err := s.st.c.Pool.Exec(ctx, `INSERT INTO exec.recording_chunk (session_id, device_id, n, ct, dek_ct, mac)
		VALUES ($1, $2, $3, $4, $5, $6)`, s.sid, s.device, s.n, ct, dek, s.st.chunkMAC(s.sid, s.device, s.n, c[:], k[:])); err != nil {
		return err
	}
	s.total.Write(c[:])
	s.total.Write(k[:])
	s.n++
	return nil
}

/*
Input records a line before it is sent (stored at once). Any error means
the line must not be sent: ErrFailed (the recording failed, now or before)
or ErrFull (recording_max_mib reached).
*/
func (s *Stream) Input(ctx context.Context, line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.err != nil {
		return ErrFailed
	}
	s.flushCarry()
	if s.full || s.size >= s.limit || s.n >= maxChunks {
		if !s.full {
			s.full = true
			s.st.alert(ctx, KindFull, "warning", s.device, fmt.Sprintf("the recording of change session %s on device %d reached "+
				"recording_max_mib; the session sends no further line to the device (save, roll back or close it)", idString(s.sid), s.device))
		}
		if err := s.flush(ctx, false); err != nil {
			return err
		}
		return ErrFull
	}
	if err := s.flush(ctx, false); err != nil { /* what came before, so that a failure below is this line's alone */
		return err
	}
	at, size := len(s.buf), s.size
	s.event("i", s.input(line)+"\n")
	if err := s.flush(ctx, false); err != nil {
		s.undo(at, size) /* not sent: never recorded as sent */
		return err
	}
	return nil
}

/*
Output records the device's answer. Whole lines are masked and buffered;
the text after the last line end is held (unmasked, only here) until the
line ends, the next event or the end, at most maxCarry bytes.
*/
func (s *Stream) Output(ctx context.Context, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.err != nil {
		return ErrFailed
	}
	all := s.carry + text
	i := strings.LastIndexByte(all, '\n') + 1
	whole, rest := all[:i], all[i:]
	if len(rest) > maxCarry {
		whole, rest = all, ""
	}
	s.carry = rest
	if whole != "" {
		s.answer(whole)
	}
	return s.flush(ctx, true)
}

/*
answer records one answer, at most maxAnswer bytes of masked text: a longer
one is cut at a line end of the device's text (then of the masked text)
and a marker says how much was not recorded. This bounds what one answer
adds past recording_max_mib (replayBound).
*/
func (s *Stream) answer(whole string) {
	raw := whole
	if len(raw) > maxAnswer {
		cut := strings.LastIndexByte(raw[:maxAnswer], '\n') + 1
		if cut == 0 {
			cut = maxAnswer
		}
		raw = raw[:cut]
	}
	o := s.output(raw)
	if len(o) > maxAnswer {
		cut := maxAnswer
		for cut > 0 && !utf8.RuneStart(o[cut]) {
			cut--
		}
		o = o[:cut]
	}
	s.event("o", o)
	if len(raw) < len(whole) || len(o) < len(s.output(raw)) {
		s.event("m", fmt.Sprintf("the device's answer is cut here in the recording: %d bytes of it were not recorded (bound of one answer)",
			len(whole)-len(raw)))
	}
}

/* Mark records a marker of the executor (stored at once); it is recorded past recording_max_mib too. */
func (s *Stream) Mark(ctx context.Context, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.err != nil {
		return ErrFailed
	}
	s.flushCarry()
	over := s.size >= s.limit
	if over && s.pastLimit >= int64(markerBudget) {
		return ErrFull
	}
	if err := s.flush(ctx, false); err != nil {
		return err
	}
	at, size := len(s.buf), s.size
	s.event("m", s.label(label))
	if err := s.flush(ctx, false); err != nil {
		s.undo(at, size) /* the action is refused: its marker must not be stored later */
		return err
	}
	if over {
		s.pastLimit += s.size - size
	}
	return nil
}

/*
Close records the end marker, stores what is left (again after a failure:
nothing was sent since) and writes the manifest. A failure raises a high
alert: without its manifest the recording is never replayed.
*/
func (s *Stream) Close(ctx context.Context, label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.flushCarry()
	s.event("m", s.label(label))
	s.err = nil /* the retry of the buffer: Input refuses anyway once closed */
	err := s.flush(ctx, false)
	if err == nil {
		err = s.manifest(ctx)
		if err != nil {
			s.st.alert(ctx, KindFailed, "high", s.device, fmt.Sprintf("the manifest of the recording of change session %s on device "+
				"%d was not written; the recording cannot be replayed", idString(s.sid), s.device))
		}
	}
	return err
}

func (s *Stream) manifest(ctx context.Context) error {
	sum := s.total.Sum(nil)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recordTime)
	defer cancel()
	_, err := s.st.c.Pool.Exec(ctx, `INSERT INTO exec.recording_manifest (session_id, device_id, chunks, sha256, mac) VALUES ($1, $2, $3, $4, $5)`,
		s.sid, s.device, s.n, sum, s.st.manifestMAC(s.sid, s.device, s.n, sum))
	return err
}

/*
Recover finishes the recording of a device of a session a previous process
left without its end (Manager.Recover, before /x serves): when it has no
manifest, its chunks must all pass their MAC in order 0, 1, ...; then a
marker says what followed the last stored chunk is lost and the manifest is
written. A chunk that fails raises a high tamper alert and no manifest is
written (the replay refuses it).
*/
func (st *Store) Recover(ctx context.Context, session [16]byte, device int64, opened time.Time) error {
	qctx, cancel := context.WithTimeout(ctx, recordTime)
	defer cancel()
	var done bool
	if err := st.c.Pool.QueryRow(qctx, `SELECT EXISTS (SELECT 1 FROM exec.recording_manifest WHERE session_id = $1 AND device_id = $2)`,
		session, device).Scan(&done); err != nil || done {
		return err
	}
	rows, err := st.c.Pool.Query(qctx, `SELECT n, sha256(ct), sha256(dek_ct), mac FROM exec.recording_chunk
		WHERE session_id = $1 AND device_id = $2 ORDER BY n LIMIT $3`, session, device, maxChunks+1)
	if err != nil {
		return err
	}
	s := &Stream{st: st, sid: session, device: device, mask: func(t string) string { return t }, start: opened, total: sha256.New()}
	bad := ""
	for rows.Next() {
		var (
			n            int
			c, k, rowMAC []byte
		)
		if err := rows.Scan(&n, &c, &k, &rowMAC); err != nil {
			rows.Close()
			return err
		}
		switch {
		case bad != "":
		case n != s.n || s.n >= maxChunks:
			bad = fmt.Sprintf("chunk %d where %d belongs", n, s.n)
		case len(c) != sha256.Size || len(k) != sha256.Size || !hmac.Equal(rowMAC, st.chunkMAC(session, device, n, c, k)):
			bad = fmt.Sprintf("chunk %d fails its MAC", n)
		default:
			s.total.Write(c)
			s.total.Write(k)
			s.n++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if bad != "" {
		st.alert(ctx, KindTamper, "high", device, fmt.Sprintf("the recording of change session %s on device %d: %s; it cannot be "+
			"replayed", idString(session), device, bad))
		return nil
	}
	if s.n == 0 {
		s.header()
	}
	s.event("m", "recording recovered after an executor restart: what followed the last stored chunk is missing")
	if err := s.flush(ctx, false); err != nil {
		return err
	}
	return s.manifest(ctx)
}
