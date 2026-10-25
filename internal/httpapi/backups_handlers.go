package httpapi

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/textdiff"
)

/* Limits of the backup endpoints. */
const (
	defaultBackupPage  = 50
	maxBackupPage      = 100
	maxDiffText        = 1 << 20 /* each masked text and the rendered diff, bytes (masked copies may reach 4 MiB: larger ones are not compared) */
	maxDiffEdits       = 2500    /* inserted plus deleted lines the diff computes */
	diffContext        = 3
	diffSlots          = 2
	diffWait           = 2 * time.Second /* how long a diff waits for a slot before answering 503 */
	backupsPerMinute   = 10              /* manual backups per user */
	backupGap          = 5 * time.Minute
	shaPrefixLen       = 12 /* hex characters of the hash shown */
	maxDownloadNameLen = 60
)

var (
	errDiffTooLarge = apiError{http.StatusRequestEntityTooLarge, "too_large", "Тексты слишком велики или слишком сильно различаются для сравнения"}
	errDiffBusy     = apiError{http.StatusServiceUnavailable, "busy", "Сервер занят сравнением конфигураций, повторите позже"}
)

/*
keyLimiter allows n events per key in any sliding minute. Keys with nothing
in the last minute are forgotten on every call, so it holds at most the keys
of the last minute's events.
*/
type keyLimiter[K comparable] struct {
	mu   sync.Mutex
	seen map[K][]time.Time
}

/* userLimiter allows n events per user in any sliding minute. */
type userLimiter = keyLimiter[int64]

func (l *keyLimiter[K]) allow(uid K, now time.Time, n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen == nil {
		l.seen = map[K][]time.Time{}
	}
	for u, ts := range l.seen { /* forget users with nothing recent */
		if len(ts) > 0 && now.Sub(ts[len(ts)-1]) >= time.Minute {
			delete(l.seen, u)
		}
	}
	ts := l.seen[uid]
	for len(ts) > 0 && now.Sub(ts[0]) >= time.Minute {
		ts = ts[1:]
	}
	if len(ts) >= n {
		l.seen[uid] = ts
		return false
	}
	l.seen[uid] = append(ts, now)
	return true
}

/* refund forgets the event allow admitted at now (for an action that did not happen after all). */
func (l *keyLimiter[K]) refund(uid K, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.seen[uid]
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(now) {
			l.seen[uid] = append(ts[:i:i], ts[i+1:]...)
			return
		}
	}
}

type backupVersion struct {
	ID      int64     `json:"id"`
	TakenAt time.Time `json:"taken_at"`
	Source  string    `json:"source"`
	Size    int       `json:"size"`
	SHA256  string    `json:"sha256"` /* prefix */
	Drift   bool      `json:"drift"`
}

type backupCursor struct {
	T  int64 `json:"t"` /* taken_at, microseconds since the epoch */
	ID int64 `json:"i"`
}

/* scanVersion reads the columns id, taken_at, source, size, sha256, drift. */
func scanVersion(row pgx.Row) (backupVersion, error) {
	var v backupVersion
	var sha []byte
	if err := row.Scan(&v.ID, &v.TakenAt, &v.Source, &v.Size, &sha, &v.Drift); err != nil {
		return v, err
	}
	v.SHA256 = shaPrefix(sha)
	return v, nil
}

func shaPrefix(sha []byte) string {
	h := hex.EncodeToString(sha)
	if len(h) > shaPrefixLen {
		h = h[:shaPrefixLen]
	}
	return h
}

/*
Version queries name their columns (the api role may not read the ciphertext
columns of backups.config_version) and join core.device: versions of a deleted
device are visible to nobody.
*/
const versionCols = `v.id, v.taken_at, v.source, v.size, v.sha256, v.drift`

/* versionID parses the {vid} URL parameter; anything but a positive integer answers 404. */
func versionID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "vid"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, errNotFound)
		return 0, false
	}
	return id, true
}

/* listBackups lists the versions of a device, newest first, with an opaque cursor over (taken_at, id). */
func (s *server) listBackups(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	curS, okC := single(q, "cursor")
	limit, okL := queryInt(q, "limit", defaultBackupPage, 1, maxBackupPage)
	var cur backupCursor
	if curS != "" {
		okC = okC && decodeCursor(curS, &cur) && cur.ID > 0
	}
	if !okC || !okL {
		writeError(w, errBadRequest)
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT `+versionCols+`
FROM backups.config_version v JOIN core.device d ON d.id = v.device_id
WHERE v.device_id = $1 AND ($2::bool = false OR (v.taken_at, v.id) < ($3, $4))
ORDER BY v.taken_at DESC, v.id DESC LIMIT $5`, id, curS != "", time.UnixMicro(cur.T).UTC(), cur.ID, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (backupVersion, error) { return scanVersion(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1]
		c := encodeCursor(backupCursor{T: last.TakenAt.UnixMicro(), ID: last.ID})
		next = &c
	}
	if items == nil {
		items = []backupVersion{}
	}
	writeJSON(w, http.StatusOK, struct {
		Items      []backupVersion `json:"items"`
		NextCursor *string         `json:"next_cursor"`
	}{items, next})
}

/* maskedVersion loads one version of device id with its masked text; pgx.ErrNoRows when absent. */
func (s *server) maskedVersion(ctx context.Context, device, vid int64) (backupVersion, string, error) {
	var text string
	var v backupVersion
	var sha []byte
	err := s.pool.QueryRow(ctx, `SELECT `+versionCols+`, v.masked
FROM backups.config_version v JOIN core.device d ON d.id = v.device_id
WHERE v.device_id = $1 AND v.id = $2`, device, vid).Scan(&v.ID, &v.TakenAt, &v.Source, &v.Size, &sha, &v.Drift, &text)
	v.SHA256 = shaPrefix(sha)
	return v, text, err
}

/* getBackup serves the masked text of a version (JSON; as plain text it is served by download). */
func (s *server) getBackup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	vid, ok := versionID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	v, text, err := s.maskedVersion(r.Context(), id, vid)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, errNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		backupVersion
		Text string `json:"text"`
	}{v, text})
}

/* downloadName builds "<device>-<taken_at>.txt" from characters that are safe in a header and on any file system. */
func downloadName(device string, taken time.Time) string {
	var sb strings.Builder
	for _, c := range device {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			sb.WriteRune(c)
		default:
			sb.WriteByte('_')
		}
		if sb.Len() >= maxDownloadNameLen {
			break
		}
	}
	name := strings.Trim(sb.String(), "_")
	if name == "" {
		name = "device"
	}
	return name + "-" + taken.UTC().Format("20060102T150405Z") + ".txt"
}

/*
downloadBackup serves the masked text as a plain-text attachment. Downloads
are audited, at most one record per user a minute: repeated downloads must not
become a flood of audit records.
*/
func (s *server) downloadBackup(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	vid, ok := versionID(w, r)
	if !ok {
		return
	}
	d, err := s.authorizeDevice(r, rbac.PermDevicesRead, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, text, err := s.maskedVersion(r.Context(), id, vid)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, errNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sc, _ := sessionFrom(r.Context())
	if s.downloadAuditRL.allow([2]int64{sc.sess.UserID, id}, s.now(), 1) {
		ev := audit.Event{Action: "devices.backup_download", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{"version_id": vid}}
		if !s.change(w, r, ev, func(pgx.Tx, *audit.Event) error { return nil }) {
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+downloadName(d.Name, v.TakenAt)+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(text))
}

type diffSide struct {
	ID      int64     `json:"id"`
	TakenAt time.Time `json:"taken_at"`
}

/*
diffBackups returns the unified diff of the masked texts of two versions of
one device (a: before, b: after). Texts over 1 MiB or textdiff.MaxLines
lines, a diff over 1 MiB or one with too many changed lines answer 413
too_large; with every diff slot taken for diffWait the answer is 503 busy.
The slot is taken before the texts are loaded, so at most diffSlots pairs
are held in memory.
*/
func (s *server) diffBackups(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	parse := func(name string) (int64, bool) {
		v, ok := single(q, name)
		n, err := strconv.ParseInt(v, 10, 64)
		return n, ok && err == nil && n > 0
	}
	a, okA := parse("a")
	b, okB := parse("b")
	if !okA || !okB {
		writeError(w, errBadRequest)
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	/* Sizes and line counts first, so that an oversized text is never loaded. */
	rows, err := s.pool.Query(r.Context(), `SELECT v.id, octet_length(v.masked), octet_length(v.masked) - octet_length(replace(v.masked, chr(10), ''))
FROM backups.config_version v JOIN core.device d ON d.id = v.device_id
WHERE v.device_id = $1 AND v.id = ANY($2)`, id, []int64{a, b})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sizes := map[int64]int{}
	tooLarge := false
	for rows.Next() {
		var vid int64
		var n, newlines int
		if err := rows.Scan(&vid, &n, &newlines); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		sizes[vid] = n
		/* a last line without a newline is one more: textdiff refuses that case itself after loading */
		tooLarge = tooLarge || n > maxDiffText || newlines > textdiff.MaxLines
	}
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, ok := sizes[a]; !ok {
		writeError(w, errNotFound)
		return
	}
	if _, ok := sizes[b]; !ok {
		writeError(w, errNotFound)
		return
	}
	if tooLarge {
		writeError(w, errDiffTooLarge)
		return
	}
	select {
	case s.diffSem <- struct{}{}:
		defer func() { <-s.diffSem }()
	case <-time.After(diffWait):
		w.Header().Set("Retry-After", "1")
		writeError(w, errDiffBusy)
		return
	case <-r.Context().Done():
		return
	}
	va, ta, err := s.maskedVersion(r.Context(), id, a)
	if err == nil {
		var vb backupVersion
		var tb string
		if vb, tb, err = s.maskedVersion(r.Context(), id, b); err == nil {
			s.writeDiff(w, r, va, vb, ta, tb)
			return
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, errNotFound)
		return
	}
	s.fail(w, r, err)
}

func (s *server) writeDiff(w http.ResponseWriter, r *http.Request, va, vb backupVersion, ta, tb string) {
	label := func(v backupVersion) string {
		return "version " + strconv.FormatInt(v.ID, 10) + " " + v.TakenAt.UTC().Format(time.RFC3339)
	}
	d, err := textdiff.Unified(r.Context(), label(va), label(vb), ta, tb, diffContext, maxDiffEdits)
	if r.Context().Err() != nil {
		return /* the client is gone */
	}
	if errors.Is(err, textdiff.ErrTooLarge) || len(d) > maxDiffText {
		writeError(w, errDiffTooLarge)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		A    diffSide `json:"a"`
		B    diffSide `json:"b"`
		Diff string   `json:"diff"`
	}{diffSide{va.ID, va.TakenAt}, diffSide{vb.ID, vb.TakenAt}, d})
}

/*
backupNow queues a manual backup. The poller keeps its own per-device gap
(5 minutes): when the last successful backup is younger, the job completes
without fetching and the answer says so in note.
*/
func (s *server) backupNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesBackup, id); err != nil {
		s.fail(w, r, err)
		return
	}
	sc, _ := sessionFrom(r.Context())
	uid, at := sc.sess.UserID, s.now()
	if !s.backupRL.allow(uid, at, backupsPerMinute) {
		/* Audited, but at most once a minute per user, like refused show requests. */
		if s.backupAuditRL.allow(uid, at, 1) {
			ev := audit.Event{Action: "devices.backup_now", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{}}
			s.change(w, r, ev, func(pgx.Tx, *audit.Event) error { return auth.ErrRateLimited })
			return
		}
		writeError(w, errRateLimited)
		return
	}
	var recent bool
	if err := s.pool.QueryRow(r.Context(), `SELECT COALESCE((SELECT last_ok_at > now() - make_interval(secs => $2) FROM backups.backup_state WHERE device_id = $1), false)`,
		id, backupGap.Seconds()).Scan(&recent); err != nil {
		s.fail(w, r, err)
		return
	}
	ev := audit.Event{Action: "devices.backup_now", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10), Details: map[string]any{"recent_backup": recent}}
	if !s.change(w, r, ev, func(tx pgx.Tx, _ *audit.Event) error {
		return s.jobs.EnqueueBackupNow(r.Context(), tx, id, "manual")
	}) {
		/* nothing was queued (the transaction rolled back): the attempt does not count */
		s.backupRL.refund(uid, at)
		return
	}
	resp := struct {
		Note string `json:"note,omitempty"`
	}{}
	if recent {
		resp.Note = "recent backup exists"
	}
	writeJSON(w, http.StatusAccepted, resp)
}

type backupStateResponse struct {
	LastOKAt   *time.Time     `json:"last_ok_at"`
	LastError  *string        `json:"last_error"`
	NeedsWrite bool           `json:"needs_write"`
	LastSHA256 *string        `json:"last_sha256"` /* prefix */
	Latest     *backupVersion `json:"latest_version"`
}

/* backupState reports the state of the last backup attempt and the newest version (with its drift flag). */
func (s *server) backupState(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var out backupStateResponse
	var sha []byte
	err := s.pool.QueryRow(r.Context(), `SELECT last_ok_at, last_error, needs_write, last_sha256 FROM backups.backup_state WHERE device_id = $1`, id).
		Scan(&out.LastOKAt, &out.LastError, &out.NeedsWrite, &sha)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		s.fail(w, r, err)
		return
	}
	if sha != nil {
		p := shaPrefix(sha)
		out.LastSHA256 = &p
	}
	v, err := scanVersion(s.pool.QueryRow(r.Context(), `SELECT `+versionCols+`
FROM backups.config_version v JOIN core.device d ON d.id = v.device_id
WHERE v.device_id = $1 ORDER BY v.taken_at DESC, v.id DESC LIMIT 1`, id))
	switch {
	case err == nil:
		out.Latest = &v
	case !errors.Is(err, pgx.ErrNoRows):
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
