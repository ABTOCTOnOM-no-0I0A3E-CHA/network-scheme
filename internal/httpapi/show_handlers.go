package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/rbac"
)

/*
On-demand show commands. The api only validates and queues: a request names a
key of the device driver's show table (internal/drivers/showspec, a leaf
package: the api links no SSH code for this) and typed arguments, becomes a
row of backups.show_result owned by the session user, and a show_now job. The
poller checks everything again from the row and runs the command; the output
is untrusted text and is only ever returned as a JSON string.
*/
const (
	showsPerMinute = 10              /* show requests per user */
	showBusyWindow = 3 * time.Minute /* a queued or running row older than this no longer blocks its device (the poller's job timeout is shorter) */
	maxShowKeyLog  = 64              /* bytes of a rejected key recorded in the audit details */
)

var (
	errShowInvalid = errors.New("httpapi: invalid show command")
	errShowBusy    = errors.New("httpapi: a show command is running on the device")

	apiShowInvalid = apiError{http.StatusBadRequest, "invalid_show", "Недопустимая команда или аргументы"}
	apiShowBusy    = apiError{http.StatusConflict, "device_busy", "На устройстве уже выполняется команда"}
)

type showCommandInfo struct {
	Key  string   `json:"key"`
	Args []string `json:"args"`
}

type showCommandsResponse struct {
	Commands []showCommandInfo `json:"commands"`
}

/* listShowCommands lists the show commands of the device's driver with the kinds of their arguments. */
func (s *server) listShowCommands(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	d, err := s.authorizeDevice(r, rbac.PermDevicesShow, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := showCommandsResponse{Commands: []showCommandInfo{}}
	for _, sp := range showspec.For(d.Driver) {
		c := showCommandInfo{Key: sp.Key, Args: []string{}}
		for _, k := range sp.Args {
			c.Args = append(c.Args, string(k))
		}
		out.Commands = append(out.Commands, c)
	}
	writeJSON(w, http.StatusOK, out)
}

/* startShow queues a show command: key from the driver table, arguments typed, interfaces from this device's inventory. */
func (s *server) startShow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var body struct {
		Key  string          `json:"key"`
		Args json.RawMessage `json:"args"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	d, err := s.authorizeDevice(r, rbac.PermDevicesShow, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sc, _ := sessionFrom(r.Context())
	uid := sc.sess.UserID
	if !s.showRL.allow(uid, s.now(), showsPerMinute) {
		writeError(w, errRateLimited)
		return
	}
	var resultID int64
	ev := audit.Event{Action: "devices.show", ObjectType: "device", ObjectID: strconv.FormatInt(id, 10),
		Details: map[string]any{"key": clip(body.Key, maxShowKeyLog)}}
	if !s.change(w, r, ev, func(tx pgx.Tx, ev *audit.Event) error {
		spec, found := findSpec(showspec.For(d.Driver), body.Key)
		if !found {
			return errShowInvalid
		}
		vals, canon, err := showspec.ParseArgs(spec, body.Args)
		if err != nil {
			return errShowInvalid
		}
		for i, k := range spec.Args {
			if k != showspec.InterfaceName {
				continue
			}
			var member bool
			if err := tx.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM inventory.interface WHERE device_id = $1 AND name = $2)`, id, vals[i]).Scan(&member); err != nil {
				return err
			}
			if !member {
				return errShowInvalid
			}
		}
		ev.Details["args"] = json.RawMessage(canon)
		/* One command per device: the lock orders concurrent requests, the check refuses the second. */
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended('show:' || $1::bigint::text, 0))`, id); err != nil {
			return err
		}
		var busy bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM backups.show_result
WHERE device_id = $1 AND status IN ('queued', 'running') AND expires_at > now() AND requested_at > now() - make_interval(secs => $2))`,
			id, showBusyWindow.Seconds()).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return errShowBusy
		}
		if err := tx.QueryRow(r.Context(), `INSERT INTO backups.show_result (device_id, user_id, command_key, args) VALUES ($1, $2, $3, $4::jsonb) RETURNING id`,
			id, uid, spec.Key, string(canon)).Scan(&resultID); err != nil {
			return err
		}
		ev.Details["result_id"] = resultID
		return s.jobs.EnqueueShowNow(r.Context(), tx, id, resultID)
	}) {
		return
	}
	writeJSON(w, http.StatusAccepted, struct {
		ID int64 `json:"id"`
	}{resultID})
}

func findSpec(specs []showspec.Spec, key string) (showspec.Spec, bool) {
	for _, sp := range specs {
		if sp.Key == key {
			return sp, true
		}
	}
	return showspec.Spec{}, false
}

/* clip cuts s to at most n bytes at a character boundary. */
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

type showResultResponse struct {
	ID          int64           `json:"id"`
	DeviceID    int64           `json:"device_id"`
	Key         string          `json:"key"`
	Args        json.RawMessage `json:"args"`
	Status      string          `json:"status"`
	RequestedAt time.Time       `json:"requested_at"`
	FinishedAt  *time.Time      `json:"finished_at"`
	Output      *string         `json:"output"`
	Truncated   bool            `json:"truncated"`
}

/*
getShow returns a result to its author or a global admin, and only while the
caller still holds devices.show on the device's group. Every other case,
including an expired row, answers 404 alike.
*/
func (s *server) getShow(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, errNotFound)
		return
	}
	var (
		out    showResultResponse
		author int64
	)
	err = s.pool.QueryRow(r.Context(), `SELECT r.id, r.device_id, r.user_id, r.command_key, r.args, r.status, r.requested_at, r.finished_at, r.output, r.truncated
FROM backups.show_result r JOIN core.device d ON d.id = r.device_id
WHERE r.id = $1 AND r.expires_at > now()`, id).
		Scan(&out.ID, &out.DeviceID, &author, &out.Key, &out.Args, &out.Status, &out.RequestedAt, &out.FinishedAt, &out.Output, &out.Truncated)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, errNotFound)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.authorizeDevice(r, rbac.PermDevicesShow, out.DeviceID); err != nil {
		s.fail(w, r, err)
		return
	}
	subj, _ := r.Context().Value(keySubject).(rbac.Subject)
	if author != subj.UserID && !isGlobalAdmin(subj) {
		writeError(w, errNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

/* isGlobalAdmin: the subject holds the admin role without a group. */
func isGlobalAdmin(s rbac.Subject) bool {
	return slices.ContainsFunc(s.Bindings, func(b rbac.Binding) bool { return b.Role == rbac.RoleAdmin && b.GroupID == nil })
}
