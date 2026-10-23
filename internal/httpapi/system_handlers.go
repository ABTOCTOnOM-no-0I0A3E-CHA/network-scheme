package httpapi

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type pollerStatus struct {
	ID               string     `json:"id"`
	Devices          int64      `json:"devices"`
	DevicesReporting int64      `json:"devices_reporting"` /* devices with a known state: 0 for a silent poller */
	HeartbeatAt      *time.Time `json:"heartbeat_at"`      /* last heartbeat; nil when the poller never wrote one */
}

type eventdStatus struct {
	Instance      string    `json:"instance"`
	UpdatedAt     time.Time `json:"updated_at"`
	Received      int64     `json:"received"`
	Accepted      int64     `json:"accepted"`
	UnknownSource int64     `json:"unknown_source"`
	AuthFailed    int64     `json:"auth_failed"`
	RateLimited   int64     `json:"rate_limited"`
	Dropped       int64     `json:"dropped"`
	QueueDepth    int32     `json:"queue_depth"`
}

type queueStatus struct {
	Name      string `json:"name"`
	Available int64  `json:"available"`
	Running   int64  `json:"running"`
	Retryable int64  `json:"retryable"`
}

type systemStatus struct {
	Now         time.Time      `json:"now"` /* server clock, the reference for updated_at */
	Pollers     []pollerStatus `json:"pollers"`
	Eventd      []eventdStatus `json:"eventd"`
	DBSizeBytes int64          `json:"db_size_bytes"`
	Queues      []queueStatus  `json:"queues"`
}

/*
systemStatus reports the health of the services as the database sees it. A
poller shows the devices it owns, how many of them report a state (the state
view hides the state of devices whose poller has been silent for 90 s) and its
last heartbeat (the api may read only the poller id and time of that table).
*/
func (s *server) systemStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := systemStatus{Now: s.now().UTC()}
	rows, err := s.pool.Query(ctx, `
		SELECT d.poller_id, count(*), count(*) FILTER (WHERE v.state <> 'unknown'), h.at
		FROM core.device d LEFT JOIN inventory.device_state_v v ON v.device_id = d.id
		LEFT JOIN inventory.poller_heartbeat h ON h.poller_id = d.poller_id
		GROUP BY d.poller_id, h.at ORDER BY d.poller_id`)
	if err == nil {
		out.Pollers, err = pgx.CollectRows(rows, pgx.RowToStructByPos[pollerStatus])
	}
	if err == nil {
		rows, err = s.pool.Query(ctx, `
			SELECT instance, updated_at, received, accepted, unknown_source, auth_failed, rate_limited, dropped, queue_depth
			FROM events.eventd_stats ORDER BY instance`)
		if err == nil {
			out.Eventd, err = pgx.CollectRows(rows, pgx.RowToStructByPos[eventdStatus])
		}
	}
	if err == nil {
		err = s.pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&out.DBSizeBytes)
	}
	if err == nil {
		rows, err = s.pool.Query(ctx, `
			SELECT queue, count(*) FILTER (WHERE state = 'available'), count(*) FILTER (WHERE state = 'running'),
			       count(*) FILTER (WHERE state = 'retryable')
			FROM jobs.river_job WHERE state IN ('available', 'running', 'retryable')
			GROUP BY queue ORDER BY queue`)
		if err == nil {
			out.Queues, err = pgx.CollectRows(rows, pgx.RowToStructByPos[queueStatus])
		}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out.Pollers == nil {
		out.Pollers = []pollerStatus{}
	}
	if out.Eventd == nil {
		out.Eventd = []eventdStatus{}
	}
	if out.Queues == nil {
		out.Queues = []queueStatus{}
	}
	writeJSON(w, http.StatusOK, out)
}
