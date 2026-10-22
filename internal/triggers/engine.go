package triggers

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/notify"
)

// Clock supplies the time the engine measures durations and watermarks with.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

/* Cadence: availability and events every tick, samples every second tick, system checks and config every sixth. */
const (
	tickInterval = 5 * time.Second
	midEvery     = 2
	slowEvery    = 6
	cycleTimeout = 30 * time.Second
	lockRetry    = 10 * time.Second
	lockPing     = 3 /* ticks between checks that the lock connection is alive */
)

/* lockKey is the advisory lock that keeps a second api process from running the engine. */
const lockKey int64 = 0x6e6d7374726967

// Config wires the engine to its dependencies.
type Config struct {
	Pool     *pgxpool.Pool
	Samples  SampleSource
	Channels []notify.Channel
	Clock    Clock /* nil: the wall clock */
	/* PollNow asks for an extra read-only poll of a device; nil: none. It is called at most once per device and PollNowGap. */
	PollNow func(ctx context.Context, deviceID int64) error
	Log     *slog.Logger
}

/* PollNowGap is the minimum gap between two extra polls requested for one device. */
const PollNowGap = 30 * time.Second

type devMeta struct {
	name  string
	group int64
}

/* tkey identifies the data-derived state of one trigger on one device object. */
type tkey struct {
	trig, dev int64
	obj       string
}

/* tracker is the in-memory part of the anti-flapping state: how long a condition has held and how often it was seen false. */
type tracker struct {
	firstTrue time.Time /* data timestamp at which the condition began to hold (zero: it does not) */
	lastTS    time.Time /* newest sample already applied */
	floor     time.Time /* samples at or before this are older than a trap fact and are ignored */
	falses    int       /* consecutive evaluations that found the condition false */
	lastEvent time.Time /* newest matching trap or syslog message (event problems auto-resolve after a quiet period) */
}

/*
Engine evaluates triggers and system conditions and maintains problems. It
only reads: device state, interface and system samples, traps, syslog, eventd
counters and access-profile status come from the database (never from
devices), and its only writes are rows of problems.problem and
problems.engine_state plus, through the optional PollNow hook, an extra
read-only poll request. Create it with New and run it with Run.
*/
type Engine struct {
	pool     *pgxpool.Pool
	samples  SampleSource
	channels []notify.Channel
	clock    Clock
	pollNow  func(ctx context.Context, deviceID int64) error
	log      *slog.Logger

	cfg       *config
	open      map[pkey]*openP
	meta      map[int64]devMeta
	trackers  map[tkey]*tracker
	wmSeq     map[string]int64 /* position of each event stream (ingest_seq) */
	held      map[pkey]heldReq /* openings postponed while an ancestor's outage is still pending */
	afterLoad func()           /* test hook: runs after the open problems were loaded */
	availFire map[int64]bool   /* devices whose availability condition fires now (set by evalAvailability) */
	upAt      time.Time        /* last full read of the interface inventory */
	sampleTo  time.Time
	sampleCut bool /* the last sample round stopped before reaching now */
	polled    map[int64]time.Time
	pollHints map[int64]time.Time
	unknown   map[string][]counterSample
	sysFalse  map[pkey]int
	supp      *suppressCtx
	seenUp    map[[2]int64]time.Time /* interface -> first time it was observed oper-up (zero: before the engine's data) */
}

// New returns an engine over c.
func New(c Config) *Engine {
	e := &Engine{pool: c.Pool, samples: c.Samples, channels: c.Channels, clock: c.Clock, pollNow: c.PollNow, log: c.Log, meta: map[int64]devMeta{}}
	if e.clock == nil {
		e.clock = realClock{}
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	e.resetMemory()
	return e
}

/* resetMemory forgets everything derived from earlier cycles; the next cycle re-reads its windows like a fresh start. */
func (e *Engine) resetMemory() {
	e.cfg, e.open = nil, nil
	e.trackers, e.wmSeq = map[tkey]*tracker{}, map[string]int64{}
	e.held, e.availFire, e.upAt = map[pkey]heldReq{}, map[int64]bool{}, time.Time{}
	e.sampleTo = time.Time{}
	e.seenUp = map[[2]int64]time.Time{}
	e.polled, e.pollHints, e.unknown, e.sysFalse = map[int64]time.Time{}, map[int64]time.Time{}, map[string][]counterSample{}, map[pkey]int{}
}

/*
Run evaluates until ctx ends. Only one engine runs per database: it holds a
session-level advisory lock on a dedicated connection and, without it, waits
and retries. Losing the lock connection stops the evaluation until it is won
again.
*/
func (e *Engine) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		conn, err := e.pool.Acquire(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			e.log.Warn("trigger engine: no connection", "error", err.Error())
			sleep(ctx, lockRetry)
			continue
		}
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
			conn.Release()
			if err != nil && ctx.Err() == nil {
				e.log.Warn("trigger engine: lock attempt failed", "error", err.Error())
			}
			sleep(ctx, lockRetry)
			continue
		}
		e.log.Info("trigger engine started")
		e.loop(ctx, conn)
		/* Unlock explicitly; closing a broken connection drops the lock anyway. */
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, lockKey); err != nil {
			_ = conn.Conn().Close(uctx) /* the lock dies with the connection */
		}
		cancel()
		conn.Release()
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

/* loop runs cycles while the lock connection stays healthy. */
func (e *Engine) loop(ctx context.Context, lock *pgxpool.Conn) {
	e.resetMemory()
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for n := 0; ; n++ {
		if n%lockPing == lockPing-1 {
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := lock.Conn().Ping(pctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					e.log.Warn("trigger engine: lost the lock connection", "error", err.Error())
				}
				return
			}
		}
		c := cycleFast
		if n == 0 {
			c = cycleAll
		} else {
			if n%midEvery == 0 {
				c |= cycleMid
			}
			if n%slowEvery == 0 {
				c |= cycleSlow
			}
		}
		cctx, cancel := context.WithTimeout(ctx, cycleTimeout)
		if err := e.cycle(cctx, c); err != nil && ctx.Err() == nil {
			e.log.Warn("trigger cycle failed", "error", err.Error())
			e.resetMemory()
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type cycleKind int

const (
	cycleFast cycleKind = 1 << iota
	cycleMid
	cycleSlow
	cycleAll = cycleFast | cycleMid | cycleSlow
)

/*
cycle runs one evaluation round. It collects every change into actions first
and writes them in one transaction, so a failure leaves the database as it was
(the caller then resets the memory and the next round starts like a restart).
*/
func (e *Engine) cycle(ctx context.Context, kind cycleKind) error {
	now := e.clock.Now()
	reloaded := false
	if e.cfg == nil || kind&cycleSlow != 0 {
		cfg, err := loadConfig(ctx, e.pool, now, e.log)
		if err != nil {
			return err
		}
		e.cfg, reloaded = cfg, true
		for id, d := range cfg.devices {
			e.meta[id] = devMeta{name: d.name, group: d.groupID}
		}
	}
	if err := e.loadOpen(ctx); err != nil {
		return err
	}
	if e.afterLoad != nil {
		e.afterLoad()
	}
	if reloaded {
		/* Names are kept for devices that still have an open problem (their resolution is announced this round). */
		for id := range e.meta {
			if _, ok := e.cfg.devices[id]; ok {
				continue
			}
			inUse := false
			for k := range e.open {
				if k.dev == id {
					inUse = true
					break
				}
			}
			if !inUse {
				delete(e.meta, id)
			}
		}
	}
	a := newActions()
	if reloaded {
		e.reconcile(a)
	}
	var errs []error
	collect := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	if kind&cycleFast != 0 {
		collect(e.evalAvailability(ctx, a, now))
		collect(e.evalEvents(ctx, a, now))
	}
	if kind&cycleMid != 0 {
		collect(e.evalSamples(ctx, a, now))
	}
	if kind&cycleSlow != 0 {
		collect(e.evalSystem(ctx, a, now))
	}
	if err := errors.Join(errs...); err != nil {
		/* A partial evaluation could resolve problems on missing data: write nothing. */
		return err
	}
	e.planSuppression(a, now)
	e.enrichInterfaceNames(ctx, a)
	if err := e.apply(ctx, a, now); err != nil {
		return err
	}
	if !a.sampleTo.IsZero() {
		e.sampleTo, e.sampleCut = a.sampleTo, a.sampleCut
	}
	for name, w := range a.wmSeq {
		e.wmSeq[name] = max(e.wmSeq[name], w)
	}
	e.requestPolls(ctx, now)
	return nil
}

/*
reconcile resolves, as "removed", the open problems whose device or trigger
is gone or no longer applies to the device (disabled, override, template or
group changed). It runs right after a configuration reload.
*/
func (e *Engine) reconcile(a *actions) {
	for k := range e.open {
		switch {
		case k.trig != 0:
			if _, ok := e.cfg.devices[k.dev]; !ok || e.cfg.eff[k.dev][k.trig] == nil {
				a.resolve(e, k, reasonRemoved, "", time.Time{})
			}
		case k.dev != 0:
			if _, ok := e.cfg.devices[k.dev]; !ok {
				a.resolve(e, k, reasonRemoved, "", time.Time{})
			}
		}
	}
	for k := range e.trackers {
		if e.cfg.eff[k.dev][k.trig] == nil {
			delete(e.trackers, k)
		}
	}
}

/* tracker returns (creating it) the tracker of k. */
func (e *Engine) tracker(k tkey) *tracker {
	t := e.trackers[k]
	if t == nil {
		t = &tracker{}
		e.trackers[k] = t
	}
	return t
}

/* requestPolls asks for the extra polls the cycle's traps called for. */
func (e *Engine) requestPolls(ctx context.Context, now time.Time) {
	for dev, at := range e.polled {
		if now.Sub(at) > PollNowGap {
			delete(e.polled, dev)
		}
	}
	for dev, at := range e.pollHints {
		delete(e.pollHints, dev)
		if e.pollNow == nil || at.Before(now.Add(-time.Minute)) {
			continue
		}
		if last, ok := e.polled[dev]; ok && now.Sub(last) < PollNowGap {
			continue
		}
		e.polled[dev] = now
		if err := e.pollNow(ctx, dev); err != nil {
			e.log.Warn("extra poll request failed", "device", dev, "error", err.Error())
		}
	}
}
