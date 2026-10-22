/*
Package eventd receives syslog (UDP 514, TCP 514, TLS 6514) and SNMP traps and
informs (UDP 162) from the devices and stores them in the events schema.

Everything arriving here is untrusted. A packet is used only when the peer
address of the datagram or connection belongs to exactly one known device
(names and addresses inside messages never count) and, for traps, proves the
read credentials of that device. Packets from other addresses are counted
(unknown_source) and dropped before any parsing; packets that fail the
credentials are counted (auth_failed) and dropped. eventd opens no outgoing
connection except the database; the only datagram it ever sends is the
acknowledgement of an authenticated SNMPv1/v2c INFORM to its sender.

gosnmp's TrapListener is deliberately not used: it parses before the source can
be checked, acknowledges every INFORM whatever the verdict, and answers v3
engine discovery from any address. eventd reads the datagrams itself and uses
gosnmp only to decode them (UnmarshalTrap with the USM table of the one source
device).
*/
package eventd

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/curve25519"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/events/syslog"
	"github.com/beekamai/network-scheme/internal/events/trap"
	"github.com/beekamai/network-scheme/internal/jobs"
)

const (
	resyncEvery   = 5 * time.Minute        /* full reread even without notifications */
	settleFor     = 300 * time.Millisecond /* coalesces a burst of notifications */
	relistenAfter = 2 * time.Second
	pollGap       = 30 * time.Second /* least time between two poll_now requests of a device */
	callTimeout   = 10 * time.Second /* one database round trip of a background loop */
	drainTimeout  = 10 * time.Second /* shutdown: how long the writer may take for what is queued */
	udpQueue      = 1024
	udpReadBuf    = 8 << 20
	maxTrapPacket = 65535
	slowDevRate   = 0.1 /* one SNMPv3 key derivation per 10 s per device (burst 3, so a genuine first trap has a chance against a slow spoofer) ... */
	slowDevBurst  = 3
	slowAllRate   = 5 /* ... and 5 per second in total: ~6 ms of CPU each */
	slowAllBurst  = 5
)

/* Notification channels. */
const (
	chanDevices = "device_changed"
	chanRules   = "trap_rules"
)

/* PollEnqueuer queues an immediate poll; *jobs.Enqueuer implements it. */
type PollEnqueuer interface {
	EnqueuePollNow(ctx context.Context, tx pgx.Tx, deviceID int64) error
}

/* Addrs are the bound listener addresses (nil for a disabled listener). */
type Addrs struct {
	SyslogUDP, SyslogTCP, SyslogTLS, TrapUDP net.Addr
}

/*
Deps are the collaborators of Run. Pool is the nms_eventd connection pool;
Priv and Pub are the read-domain key pair. The rest has defaults.
*/
type Deps struct {
	Pool      *pgxpool.Pool
	Priv, Pub *[32]byte
	Logger    *slog.Logger
	Enqueuer  PollEnqueuer
	Registry  *drivers.Registry
	Clock     func() time.Time
	/* Ready, when set, is called once all listeners are bound. */
	Ready func(Addrs)
	/* StatsEvery overrides the 10 s stats interval (tests). */
	StatsEvery time.Duration
}

type ruleSet struct{ m map[string]trap.Rule }

type server struct {
	cfg      config.EventD
	pool     *pgxpool.Pool
	log      *slog.Logger
	now      func() time.Time
	instance string

	src     *sources
	q       *queue
	lim     *limiter
	slowDev *limiter /* SNMPv3 messages with an unpinned engine, per device */
	slowAll *limiter /* the same, in total */
	storm   *storm
	st      stats
	polls   *pollTrigger
	rules   atomic.Pointer[ruleSet]
	conns   *conns
	hsLast  atomic.Int64 /* unix nanoseconds of the last logged TLS handshake failure */
	hsSkip  atomic.Int64 /* failures since then that were not logged */
}

/*
Run serves until ctx ends: listeners, the batch writer, stats, device and rule
reloads. It fails only when the initial device list or rules cannot be read or
a listener cannot be bound; later database errors are logged and retried.
On shutdown the queue and the pending storm rows are written (up to 10 s).
*/
func Run(ctx context.Context, cfg config.EventD, deps Deps) error {
	s := newServer(cfg, deps)
	if err := s.src.reload(ctx, s.pool); err != nil {
		return err
	}
	if err := s.loadRules(ctx); err != nil {
		return err
	}
	done := make(chan struct{})
	var rx sync.WaitGroup /* receivers: end first */
	addrs, closers, err := s.listen(&rx, done)
	if err != nil {
		close(done)
		for _, c := range closers {
			_ = c.Close()
		}
		return err
	}
	var bg sync.WaitGroup /* background loops: end with ctx */
	wctx, cancelWrite := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWrite()
	w := &writer{pool: s.pool, st: &s.st, log: s.log, size: cfg.BatchSize, wait: cfg.BatchInterval}
	wdone := make(chan struct{})
	go func() { defer close(wdone); w.run(wctx, s.q) }()
	bg.Go(func() { s.src.seedPending(ctx) })
	bg.Go(func() { s.listenDB(ctx) })
	bg.Go(func() { s.statsLoop(ctx, deps.StatsEvery) })
	bg.Go(func() { s.stormLoop(ctx) })
	bg.Go(func() { s.polls.run(ctx, s.pool, s.log) })
	s.log.Info("eventd started", slog.String("instance", s.instance))
	if deps.Ready != nil {
		deps.Ready(addrs)
	}

	<-ctx.Done()
	close(done)
	for _, c := range closers {
		_ = c.Close()
	}
	rx.Wait()
	bg.Wait()
	s.storm.flush()
	s.q.close()
	select {
	case <-wdone:
	case <-time.After(drainTimeout):
		cancelWrite()
		<-wdone
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.st.flush(sctx, s.pool, s.instance, 0); err != nil {
		s.log.Warn("final stats write failed", slog.String("err", err.Error()))
	}
	return nil
}

func newServer(cfg config.EventD, deps Deps) *server {
	s := &server{cfg: cfg, pool: deps.Pool, log: deps.Logger, now: deps.Clock, instance: Instance(cfg)}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	reg := deps.Registry
	if reg == nil {
		reg = drivers.Default()
	}
	enq := deps.Enqueuer
	if enq == nil {
		e, err := jobs.NewEnqueuer(deps.Pool)
		if err != nil {
			panic(err) /* only a bad River config: a programming error */
		}
		enq = e
	}
	s.src = newSources(deps.Priv, deps.Pub, reg, s.now, s.log)
	s.q = newQueue(cfg.QueueSize, cfg.QueueBytes)
	s.lim = newLimiter(cfg.RatePerSource, cfg.RateBurst)
	s.slowDev, s.slowAll = newLimiterF(slowDevRate, slowDevBurst), newLimiterF(slowAllRate, slowAllBurst)
	s.storm = newStorm(s.emit)
	s.polls = newPollTrigger(enq, s.now)
	s.conns = &conns{max: cfg.MaxTCPConns, per: map[netip.Addr]int{}}
	s.rules.Store(&ruleSet{m: map[string]trap.Rule{}})
	return s
}

/*
safely runs the processing of one packet. A panic on hostile input is counted
(as malformed) and logged without the packet; the worker lives on.
*/
func (s *server) safely(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			s.st.panics.Add(1)
			s.st.malformed.Add(1)
			s.log.Error("panic while processing a packet", slog.String("panic", fmt.Sprintf("%T", r)))
		}
	}()
	fn()
}

/* emit queues a storm row; a full queue loses it (its count goes to dropped). */
func (s *server) emit(e event) {
	if !s.q.push(e) {
		s.st.dropped.Add(uint64(e.count)) // #nosec G115 -- a storm row has count > 0
	}
}

func (s *server) known(ip netip.Addr) bool {
	_, rel, ok := s.src.acquire(ip)
	if ok {
		rel()
	}
	return ok
}

/*
admit applies the rate limit of the source and queues the event. Above the
limit an event is folded into the storm row of its source and minute. It
reports whether the event was taken (queued or folded).
*/
func (s *server) admit(d *device, k kind, e event) bool {
	now := s.now()
	if !s.lim.allow(d.id, now) {
		s.storm.add(d.id, k, now)
		s.st.rateLimited.Add(1)
		return true
	}
	if s.q.push(e) {
		s.st.accepted.Add(1)
		return true
	}
	s.st.dropped.Add(1)
	return false
}

/* listen binds the configured listeners and starts them; closers stop them. */
func (s *server) listen(rx *sync.WaitGroup, done <-chan struct{}) (Addrs, []interface{ Close() error }, error) {
	var (
		a       Addrs
		closers []interface{ Close() error }
		lc      net.ListenConfig
	)
	on := func(addr string) bool { return addr != "" && addr != config.Off }
	ctx := context.Background()
	if on(s.cfg.SyslogUDP) {
		pc, err := lc.ListenPacket(ctx, "udp", s.cfg.SyslogUDP)
		if err != nil {
			return a, closers, fmt.Errorf("eventd: listen syslog udp: %w", err)
		}
		c := pc.(*net.UDPConn)
		closers = append(closers, c)
		a.SyslogUDP = c.LocalAddr()
		s.pumpUDP(rx, c, syslog.MaxMessage+1, func(ip netip.Addr, _ netip.AddrPort, b []byte) { s.handleSyslog(ip, b) })
	}
	if on(s.cfg.TrapUDP) {
		pc, err := lc.ListenPacket(ctx, "udp", s.cfg.TrapUDP)
		if err != nil {
			return a, closers, fmt.Errorf("eventd: listen trap udp: %w", err)
		}
		c := pc.(*net.UDPConn)
		closers = append(closers, c)
		a.TrapUDP = c.LocalAddr()
		s.pumpUDP(rx, c, maxTrapPacket, func(ip netip.Addr, from netip.AddrPort, b []byte) {
			s.handleTrap(ip, b, func(out []byte) { _, _ = c.WriteToUDPAddrPort(out, from) })
		})
	}
	if on(s.cfg.SyslogTCP) {
		l, err := lc.Listen(ctx, "tcp", s.cfg.SyslogTCP)
		if err != nil {
			return a, closers, fmt.Errorf("eventd: listen syslog tcp: %w", err)
		}
		closers = append(closers, l)
		a.SyslogTCP = l.Addr()
		rx.Go(func() { s.serveStream(l, nil, rx, done) })
	}
	if on(s.cfg.SyslogTLS) {
		if s.cfg.TLSCertFile == "" {
			s.log.Info("syslog over TLS disabled: no certificate configured")
		} else {
			cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
			if err != nil {
				return a, closers, fmt.Errorf("eventd: load tls certificate: %w", err)
			}
			l, err := lc.Listen(ctx, "tcp", s.cfg.SyslogTLS)
			if err != nil {
				return a, closers, fmt.Errorf("eventd: listen syslog tls: %w", err)
			}
			closers = append(closers, l)
			a.SyslogTLS = l.Addr()
			/* No session tickets: a sender that writes and closes without reading them makes the kernel reset the connection and lose its message. */
			tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true, ClientAuth: tls.NoClientCert}
			rx.Go(func() { s.serveStream(l, tc, rx, done) })
		}
	}
	return a, closers, nil
}

type udpPacket struct {
	ip   netip.Addr
	from netip.AddrPort
	data []byte
}

/*
pumpUDP reads datagrams from c (size bytes at most; a longer one is cut and
then fails parsing) and hands them to workers, so that slow processing (SNMPv3
verification) does not make the kernel buffer overflow. A datagram from an
address that is not a known device is counted and dropped right here, before
it is copied or queued. A full hand-over queue drops the datagram and counts
it.
*/
func (s *server) pumpUDP(rx *sync.WaitGroup, c *net.UDPConn, size int, handle func(ip netip.Addr, from netip.AddrPort, b []byte)) {
	_ = c.SetReadBuffer(udpReadBuf)
	ch := make(chan udpPacket, udpQueue)
	var ww sync.WaitGroup
	for range max(2, runtime.GOMAXPROCS(0)) {
		ww.Go(func() {
			for p := range ch {
				s.safely(func() { handle(p.ip, p.from, p.data) })
			}
		})
	}
	rx.Go(func() {
		defer func() { close(ch); ww.Wait() }()
		buf := make([]byte, size)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue /* e.g. an ICMP port unreachable surfacing on Windows: not fatal */
			}
			s.st.received.Add(1)
			ip := from.Addr().Unmap().WithZone("")
			if !s.known(ip) {
				s.st.unknownSource.Add(1)
				continue
			}
			select {
			case ch <- udpPacket{ip: ip, from: from, data: append([]byte(nil), buf[:n]...)}:
			default:
				s.st.dropped.Add(1)
			}
		}
	})
}

/* stormLoop writes the storm rows of finished minutes. */
func (s *server) stormLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.storm.sweep(now)
		}
	}
}

/* statsLoop mirrors the counters into events.eventd_stats, logs losses and sweeps expired replay entries. */
func (s *server) statsLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = statsEvery
	}
	t := time.NewTicker(every)
	defer t.Stop()
	var lastDropped, lastMalformed, lastFailed, lastSlow, lastInform, lastPanics, lastRollbacks, lastReplayed, lastFull uint64
	sweep := 0
	for {
		sweep = s.src.sweepReplay(s.now(), sweep, replaySweepMax)
		if full := replayFull.Load(); full != lastFull {
			s.log.Warn("v3 replay cache full: authenticated messages not remembered", slog.Uint64("v3_replay_cache_full", full-lastFull),
				slog.Int64("entries", replayEntries.Load()))
			lastFull = full
		}
		fctx, cancel := context.WithTimeout(ctx, callTimeout)
		err := s.st.flush(fctx, s.pool, s.instance, s.q.depth())
		cancel()
		if err != nil && ctx.Err() == nil {
			s.log.Warn("stats write failed", slog.String("err", err.Error()))
		}
		d, m, f := s.st.dropped.Load(), s.st.malformed.Load(), s.st.authFailed.Load()
		sl, in, pa, rb := s.st.slowDropped.Load(), s.st.v3Inform.Load(), s.st.panics.Load(), s.src.rollbacks.Load()
		rp := s.st.replayed.Load()
		if d != lastDropped || m != lastMalformed || f != lastFailed || sl != lastSlow || in != lastInform || pa != lastPanics || rb != lastRollbacks || rp != lastReplayed {
			s.log.Warn("events refused", slog.Uint64("dropped", d-lastDropped), slog.Uint64("malformed", m-lastMalformed),
				slog.Uint64("auth_failed", f-lastFailed), slog.Uint64("v3_budget_exceeded", sl-lastSlow),
				slog.Uint64("v3_inform_unsupported", in-lastInform), slog.Uint64("panics", pa-lastPanics),
				slog.Uint64("credential_rollbacks", rb-lastRollbacks), slog.Uint64("v3_replayed", rp-lastReplayed), slog.Int("queue", s.q.depth()))
			lastDropped, lastMalformed, lastFailed, lastSlow, lastInform, lastPanics, lastRollbacks, lastReplayed = d, m, f, sl, in, pa, rb, rp
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

/* loadRules rereads the operator trap rules. */
func (s *server) loadRules(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	rows, err := s.pool.Query(ctx, `SELECT trap_oid, name, severity FROM events.trap_rule`)
	if err != nil {
		return fmt.Errorf("eventd: load trap rules: %w", err)
	}
	m := map[string]trap.Rule{}
	var oid string
	var r trap.Rule
	if _, err := pgx.ForEachRow(rows, []any{&oid, &r.Name, &r.Severity}, func() error {
		m[oid] = r
		return nil
	}); err != nil {
		return fmt.Errorf("eventd: load trap rules: %w", err)
	}
	s.rules.Store(&ruleSet{m: m})
	return nil
}

/*
listenDB rereads the devices on every device_changed notification and the trap
rules on trap_rules (after a short settle time), every 5 minutes, and after
reconnecting.
*/
func (s *server) listenDB(ctx context.Context) {
	for {
		err := s.listenOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		s.log.Warn("change listener failed", slog.String("err", err.Error()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(relistenAfter):
		}
	}
}

func (s *server) listenOnce(ctx context.Context) error {
	actx, cancel := context.WithTimeout(ctx, callTimeout)
	c, err := s.pool.Acquire(actx)
	cancel()
	if err != nil {
		return err
	}
	conn := c.Hijack() /* a LISTENing connection never goes back to the pool */
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), relistenAfter)
		defer cancel()
		_ = conn.Close(cctx)
	}()
	for _, ch := range []string{chanDevices, chanRules} {
		lctx, cancel := context.WithTimeout(ctx, callTimeout)
		_, err := conn.Exec(lctx, `LISTEN `+ch)
		cancel()
		if err != nil {
			return err
		}
	}
	/* Reread after LISTEN: no change between the first load and now is missed. */
	if err := s.reloadAll(ctx, true, true); err != nil {
		return err
	}
	wait := func(d time.Duration) (ch string, got bool, err error) {
		wctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		n, err := conn.WaitForNotification(wctx)
		switch {
		case err == nil:
			return n.Channel, true, nil
		case ctx.Err() == nil && errors.Is(wctx.Err(), context.DeadlineExceeded):
			return "", false, nil
		default:
			return "", false, err
		}
	}
	for {
		ch, got, err := wait(resyncEvery)
		if err != nil {
			return err
		}
		devs, rules := !got || ch == chanDevices, !got || ch == chanRules
		for {
			ch, more, err := wait(settleFor)
			if err != nil {
				return err
			}
			if !more {
				break
			}
			devs, rules = devs || ch == chanDevices, rules || ch == chanRules
		}
		if err := s.reloadAll(ctx, devs, rules); err != nil {
			return err
		}
	}
}

func (s *server) reloadAll(ctx context.Context, devs, rules bool) error {
	if devs {
		rctx, cancel := context.WithTimeout(ctx, 3*callTimeout)
		err := s.src.reload(rctx, s.pool)
		cancel()
		if err != nil {
			return err
		}
		s.src.seedPending(ctx)
		ids := s.src.ids()
		keep := func(id int64) bool { _, ok := ids[id]; return ok }
		s.lim.prune(keep)
		s.slowDev.prune(keep)
	}
	if rules {
		return s.loadRules(ctx)
	}
	return nil
}

/* ids returns the ids of the devices in the current table. */
func (s *sources) ids() map[int64]struct{} {
	all := s.cur.Load().all
	m := make(map[int64]struct{}, len(all))
	for _, d := range all {
		m[d.id] = struct{}{}
	}
	return m
}

/*
pollTrigger asks for an immediate poll of a device whose trap changes its
state, at most once per pollGap. A request counts as made only when it was
queued; while one is in flight, further ones for the device are dropped.
*/
type pollTrigger struct {
	enq     PollEnqueuer
	now     func() time.Time
	mu      sync.Mutex
	last    map[int64]time.Time /* when the last request was queued */
	pending map[int64]bool
	ch      chan int64
}

func newPollTrigger(enq PollEnqueuer, now func() time.Time) *pollTrigger {
	return &pollTrigger{enq: enq, now: now, last: map[int64]time.Time{}, pending: map[int64]bool{}, ch: make(chan int64, 256)}
}

func (p *pollTrigger) request(id int64) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.last[id]; (ok && now.Sub(t) < pollGap) || p.pending[id] {
		return
	}
	select {
	case p.ch <- id:
		p.pending[id] = true
	default: /* a burst of state traps from many devices: the regular polls follow anyway */
	}
}

/* done records the outcome of a request and forgets the entries that no longer throttle. */
func (p *pollTrigger) done(id int64, ok bool) {
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, id)
	if ok {
		p.last[id] = now
	}
	for k, t := range p.last {
		if now.Sub(t) >= pollGap {
			delete(p.last, k)
		}
	}
}

func (p *pollTrigger) run(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case id := <-p.ch:
			err := p.enqueue(ctx, pool, id)
			p.done(id, err == nil)
			if err != nil && ctx.Err() == nil {
				log.Warn("poll request failed", slog.Int64("device_id", id), slog.String("err", err.Error()))
			}
		}
	}
}

func (p *pollTrigger) enqueue(ctx context.Context, pool *pgxpool.Pool, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := p.enq.EnqueuePollNow(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

/* Instance returns the name under which cfg's process records its stats: instance, else the host name. */
func Instance(cfg config.EventD) string {
	if cfg.Instance != "" {
		return cfg.Instance
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "eventd"
}

/*
ReadKeys reads the read-domain key pair and checks that the public key belongs
to the private key, so a mixed-up file fails at start, not as "undecryptable"
on every credential.
*/
func ReadKeys(cfg config.EventD) (priv, pub *[32]byte, err error) {
	if priv, err = config.ReadKeyFile(cfg.ReadKeyFile); err != nil {
		return nil, nil, err
	}
	if pub, err = config.ReadKeyFile(cfg.ReadPubKeyFile); err != nil {
		return nil, nil, err
	}
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil || subtle.ConstantTimeCompare(derived, pub[:]) != 1 {
		return nil, nil, errors.New("read_pub_key_file does not belong to read_key_file")
	}
	return priv, pub, nil
}
