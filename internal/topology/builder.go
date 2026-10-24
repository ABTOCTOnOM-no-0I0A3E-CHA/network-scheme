/*
Package topology builds core.link rows from the neighbour data the poller
collected (inventory.lldp_neighbor, inventory.mac_entry, inventory.arp_entry).
Everything a device reports is untrusted: a neighbour becomes a link only
through strict matching against data the reporting device does not control
alone (see lldp.go), and a link appears or disappears only by the rules of
apply.go. The builder reads inventory and writes core.link and core.link_change
only; it never touches a device.
*/
package topology

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

/* Clock supplies the time stamped on links; tests use a fake one. */
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

const (
	/* Interval is the periodic build cadence. */
	Interval = 60 * time.Second
	/* minGap is the shortest pause between two builds, however often Reload is called. */
	minGap       = 5 * time.Second
	buildTimeout = 90 * time.Second
	lockRetry    = 10 * time.Second
	/* MissLimit is the number of consecutive builds without confirmation after which an automatic link disappears. */
	MissLimit = 3
)

/* lockKey is the advisory lock of the topology builder; it differs from the trigger engine's key. */
const lockKey int64 = 0x6e6d73746f706f

/* fenceKey is taken (transaction-level, try) by every write transaction: a build that runs outside Run's lock never overlaps another. */
const fenceKey = lockKey + 1

/* hardRowCap bounds the LLDP rows used per reporting device; a device is also limited to its interface count. */
const hardRowCap = 4096

/* maxPortRows is the most neighbours one port can report (a few, for a hub or a media converter chain). */
const maxPortRows = 4

const warnEvery = 10 * time.Minute

// Config wires the builder to its dependencies.
type Config struct {
	Pool  *pgxpool.Pool
	Clock Clock /* nil: the wall clock */
	Log   *slog.Logger
}

/* Builder maintains the automatic links. Create it with New and run it with Run. */
type Builder struct {
	pool   *pgxpool.Pool
	clock  Clock
	log    *slog.Logger
	reload chan struct{}

	markers   map[int64]time.Time /* per missing link: newest inventory time already counted as a miss (see apply) */
	lastWarn  time.Time
	lastSpoof time.Time
}

// New returns a builder over c.
func New(c Config) *Builder {
	b := &Builder{pool: c.Pool, clock: c.Clock, log: c.Log, reload: make(chan struct{}, 1), markers: map[int64]time.Time{}}
	if b.clock == nil {
		b.clock = realClock{}
	}
	if b.log == nil {
		b.log = slog.Default()
	}
	return b
}

/*
Reload asks the running builder to build now (after a device or manual link
change) instead of at the next periodic build. It never blocks; repeated calls
collapse into one. A builder that is not running (another api process holds
the lock) ignores it.
*/
func (b *Builder) Reload() {
	select {
	case b.reload <- struct{}{}:
	default:
	}
}

/*
Run builds until ctx ends. Only one builder runs per database: it holds a
session-level advisory lock on a dedicated connection and, without it, waits
and retries.
*/
func (b *Builder) Run(ctx context.Context) error {
	for ctx.Err() == nil {
		conn, err := b.pool.Acquire(ctx)
		if err != nil {
			if ctx.Err() == nil {
				b.log.Warn("topology builder: no connection", "error", err.Error())
			}
			sleep(ctx, lockRetry)
			continue
		}
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
			conn.Release()
			if err != nil && ctx.Err() == nil {
				b.log.Warn("topology builder: lock attempt failed", "error", err.Error())
			}
			sleep(ctx, lockRetry)
			continue
		}
		b.log.Info("topology builder started")
		b.loop(ctx, conn)
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

/* loop builds on every tick and reload signal while the lock connection stays healthy. */
func (b *Builder) loop(ctx context.Context, lock *pgxpool.Conn) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	var last time.Time
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-b.reload:
				if wait := minGap - time.Since(last); wait > 0 {
					sleep(ctx, wait)
				}
			}
		}
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := lock.Conn().Ping(pctx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				b.log.Warn("topology builder: lock connection lost", "error", err.Error())
			}
			return
		}
		last = time.Now()
		bctx, cancel := context.WithTimeout(ctx, buildTimeout)
		res, err := b.Build(bctx)
		cancel()
		switch {
		case err != nil && ctx.Err() == nil:
			b.log.Warn("topology build failed", "error", err.Error())
		case err == nil && (res.Appeared > 0 || res.Disappeared > 0):
			b.log.Info("topology links changed", "appeared", res.Appeared, "disappeared", res.Disappeared, "links", res.Links)
		}
	}
}

/* Result summarises one build. */
type Result struct {
	Appeared, Disappeared int
	Links                 int /* automatic links after the build */
}

/*
Build runs one build: it reads the inventory, derives the links, and
reconciles core.link (and core.link_change) with them in one transaction. It
takes no lock itself; Run does.
*/
func (b *Builder) Build(ctx context.Context) (Result, error) {
	/* One snapshot for all reads: the inventory the links are derived from is consistent. */
	rtx, err := b.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Result{}, err
	}
	in, err := b.load(ctx, rtx)
	_ = rtx.Rollback(context.WithoutCancel(ctx))
	if err != nil {
		return Result{}, err
	}
	want, err := derive(ctx, in)
	if err != nil {
		return Result{}, err
	}
	if in.spoofs > 0 && b.clock.Now().Sub(b.lastSpoof) > warnEvery {
		b.lastSpoof = b.clock.Now()
		b.log.Warn("topology: several devices claim the same neighbour port, none is trusted", "claims", in.spoofs)
	}
	var res Result
	markers := maps.Clone(b.markers)
	err = pgx.BeginFunc(ctx, b.pool, func(tx pgx.Tx) error {
		var err error
		res, err = apply(ctx, tx, in, want, b.clock.Now(), markers)
		return err
	})
	if err == nil {
		b.markers = markers
	}
	return res, err
}

type ifKey struct {
	dev int64
	ifx int32
}

type textKey struct {
	dev  int64
	text string
}

type lldpRow struct {
	dev     int64
	rawIf   int32 /* as reported (may be an LLDP port number until resolved upstream) */
	ifx     int32 /* rawIf when it is an interface of the device, else 0 */
	named   bool  /* rawIf was confirmed by name through lldpLocPortTable */
	chassis string
	portID  string
	sysName string
	mgmt    netip.Addr /* invalid: none */
}

/* inputs is everything the build reads, indexed for the matching rules. */
type inputs struct {
	devName  map[int64]string
	byAddr   map[netip.Addr]int64 /* unique addresses only */
	byName   map[string]int64     /* unique names only */
	ifaces   map[ifKey]bool
	portIf   map[textKey]int32 /* interface name/alias/ifindex text -> ifindex; absent when ambiguous */
	lldp     []lldpRow
	lldpPort map[ifKey]bool      /* ports with any LLDP row (raw local index) */
	stations map[ifKey][]int64   /* port -> owners (known devices) of the MACs learned there */
	live     map[int64]bool      /* device is up or partial under a fresh poller heartbeat */
	spoofs   int                 /* one-sided claims on a target port that several rows name */
	invAt    map[int64]time.Time /* newest seen_at of the device's interface and LLDP rows: when it was last polled */
}

func normAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

/* normChassis canonicalises a MAC-looking chassis id and lower-cases anything else; the result is only ever compared. */
func normChassis(s string) string {
	s = strings.TrimSpace(s)
	if hw, err := net.ParseMAC(s); err == nil {
		return hw.String()
	}
	return strings.ToLower(s)
}

const maxText = 255 /* longer device-supplied strings are ignored */

/* querier is a transaction (or pool) the inventory is read through. */
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (b *Builder) load(ctx context.Context, pool querier) (*inputs, error) {
	in := &inputs{devName: map[int64]string{}, byAddr: map[netip.Addr]int64{}, byName: map[string]int64{},
		ifaces: map[ifKey]bool{}, portIf: map[textKey]int32{}, lldpPort: map[ifKey]bool{}, stations: map[ifKey][]int64{}, live: map[int64]bool{}, invAt: map[int64]time.Time{}}
	rows, err := pool.Query(ctx, `SELECT id, name, host(address) FROM core.device`)
	if err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}
	addrN, nameN := map[netip.Addr]int{}, map[string]int{}
	for rows.Next() {
		var id int64
		var name, addr string
		if err := rows.Scan(&id, &name, &addr); err != nil {
			rows.Close()
			return nil, err
		}
		in.devName[id] = name
		if a := normAddr(addr); a.IsValid() {
			addrN[a]++
			in.byAddr[a] = id
		}
		nameN[name]++
		in.byName[name] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for a, n := range addrN {
		if n > 1 {
			delete(in.byAddr, a) /* two devices on one address (different ports): not an identity */
		}
	}
	for s, n := range nameN {
		if n > 1 {
			delete(in.byName, s)
		}
	}

	rows, err = pool.Query(ctx, `SELECT device_id, if_index, name, alias, seen_at FROM inventory.interface`)
	if err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}
	ambiguous := map[textKey]bool{}
	ifCount := map[int64]int{}
	add := func(dev int64, text string, ifx int32) {
		if text == "" || len(text) > maxText {
			return
		}
		k := textKey{dev, text}
		if old, ok := in.portIf[k]; ok && old != ifx {
			ambiguous[k] = true
			return
		}
		in.portIf[k] = ifx
	}
	for rows.Next() {
		var dev int64
		var ifx int32
		var name, alias string
		var seen time.Time
		if err := rows.Scan(&dev, &ifx, &name, &alias, &seen); err != nil {
			rows.Close()
			return nil, err
		}
		in.ifaces[ifKey{dev, ifx}] = true
		ifCount[dev]++
		if seen.After(in.invAt[dev]) {
			in.invAt[dev] = seen
		}
		add(dev, name, ifx)
		add(dev, alias, ifx)
		add(dev, fmt.Sprint(ifx), ifx)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for k := range ambiguous {
		delete(in.portIf, k)
	}

	/* A port with more than maxPortRows neighbours is a hub or a flood: none of its rows is believed, and MAC inference skips it. */
	var capped int
	rows, err = pool.Query(ctx, `SELECT device_id, local_if_index FROM inventory.lldp_neighbor GROUP BY device_id, local_if_index HAVING count(*) > $1`, maxPortRows)
	if err != nil {
		return nil, fmt.Errorf("lldp ports: %w", err)
	}
	for rows.Next() {
		var k ifKey
		if err := rows.Scan(&k.dev, &k.ifx); err != nil {
			rows.Close()
			return nil, err
		}
		in.lldpPort[k] = true
		capped++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	/* Per reporter the quietest ports come first, so a flood on one port cannot push out genuine rows on others. */
	rows, err = pool.Query(ctx, `SELECT device_id, local_if_index, chassis_id, port_id, sys_name, host(mgmt_addr), seen_at, local_port_resolved FROM (
			SELECT *, row_number() OVER (PARTITION BY device_id ORDER BY pc, local_if_index, chassis_id, port_id) AS rn FROM (
				SELECT *, count(*) OVER (PARTITION BY device_id, local_if_index) AS pc FROM inventory.lldp_neighbor) c
			WHERE pc <= $2) t
		WHERE rn <= $1 ORDER BY device_id, pc, local_if_index, chassis_id, port_id`, hardRowCap, maxPortRows)
	if err != nil {
		return nil, fmt.Errorf("lldp: %w", err)
	}
	perDev := map[int64]int{}
	tabled := map[int64]bool{} /* reporters with a resolved row: they have an lldpLocPortTable */
	for rows.Next() {
		var r lldpRow
		var mgmt *string
		var seen time.Time
		if err := rows.Scan(&r.dev, &r.rawIf, &r.chassis, &r.portID, &r.sysName, &mgmt, &seen, &r.named); err != nil {
			rows.Close()
			return nil, err
		}
		if r.named {
			tabled[r.dev] = true
		}
		if seen.After(in.invAt[r.dev]) {
			in.invAt[r.dev] = seen
		}
		in.lldpPort[ifKey{r.dev, r.rawIf}] = true
		/* A reporter is believed on at most as many neighbours as it has interfaces (and hardRowCap). */
		if perDev[r.dev]++; perDev[r.dev] > ifCount[r.dev] {
			capped++
			continue
		}
		if len(r.chassis) > maxText || len(r.portID) > maxText || len(r.sysName) > maxText {
			continue
		}
		r.chassis = normChassis(r.chassis)
		if in.ifaces[ifKey{r.dev, r.rawIf}] {
			r.ifx = r.rawIf
		}
		if mgmt != nil {
			r.mgmt = normAddr(*mgmt)
		}
		in.lldp = append(in.lldp, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	/*
		A reporter with a port table resolves its ports by name: a row it could not
		resolve names no known interface, even if its LLDP port number happens to
		equal some ifIndex.
	*/
	for i := range in.lldp {
		if r := &in.lldp[i]; !r.named && tabled[r.dev] {
			r.ifx = 0
		}
	}
	for _, n := range perDev {
		if n >= hardRowCap {
			capped++
		}
	}
	if capped > 0 && b.clock.Now().Sub(b.lastWarn) > warnEvery {
		b.lastWarn = b.clock.Now()
		b.log.Warn("topology: LLDP rows were ignored (flooded port, beyond a device's interface count, or the hard cap)", "ignored", capped, "hard_cap", hardRowCap)
	}

	/*
		Device MACs come from ARP entries whose IP is a device address. A device
		counts only if its address maps to exactly one MAC, and a MAC only if it
		maps to exactly one device: a conflict (spoofed ARP, shared address) is
		not evidence. A device's MAC is believed for a station on A or B's ports
		only if some device other than A and B reports it: neither end can
		choose the MAC the other is recognised by.
	*/
	rows, err = pool.Query(ctx, `
WITH own AS (
    SELECT DISTINCT a.mac, d.id AS dev, a.device_id AS reporter FROM inventory.arp_entry a
    JOIN core.device d ON d.address = set_masklen(a.ip, masklen(d.address))),
pm AS (SELECT DISTINCT mac, dev FROM own),
good AS (
    SELECT mac, dev FROM pm
    WHERE dev IN (SELECT dev FROM pm GROUP BY dev HAVING count(*) = 1)
      AND mac IN (SELECT mac FROM pm GROUP BY mac HAVING count(*) = 1))
SELECT DISTINCT m.device_id, m.if_index, g.dev FROM inventory.mac_entry m JOIN good g ON g.mac = m.mac
WHERE g.dev <> m.device_id
  AND EXISTS (SELECT 1 FROM own o WHERE o.mac = g.mac AND o.dev = g.dev AND o.reporter <> m.device_id AND o.reporter <> g.dev)`)
	if err != nil {
		return nil, fmt.Errorf("stations: %w", err)
	}
	for rows.Next() {
		var dev, owner int64
		var ifx int32
		if err := rows.Scan(&dev, &ifx, &owner); err != nil {
			rows.Close()
			return nil, err
		}
		if k := (ifKey{dev, ifx}); in.ifaces[k] {
			in.stations[k] = append(in.stations[k], owner)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = pool.Query(ctx, `SELECT device_id FROM inventory.device_state_v WHERE state IN ('up', 'partial')`)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		in.live[id] = true
	}
	rows.Close()
	return in, rows.Err()
}
