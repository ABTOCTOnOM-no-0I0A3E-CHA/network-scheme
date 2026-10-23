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
}

// New returns a builder over c.
func New(c Config) *Builder {
	b := &Builder{pool: c.Pool, clock: c.Clock, log: c.Log, reload: make(chan struct{}, 1)}
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
	in, err := load(ctx, b.pool)
	if err != nil {
		return Result{}, err
	}
	want := derive(in)
	var res Result
	err = pgx.BeginFunc(ctx, b.pool, func(tx pgx.Tx) error {
		var err error
		res, err = apply(ctx, tx, in, want, b.clock.Now())
		return err
	})
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
	lldpPort map[ifKey]bool    /* ports with any LLDP row (raw local index) */
	stations map[ifKey][]int64 /* port -> owners (known devices) of the MACs learned there */
	live     map[int64]bool    /* device is up or partial under a fresh poller heartbeat */
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

func load(ctx context.Context, pool *pgxpool.Pool) (*inputs, error) {
	in := &inputs{devName: map[int64]string{}, byAddr: map[netip.Addr]int64{}, byName: map[string]int64{},
		ifaces: map[ifKey]bool{}, portIf: map[textKey]int32{}, lldpPort: map[ifKey]bool{}, stations: map[ifKey][]int64{}, live: map[int64]bool{}}
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

	rows, err = pool.Query(ctx, `SELECT device_id, if_index, name, alias FROM inventory.interface`)
	if err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}
	ambiguous := map[textKey]bool{}
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
		if err := rows.Scan(&dev, &ifx, &name, &alias); err != nil {
			rows.Close()
			return nil, err
		}
		in.ifaces[ifKey{dev, ifx}] = true
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

	rows, err = pool.Query(ctx, `SELECT device_id, local_if_index, chassis_id, port_id, sys_name, host(mgmt_addr) FROM inventory.lldp_neighbor ORDER BY device_id, local_if_index, chassis_id, port_id`)
	if err != nil {
		return nil, fmt.Errorf("lldp: %w", err)
	}
	for rows.Next() {
		var r lldpRow
		var mgmt *string
		if err := rows.Scan(&r.dev, &r.rawIf, &r.chassis, &r.portID, &r.sysName, &mgmt); err != nil {
			rows.Close()
			return nil, err
		}
		in.lldpPort[ifKey{r.dev, r.rawIf}] = true
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
		Device MACs come from ARP entries whose IP is a device address. A device
		counts only if its address maps to exactly one MAC, and a MAC only if it
		maps to exactly one device: a conflict (spoofed ARP, shared address) is
		not evidence.
	*/
	rows, err = pool.Query(ctx, `
WITH own AS (
    SELECT a.mac, d.id AS dev FROM inventory.arp_entry a
    JOIN core.device d ON d.address = set_masklen(a.ip, masklen(d.address))
    GROUP BY a.mac, d.id),
good AS (
    SELECT mac, dev FROM own
    WHERE dev IN (SELECT dev FROM own GROUP BY dev HAVING count(*) = 1)
      AND mac IN (SELECT mac FROM own GROUP BY mac HAVING count(*) = 1))
SELECT DISTINCT m.device_id, m.if_index, g.dev FROM inventory.mac_entry m JOIN good g ON g.mac = m.mac WHERE g.dev <> m.device_id`)
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
