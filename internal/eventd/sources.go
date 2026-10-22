package eventd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* maxCiphertext is the database cap on a sealed credential; a longer one is never read. */
const maxCiphertext = 8240

/* A profile with one of these statuses was refused by the poller (see internal/poller/profiles.go). */
func refusedStatus(s string) bool {
	return s == "invalid" || s == "weak" || s == "mismatch"
}

/* quiet is the logger of every gosnmp object: it never prints (packets are untrusted, never logged). */
var quiet = gosnmp.NewLogger(log.New(io.Discard, "", 0))

/* USM protocols that creds accepts; the same table as internal/snmp. */
var (
	authProtos = map[string]gosnmp.SnmpV3AuthProtocol{
		"SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
	}
	privProtos = map[string]gosnmp.SnmpV3PrivProtocol{"AES": gosnmp.AES, "AES256": gosnmp.AES256}
)

/*
device is a known event source. Its secrets are valid until wipe; users hold
mu for reading while they use them. A device is replaced (not edited) when its
row or ciphertexts change.
*/
type device struct {
	id     int64
	addr   netip.Addr
	driver string
	drv    drivers.Driver /* nil when the driver name is unknown or "auto" */
	fp     string

	mu        sync.RWMutex
	wiped     bool
	community secret.Secret /* zero when there is no usable snmp2c profile */
	v3        *v3Auth       /* nil when there is no usable snmp3 profile */
}

/* matchCommunity compares in constant time, without making a string of the stored community. */
func (d *device) matchCommunity(got string) bool { return d.community.EqualString(got) }

/* wipe zeroes the secrets once nobody uses them any more. */
func (d *device) wipe() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wiped = true
	d.community.Wipe()
	d.community = secret.Secret{}
	if d.v3 != nil {
		d.v3.wipe()
		d.v3 = nil
	}
}

/* snapshot is the immutable address table. Addresses shared by several devices are not in byAddr. */
type snapshot struct {
	byAddr map[netip.Addr]*device
	all    []*device
}

/*
sources maps the peer address of a packet to the device it belongs to and
holds that device's verified read credentials. Only the address identifies a
source: names or addresses inside a message are never used.

Credential rule: eventd cannot read inventory.profile_seen (it has no rights
there) and never writes it, so it cannot enforce the poller's created_at mark.
Open is called with no lower bound, and the monotonic mark is kept in memory
instead (seen): a ciphertext older than the newest one this process accepted
for the device and kind is refused and counted (the api can UPDATE
access_profile and restore an old row, whatever its status says). Not
prevented: a rollback made while eventd is down or restarted (nothing
persists the mark). A profile whose status is invalid, weak or mismatch is
ignored at the next reread (at most 5 minutes).
*/
type sources struct {
	priv, pub *[32]byte
	reg       *drivers.Registry
	now       func() time.Time
	log       *slog.Logger

	cur atomic.Pointer[snapshot]
	mu  sync.Mutex /* one reload at a time; guards seen */

	/*
		seen is the newest created_at accepted per device and kind by this
		process: an older ciphertext (a rollback) is refused. Nothing remembers
		it across a restart (eventd has no rights on inventory.profile_seen),
		so a rollback made while eventd is down is not prevented.
	*/
	seen      map[seenKey]time.Time
	rollbacks atomic.Uint64
}

type seenKey struct {
	dev  int64
	kind string
}

func newSources(priv, pub *[32]byte, reg *drivers.Registry, now func() time.Time, log *slog.Logger) *sources {
	/* gosnmp keeps derived keys, keyed by the plaintext passphrase, in a process-wide map without eviction: never. */
	gosnmp.PasswordCaching(false)
	s := &sources{priv: priv, pub: pub, reg: reg, now: now, log: log, seen: map[seenKey]time.Time{}}
	s.cur.Store(&snapshot{byAddr: map[netip.Addr]*device{}})
	return s
}

/*
acquire returns the device that owns ip, read-locked: the caller calls
release when done with its secrets. ok is false for an unknown address.
*/
func (s *sources) acquire(ip netip.Addr) (d *device, release func(), ok bool) {
	for range 3 {
		d = s.cur.Load().byAddr[ip]
		if d == nil {
			return nil, nil, false
		}
		d.mu.RLock()
		if !d.wiped {
			return d, d.mu.RUnlock, true
		}
		d.mu.RUnlock() /* replaced just now: look again */
	}
	return nil, nil, false
}

type devRow struct {
	id      int64
	addr    netip.Addr
	driver  string
	profile map[string]profileRow
	engine  []byte /* SNMPv3 engine ID the poller learned; nil when none */
}

type profileRow struct {
	ct     []byte
	status string
}

/*
reload rereads core.device and the SNMP profiles in one statement. Unchanged
devices keep their object (and their verified credentials); the others are
replaced, and the replaced and removed ones are wiped. On a database error the
old table stays in force.
*/
func (s *sources) reload(ctx context.Context, pool *pgxpool.Pool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := pool.Query(ctx, `
		SELECT d.id, d.address, d.driver, p.kind, p.ciphertext, p.status, e.engine_id
		FROM core.device d
		LEFT JOIN core.device_v3_engine e ON e.device_id = d.id
		LEFT JOIN core.event_auth_profile_v p ON p.device_id = d.id AND octet_length(p.ciphertext) <= $1
		ORDER BY d.id`, maxCiphertext)
	if err != nil {
		return fmt.Errorf("eventd: load devices: %w", err)
	}
	byID := map[int64]*devRow{}
	var order []*devRow
	var (
		id           int64
		addr         netip.Addr
		driver       string
		kind, status *string
		ciphertext   []byte
		engine       []byte
	)
	if _, err := pgx.ForEachRow(rows, []any{&id, &addr, &driver, &kind, &ciphertext, &status, &engine}, func() error {
		r := byID[id]
		if r == nil {
			r = &devRow{id: id, addr: addr.Unmap().WithZone(""), driver: driver, profile: map[string]profileRow{}, engine: append([]byte(nil), engine...)}
			byID[id] = r
			order = append(order, r)
		}
		if kind != nil && status != nil {
			r.profile[*kind] = profileRow{ct: append([]byte(nil), ciphertext...), status: *status}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("eventd: load devices: %w", err)
	}

	old := s.cur.Load()
	prev := make(map[int64]*device, len(old.all))
	for _, d := range old.all {
		prev[d.id] = d
	}
	next := &snapshot{byAddr: make(map[netip.Addr]*device, len(order)), all: make([]*device, 0, len(order))}
	count := map[netip.Addr]int{}
	for _, r := range order {
		count[r.addr]++
	}
	reused := map[*device]bool{}
	for _, r := range order {
		fp := fingerprint(r)
		d := prev[r.id]
		if d != nil && d.fp == fp {
			reused[d] = true
		} else {
			d = s.build(r, fp)
		}
		next.all = append(next.all, d)
		if count[r.addr] > 1 {
			continue /* ambiguous: more than one device behind this address, nobody gets its events */
		}
		next.byAddr[r.addr] = d
	}
	for a, n := range count {
		if n > 1 {
			s.log.Warn("several devices share an address, events from it are refused", slog.String("addr", a.String()), slog.Int("devices", n))
		}
	}
	s.cur.Store(next)
	for k := range s.seen {
		if _, ok := byID[k.dev]; !ok {
			delete(s.seen, k)
		}
	}
	for _, d := range old.all {
		if !reused[d] {
			d.wipe()
		}
	}
	return nil
}

func fingerprint(r *devRow) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d|%s|%s|%x", r.id, r.addr, r.driver, r.engine)
	for _, k := range []string{creds.KindSNMP2c, creds.KindSNMP3} {
		if p, ok := r.profile[k]; ok {
			sum := sha256.Sum256(p.ct)
			_, _ = fmt.Fprintf(h, "|%s:%x:%s", k, sum, p.status)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

/* build verifies the SNMP profiles of one device; a refused profile is logged once and leaves its protocol unusable. */
func (s *sources) build(r *devRow, fp string) *device {
	d := &device{id: r.id, addr: r.addr, driver: r.driver, fp: fp}
	if s.reg != nil {
		d.drv = s.reg.ByName(r.driver)
	}
	owner := devices.Owner{Kind: devices.OwnerDevice, ID: r.id}
	for _, k := range []string{creds.KindSNMP2c, creds.KindSNMP3} {
		p, ok := r.profile[k]
		if !ok {
			continue
		}
		if refusedStatus(p.status) {
			s.log.Warn("credential ignored", slog.Int64("device_id", r.id), slog.String("kind", k), slog.String("status", p.status))
			continue
		}
		c, err := creds.Open(s.priv, s.pub, p.ct, owner, k, time.Time{}, s.now())
		if err != nil {
			s.log.Warn("credential rejected", slog.Int64("device_id", r.id), slog.String("kind", k), slog.String("err", err.Error()))
			continue
		}
		key := seenKey{r.id, k}
		if c.CreatedAt.Before(s.seen[key]) {
			c.Wipe()
			s.rollbacks.Add(1)
			s.log.Warn("credential refused: older than the one accepted before", slog.Int64("device_id", r.id), slog.String("kind", k))
			continue
		}
		s.seen[key] = c.CreatedAt
		switch k {
		case creds.KindSNMP2c:
			d.community = c.Community
		case creds.KindSNMP3:
			if d.v3, err = newV3(c); err != nil {
				s.log.Warn("credential rejected", slog.Int64("device_id", r.id), slog.String("kind", k), slog.String("err", err.Error()))
			} else {
				d.v3.seedEngine(r.engine)
			}
			c.Wipe()
		}
	}
	return d
}
