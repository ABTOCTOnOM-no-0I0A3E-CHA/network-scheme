package eventd

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
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
v3Auth checks SNMPv3 packets of one device. Its table holds exactly the USM
user of this device's snmp3 profile: a packet from this source address is
accepted only for that user, whatever other users exist for other devices.
*/
type v3Auth struct {
	mu   sync.Mutex
	user string
	sp   *gosnmp.UsmSecurityParameters
	g    *gosnmp.GoSNMP
}

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

/* matchCommunity compares in constant time (over digests, so the length does not leak either). */
func (d *device) matchCommunity(got string) bool {
	if d.community.IsZero() {
		return false
	}
	a, b := sha256.Sum256([]byte(got)), sha256.Sum256([]byte(d.community.Reveal()))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

/* wipe zeroes the secrets once nobody uses them any more. */
func (d *device) wipe() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.wiped = true
	d.community.Wipe()
	d.community = secret.Secret{}
	if v := d.v3; v != nil {
		v.mu.Lock()
		v.sp.AuthenticationPassphrase, v.sp.PrivacyPassphrase, v.sp.UserName = "", "", ""
		v.g.TrapSecurityParametersTable = nil
		v.mu.Unlock()
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
there) and never writes it, so it cannot tell a rolled-back ciphertext from the
current one by the created_at mark. Open is therefore called with no lower
bound. This is safe because the api stores one ciphertext per profile and
cannot create a credential for the read domain (it has no private key, and
every ciphertext is bound to its owner and kind): the worst a compromised api
can do is store an older, once legitimate, ciphertext again, which the poller
marks 'mismatch' on its next poll; eventd drops a profile whose status is
invalid, weak or mismatch at the next reread (at most 5 minutes).
*/
type sources struct {
	priv, pub *[32]byte
	reg       *drivers.Registry
	now       func() time.Time
	log       *slog.Logger

	cur atomic.Pointer[snapshot]
	mu  sync.Mutex /* one reload at a time */
}

func newSources(priv, pub *[32]byte, reg *drivers.Registry, now func() time.Time, log *slog.Logger) *sources {
	s := &sources{priv: priv, pub: pub, reg: reg, now: now, log: log}
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
		SELECT d.id, d.address, d.driver, p.kind, p.ciphertext, p.status
		FROM core.device d
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
	)
	if _, err := pgx.ForEachRow(rows, []any{&id, &addr, &driver, &kind, &ciphertext, &status}, func() error {
		r := byID[id]
		if r == nil {
			r = &devRow{id: id, addr: addr.Unmap().WithZone(""), driver: driver, profile: map[string]profileRow{}}
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
	for _, d := range old.all {
		if !reused[d] {
			d.wipe()
		}
	}
	return nil
}

func fingerprint(r *devRow) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d|%s|%s", r.id, r.addr, r.driver)
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
		switch k {
		case creds.KindSNMP2c:
			d.community = c.Community
		case creds.KindSNMP3:
			if d.v3, err = newV3(c); err != nil {
				s.log.Warn("credential rejected", slog.Int64("device_id", r.id), slog.String("kind", k), slog.String("err", err.Error()))
			}
			c.Wipe()
		}
	}
	return d
}

func newV3(c creds.Credential) (*v3Auth, error) {
	ap, ok := authProtos[c.AuthProto]
	pp, ok2 := privProtos[c.PrivProto]
	if !ok || !ok2 {
		return nil, fmt.Errorf("unsupported USM protocol")
	}
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 c.User,
		AuthenticationProtocol:   ap,
		AuthenticationPassphrase: c.AuthKey.Reveal(),
		PrivacyProtocol:          pp,
		PrivacyPassphrase:        c.PrivKey.Reveal(),
	}
	tbl := gosnmp.NewSnmpV3SecurityParametersTable(quiet)
	if err := tbl.Add(c.User, sp); err != nil {
		return nil, fmt.Errorf("usm user: %w", err)
	}
	g := &gosnmp.GoSNMP{
		Version:                     gosnmp.Version3,
		SecurityModel:               gosnmp.UserSecurityModel,
		MsgFlags:                    gosnmp.AuthPriv,
		TrapSecurityParametersTable: tbl,
		Logger:                      quiet,
	}
	return &v3Auth{user: c.User, sp: sp, g: g}, nil
}
