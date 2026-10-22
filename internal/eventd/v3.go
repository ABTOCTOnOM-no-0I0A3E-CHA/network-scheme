package eventd

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/creds"
)

/*
SNMPv3 cost model. gosnmp derives the USM keys of a message from the
msgAuthoritativeEngineID the message itself carries, before it checks the
HMAC: one full 1 MiB password-to-key hash per key (about 6 ms each), for any
engine ID, from anybody who can spoof the address of a device and knows its
clear-text user name. eventd therefore never lets such a message reach gosnmp
unless it is cheap:

  - The message header is read here first (bounded BER). Anything but authPriv
    USM with the device's own user name and an engine ID of 5..32 bytes is
    refused without decoding.
  - Once a trap of the device has been fully authenticated, its engine ID is
    pinned together with the localized keys (SecretKey/PrivacyKey set), so
    gosnmp derives nothing for the pinned engine: the HMAC check is cheap.
  - A message with another engine ID (the first one, or a replaced device) takes
    the slow path with a tight budget per device and a global one; over budget
    it is dropped and counted. Nothing is cached by gosnmp (PasswordCaching is
    off): the keys live only in the pinned parameters and are wiped with the
    device.
*/

const (
	minEngineID = 5 /* RFC 3411 SnmpEngineID */
	maxEngineID = 32
	maxUserName = 32
)

/* v3Header is what is read from a message before gosnmp sees it. */
type v3Header struct {
	flags  byte
	model  int
	engine string
	user   string
}

/* tlv reads one BER element with a definite length of at most 3 length octets. */
func tlv(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, l, i := b[0], int(b[1]), 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || len(b) < 2+n {
			return 0, nil, nil, false
		}
		l = 0
		for _, c := range b[2 : 2+n] {
			l = l<<8 | int(c)
		}
		i = 2 + n
	}
	if len(b)-i < l {
		return 0, nil, nil, false
	}
	return tag, b[i : i+l], b[i+l:], true
}

func small(b []byte) int {
	if len(b) == 0 || len(b) > 2 {
		return -1
	}
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

/* parseV3Header reads msgFlags, the security model, the engine ID and the user name of a v3 message. */
func parseV3Header(b []byte) (h v3Header, ok bool) {
	tag, body, _, ok := tlv(b)
	if !ok || tag != 0x30 {
		return h, false
	}
	tag, ver, body, ok := tlv(body)
	if !ok || tag != 0x02 || small(ver) != 3 {
		return h, false
	}
	tag, glob, body, ok := tlv(body)
	if !ok || tag != 0x30 {
		return h, false
	}
	for i := 0; i < 4; i++ { /* msgID, msgMaxSize, msgFlags, msgSecurityModel */
		var v []byte
		var t byte
		if t, v, glob, ok = tlv(glob); !ok {
			return h, false
		}
		switch i {
		case 2:
			if t != 0x04 || len(v) != 1 {
				return h, false
			}
			h.flags = v[0]
		case 3:
			if t != 0x02 {
				return h, false
			}
			h.model = small(v)
		}
	}
	tag, sec, _, ok := tlv(body)
	if !ok || tag != 0x04 {
		return h, false
	}
	tag, usm, _, ok := tlv(sec)
	if !ok || tag != 0x30 {
		return h, false
	}
	tag, eng, usm, ok := tlv(usm)
	if !ok || tag != 0x04 || len(eng) < minEngineID || len(eng) > maxEngineID {
		return h, false
	}
	for i := 0; i < 2; i++ { /* boots, time */
		if tag, _, usm, ok = tlv(usm); !ok || tag != 0x02 {
			return h, false
		}
	}
	tag, user, _, ok := tlv(usm)
	if !ok || tag != 0x04 || len(user) > maxUserName {
		return h, false
	}
	h.engine, h.user = string(eng), string(user)
	return h, true
}

/* v3Pin is the engine of a device whose keys are known: decoding with it derives nothing. */
type v3Pin struct {
	engine string
	sp     *gosnmp.UsmSecurityParameters
	g      *gosnmp.GoSNMP
}

/*
v3Auth checks SNMPv3 messages of one device. Its tables hold exactly the USM
user of this device's snmp3 profile: a message from this source address is
accepted only for that user, whatever users exist for other devices.
*/
type v3Auth struct {
	user string
	seen replayCache /* per device, whatever the engine: a re-pin does not reset it */

	slowMu sync.Mutex /* serializes slow decodes */
	fullSP *gosnmp.UsmSecurityParameters
	full   *gosnmp.GoSNMP

	mu  sync.Mutex /* guards pin and the decodes with it */
	pin *v3Pin
}

func newV3(c creds.Credential) (*v3Auth, error) {
	ap, ok := authProtos[c.AuthProto]
	pp, ok2 := privProtos[c.PrivProto]
	if !ok || !ok2 {
		return nil, fmt.Errorf("unsupported USM protocol")
	}
	/*
		Placeholder keys keep the table from deriving keys when the user is
		added (that would cost two password hashes per device at every reload);
		they are replaced whenever a message names another engine, which is
		always, since a message needs an engine ID of 5 bytes or more.
	*/
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 c.User,
		AuthenticationProtocol:   ap,
		AuthenticationPassphrase: c.AuthKey.Reveal(),
		PrivacyProtocol:          pp,
		PrivacyPassphrase:        c.PrivKey.Reveal(),
		SecretKey:                []byte{0},
		PrivacyKey:               []byte{0},
	}
	g, err := usmDecoder(c.User, sp)
	if err != nil {
		return nil, err
	}
	return &v3Auth{user: c.User, fullSP: sp, full: g}, nil
}

/*
seedEngine pins the engine ID the poller learned from this device, localizing
the keys now (two password hashes, once per load of a changed device), so the
first genuine trap after a start takes the fast path whatever a flood of other
engine IDs costs the slow path. The ID is not trusted: a message that carries
it is verified against these keys like any other, and one that carries another
engine ID (a replaced device) takes the slow path and re-pins.
*/
func (v *v3Auth) seedEngine(engine []byte) {
	if len(engine) < minEngineID || len(engine) > maxEngineID {
		return
	}
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 v.user,
		AuthenticationProtocol:   v.fullSP.AuthenticationProtocol,
		AuthenticationPassphrase: v.fullSP.AuthenticationPassphrase,
		PrivacyProtocol:          v.fullSP.PrivacyProtocol,
		PrivacyPassphrase:        v.fullSP.PrivacyPassphrase,
		AuthoritativeEngineID:    string(engine),
	}
	err := sp.InitSecurityKeys()
	sp.AuthenticationPassphrase, sp.PrivacyPassphrase = "", ""
	if err == nil {
		v.setPin(sp)
	}
	clear(sp.SecretKey)
	clear(sp.PrivacyKey)
}

/* usmDecoder returns a decoder whose table holds only sp. */
func usmDecoder(user string, sp *gosnmp.UsmSecurityParameters) (*gosnmp.GoSNMP, error) {
	tbl := gosnmp.NewSnmpV3SecurityParametersTable(quiet)
	if err := tbl.Add(user, sp); err != nil {
		return nil, fmt.Errorf("usm user: %w", err)
	}
	return &gosnmp.GoSNMP{
		Version:                     gosnmp.Version3,
		SecurityModel:               gosnmp.UserSecurityModel,
		MsgFlags:                    gosnmp.AuthPriv,
		TrapSecurityParametersTable: tbl,
		Logger:                      quiet,
	}, nil
}

/*
decode authenticates and decrypts data. slow is called (once) when the message
names an engine that is not pinned; it reports whether the budget allows the
expensive decode. The second result is false for every failure; nothing of an
unauthenticated message is returned.
*/
func (v *v3Auth) decode(data []byte, now time.Time, slow func() bool, replayed func()) (*gosnmp.SnmpPacket, bool) {
	h, ok := parseV3Header(data)
	if !ok || h.user != v.user || h.model != int(gosnmp.UserSecurityModel) || h.flags&byte(gosnmp.AuthPriv) != byte(gosnmp.AuthPriv) {
		return nil, false
	}
	v.mu.Lock()
	pin := v.pin
	if pin != nil && pin.engine == h.engine {
		p, err := unmarshal(pin.g, data)
		v.mu.Unlock()
		p, ok := v.verified(p, err, false)
		return v.noReplay(p, ok, data, now, replayed)
	}
	v.mu.Unlock()
	if !slow() {
		return nil, false
	}
	v.slowMu.Lock()
	defer v.slowMu.Unlock()
	if v.full == nil { /* wiped meanwhile */
		return nil, false
	}
	p, err := unmarshal(v.full, data)
	p, ok = v.verified(p, err, true)
	return v.noReplay(p, ok, data, now, replayed)
}

/*
unmarshal calls gosnmp's UnmarshalTrap, which dereferences a nil security
parameter on some malformed messages (found by FuzzAuthTrapV3); a panic is an
error here, so locks are released and the worker goes on.
*/
func unmarshal(g *gosnmp.GoSNMP, data []byte) (p *gosnmp.SnmpPacket, err error) {
	defer func() {
		if r := recover(); r != nil {
			p, err = nil, fmt.Errorf("gosnmp panic: %T", r)
		}
	}()
	return g.UnmarshalTrap(data, false)
}

/*
verified applies the checks gosnmp leaves to the caller. gosnmp authenticates
and decrypts according to the flags in the message, so a message with
noAuthNoPriv or authNoPriv would pass: authPriv is required. After a slow
decode that passed, the engine is pinned.
*/
func (v *v3Auth) verified(p *gosnmp.SnmpPacket, err error, pinIt bool) (*gosnmp.SnmpPacket, bool) {
	if err != nil || p.SecurityModel != gosnmp.UserSecurityModel || p.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv {
		return nil, false
	}
	usm, ok := p.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm.UserName != v.user {
		return nil, false
	}
	if pinIt {
		v.setPin(usm)
	}
	return p, true
}

/* setPin keeps the engine and the localized keys the authenticated message was verified with. */
func (v *v3Auth) setPin(usm *gosnmp.UsmSecurityParameters) {
	if len(usm.SecretKey) == 0 || len(usm.PrivacyKey) == 0 {
		return
	}
	sp := &gosnmp.UsmSecurityParameters{
		UserName:               v.user,
		AuthenticationProtocol: v.fullSP.AuthenticationProtocol,
		PrivacyProtocol:        v.fullSP.PrivacyProtocol,
		AuthoritativeEngineID:  usm.AuthoritativeEngineID,
		SecretKey:              append([]byte(nil), usm.SecretKey...),
		PrivacyKey:             append([]byte(nil), usm.PrivacyKey...),
	}
	g, err := usmDecoder(v.user, sp)
	if err != nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.clearPin()
	v.pin = &v3Pin{engine: usm.AuthoritativeEngineID, sp: sp, g: g}
}

func (v *v3Auth) clearPin() {
	if v.pin != nil {
		clear(v.pin.sp.SecretKey)
		clear(v.pin.sp.PrivacyKey)
		v.pin.g.TrapSecurityParametersTable = nil
		v.pin = nil
	}
}

/* wipe zeroes every secret; the object is unusable afterwards. */
func (v *v3Auth) wipe() {
	v.slowMu.Lock()
	v.fullSP.AuthenticationPassphrase, v.fullSP.PrivacyPassphrase = "", ""
	clear(v.fullSP.SecretKey)
	clear(v.fullSP.PrivacyKey)
	v.full.TrapSecurityParametersTable = nil
	v.full = nil
	v.slowMu.Unlock()
	v.mu.Lock()
	v.clearPin()
	v.mu.Unlock()
	v.seen.clear()
}

/* noReplay refuses an authenticated message whose bytes were already accepted within replayTTL. */
func (v *v3Auth) noReplay(p *gosnmp.SnmpPacket, ok bool, data []byte, now time.Time, replayed func()) (*gosnmp.SnmpPacket, bool) {
	if !ok {
		return nil, false
	}
	if v.seen.replay(sha256.Sum256(data), now) {
		replayed()
		return nil, false
	}
	return p, true
}

const (
	replayTTL        = 10 * time.Minute
	replayPerDev     = 4096
	replaySweepMax   = 1 << 18 /* expired entries dropped per sweep over all devices */
	replayCompactMin = 256     /* below this peak a cache is never rebuilt */
)

var (
	replayTotal   int64         = 1 << 20 /* entries over all devices; over it a message is simply not remembered (a var for tests) */
	replayEntries atomic.Int64            /* entries over all devices */
	replayFull    atomic.Uint64           /* authenticated messages not remembered because replayTotal was reached */
)

type replayEntry struct {
	sum [32]byte
	at  time.Time
}

/*
replayCache remembers the SHA-256 of the raw bytes of the authenticated v3
messages of one device for replayTTL, at most replayPerDev of them (oldest
evicted). It only ever refuses a message it has seen; being full or over the
global cap never blocks intake, it merely forgets sooner. Expired entries go
when the device sends again and at the periodic sweep (sweepReplay), so idle
devices do not hold the global count.
*/
type replayCache struct {
	mu    sync.Mutex
	set   map[[32]byte]struct{}
	queue []replayEntry /* oldest first */
	peak  int           /* largest len(queue) since the last rebuild: maps never shrink */
}

/* replay reports whether sum was seen within replayTTL; otherwise it remembers it. */
func (c *replayCache) replay(sum [32]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(now, replayPerDev)
	if _, ok := c.set[sum]; ok {
		return true
	}
	if len(c.queue) >= replayPerDev {
		c.drop()
	}
	if replayEntries.Load() >= replayTotal {
		replayFull.Add(1)
		return false
	}
	if c.set == nil {
		c.set = map[[32]byte]struct{}{}
	}
	c.set[sum] = struct{}{}
	c.queue = append(c.queue, replayEntry{sum, now})
	c.peak = max(c.peak, len(c.queue))
	replayEntries.Add(1)
	return false
}

/* expire drops at most budget entries older than replayTTL, then gives memory back; c.mu is held. */
func (c *replayCache) expire(now time.Time, budget int) int {
	n := 0
	for n < budget && len(c.queue) > 0 && now.Sub(c.queue[0].at) >= replayTTL {
		c.drop()
		n++
	}
	c.shrink()
	return n
}

/*
shrink releases what an emptied or much smaller cache still holds: the map
keeps its buckets and the queue its backing array after a peak.
*/
func (c *replayCache) shrink() {
	switch {
	case len(c.queue) == 0:
		c.set, c.queue, c.peak = nil, nil, 0
	case c.peak > replayCompactMin && c.peak > 2*len(c.queue):
		q := make([]replayEntry, len(c.queue), 2*len(c.queue))
		copy(q, c.queue)
		set := make(map[[32]byte]struct{}, len(q))
		for _, e := range q {
			set[e.sum] = struct{}{}
		}
		c.set, c.queue, c.peak = set, q, len(q)
	}
}

func (c *replayCache) drop() {
	delete(c.set, c.queue[0].sum)
	c.queue = c.queue[1:]
	replayEntries.Add(-1)
}

func (c *replayCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	replayEntries.Add(-int64(len(c.queue)))
	c.set, c.queue, c.peak = nil, nil, 0
}

/*
sweepReplay expires old replay entries of the devices of the current table,
starting at index from, until budget entries were dropped; it returns
where the next sweep starts. It holds no lock over the table (an immutable
snapshot) and one device at a time, in the decode order: d.mu (read) then the
cache's own mutex. At most replayPerDev entries are dropped per lock hold.
*/
func (s *sources) sweepReplay(now time.Time, from, budget int) int {
	all := s.cur.Load().all
	if len(all) == 0 {
		return 0
	}
	from %= len(all)
	for i := range len(all) {
		at := (from + i) % len(all)
		d := all[at]
		d.mu.RLock()
		if !d.wiped && d.v3 != nil {
			c := &d.v3.seen
			c.mu.Lock()
			budget -= c.expire(now, min(budget, replayPerDev))
			c.mu.Unlock()
		}
		d.mu.RUnlock()
		if budget <= 0 {
			return at /* this device may have more: start there */
		}
	}
	return from
}
