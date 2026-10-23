package snmp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/beekamai/network-scheme/internal/creds"
)

const (
	defaultTimeout = 2 * time.Second
	defaultRetries = 1
	defaultMaxOIDs = 32
	maxOIDsCeiling = 255
	maxRepetitions = 25
	minV3KeyLength = 16
)

/*
Options tunes a session. Zero values select the defaults: Timeout 2s,
Retries 1 (a negative value means no retries), MaxOIDsPerRequest 32.
ContextName selects the SNMPv3 context; leave empty for real devices.
*/
type Options struct {
	Timeout           time.Duration
	Retries           int
	MaxOIDsPerRequest int
	ContextName       string
}

type session struct {
	mu     sync.Mutex
	g      *gosnmp.GoSNMP
	maxOID int
	closed bool
}

var (
	authProtos = map[string]gosnmp.SnmpV3AuthProtocol{
		"SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
	}
	privProtos = map[string]gosnmp.SnmpV3PrivProtocol{
		"AES": gosnmp.AES, "AES256": gosnmp.AES256,
	}
)

/*
Dial opens a read-only session to addr. Supported credentials: snmp2c and
snmp3 (authPriv only, SHA-2 + AES). UDP is connectionless, so a wrong address
or credential shows up on the first request, not here.
*/
func Dial(ctx context.Context, addr netip.AddrPort, c creds.Credential, o Options) (Reader, io.Closer, error) {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	switch {
	case o.Retries == 0:
		o.Retries = defaultRetries
	case o.Retries < 0:
		o.Retries = 0
	}
	if o.MaxOIDsPerRequest <= 0 {
		o.MaxOIDsPerRequest = defaultMaxOIDs
	}
	o.MaxOIDsPerRequest = min(o.MaxOIDsPerRequest, maxOIDsCeiling)
	ip := addr.Addr().Unmap()
	g := &gosnmp.GoSNMP{
		Target:         ip.String(),
		Port:           addr.Port(),
		Transport:      "udp4",
		Timeout:        o.Timeout,
		Retries:        o.Retries,
		MaxOids:        o.MaxOIDsPerRequest,
		MaxRepetitions: maxRepetitions,
		Context:        ctx,
	}
	if ip.Is6() {
		g.Transport = "udp6"
	}
	switch c.Kind {
	case "snmp2c":
		if c.Community.IsZero() {
			return nil, nil, errors.New("snmp: empty community")
		}
		g.Version = gosnmp.Version2c
		g.Community = c.Community.Reveal()
	case "snmp3":
		ap, ok := authProtos[c.AuthProto]
		if !ok {
			return nil, nil, fmt.Errorf("snmp: unsupported auth protocol %q", c.AuthProto)
		}
		pp, ok := privProtos[c.PrivProto]
		if !ok {
			return nil, nil, fmt.Errorf("snmp: unsupported privacy protocol %q", c.PrivProto)
		}
		if c.User == "" || len(c.AuthKey.Reveal()) < minV3KeyLength || len(c.PrivKey.Reveal()) < minV3KeyLength {
			return nil, nil, errors.New("snmp: snmp3 needs a user and keys of at least 16 characters")
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.ContextName = o.ContextName
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 c.User,
			AuthenticationProtocol:   ap,
			AuthenticationPassphrase: c.AuthKey.Reveal(),
			PrivacyProtocol:          pp,
			PrivacyPassphrase:        c.PrivKey.Reveal(),
		}
	default:
		return nil, nil, fmt.Errorf("snmp: credential kind %q is not an SNMP kind", c.Kind)
	}
	if err := g.Connect(); err != nil {
		return nil, nil, mapErr(ctx, err)
	}
	s := &session{g: g, maxOID: o.MaxOIDsPerRequest}
	return s, s, nil
}

func (s *session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.g.Conn != nil {
		return s.g.Conn.Close()
	}
	return nil
}

/* begin locks the session and binds ctx to it; the returned func unlocks. */
func (s *session) begin(ctx context.Context) (func(), error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("snmp: session closed")
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.g.Context = ctx
	return s.mu.Unlock, nil
}

func (s *session) Get(ctx context.Context, oids ...string) ([]Var, error) {
	return s.fetch(ctx, oids, func(chunk []string) (*gosnmp.SnmpPacket, error) { return s.g.Get(chunk) })
}

func (s *session) BulkGet(ctx context.Context, oids []string) ([]Var, error) {
	return s.fetch(ctx, oids, func(chunk []string) (*gosnmp.SnmpPacket, error) {
		return s.g.GetBulk(chunk, uint8(len(chunk)), 0) //nolint:gosec // chunk <= maxOIDsCeiling
	})
}

func (s *session) fetch(ctx context.Context, oids []string, do func([]string) (*gosnmp.SnmpPacket, error)) ([]Var, error) {
	if len(oids) == 0 {
		return nil, nil
	}
	unlock, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	out := make([]Var, 0, len(oids))
	missing := 0
	for start := 0; start < len(oids); start += s.maxOID {
		chunk := make([]string, 0, s.maxOID)
		for _, o := range oids[start:min(start+s.maxOID, len(oids))] {
			chunk = append(chunk, "."+trimDot(o))
		}
		pkt, err := do(chunk)
		if err != nil {
			return nil, mapErr(ctx, err)
		}
		if err := packetErr(pkt); err != nil {
			return nil, err
		}
		for _, p := range pkt.Variables {
			v := convert(p)
			if v.Type == TypeNoSuchObject || v.Type == TypeNoSuchInstance || v.Type == TypeEndOfMibView {
				missing++
			}
			out = append(out, v)
		}
	}
	if missing == len(out) {
		return out, ErrNoSuchObject
	}
	return out, nil
}

func (s *session) Walk(ctx context.Context, root string, fn func(Var) error) error {
	unlock, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	err = s.g.BulkWalk("."+trimDot(root), func(p gosnmp.SnmpPDU) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(convert(p))
	})
	if err != nil {
		return mapErr(ctx, err)
	}
	return ctx.Err()
}

func packetErr(p *gosnmp.SnmpPacket) error {
	switch p.Error {
	case gosnmp.NoError:
		return nil
	case gosnmp.NoSuchName:
		return ErrNoSuchObject
	case gosnmp.AuthorizationError, gosnmp.NoAccess:
		return fmt.Errorf("%w: %s", ErrAuth, p.Error)
	}
	return fmt.Errorf("snmp: agent error: %s", p.Error)
}

/* mapErr maps gosnmp/transport errors onto the package errors; context errors win. */
func mapErr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	for _, a := range []error{
		gosnmp.ErrWrongDigest, gosnmp.ErrUnknownUsername, gosnmp.ErrDecryption,
		gosnmp.ErrNotInTimeWindow, gosnmp.ErrUnknownSecurityLevel,
	} {
		if errors.Is(err, a) {
			return fmt.Errorf("%w: %v", ErrAuth, err)
		}
	}
	if strings.Contains(err.Error(), "not authentic") {
		return fmt.Errorf("%w: %v", ErrAuth, err)
	}
	var ne net.Error
	if (errors.As(err, &ne) && ne.Timeout()) || strings.Contains(err.Error(), "timeout") {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	return fmt.Errorf("snmp: %w", err)
}

func convert(p gosnmp.SnmpPDU) Var {
	v := Var{OID: trimDot(p.Name)}
	switch p.Type {
	case gosnmp.Integer:
		v.Type = TypeInteger
		switch x := p.Value.(type) {
		case int:
			v.Value = int64(x)
		case int64:
			v.Value = x
		}
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
		v.Type = map[gosnmp.Asn1BER]Type{
			gosnmp.Counter32: TypeCounter32, gosnmp.Gauge32: TypeGauge32,
			gosnmp.TimeTicks: TypeTimeTicks, gosnmp.Uinteger32: TypeGauge32,
		}[p.Type]
		switch x := p.Value.(type) {
		case uint32:
			v.Value = uint64(x)
		case uint:
			v.Value = uint64(x)
		case uint64:
			v.Value = x
		}
	case gosnmp.Counter64:
		v.Type = TypeCounter64
		if x, ok := p.Value.(uint64); ok {
			v.Value = x
		}
	case gosnmp.OctetString, gosnmp.Opaque:
		v.Type = TypeOctetString
		if p.Type == gosnmp.Opaque {
			v.Type = TypeOpaque
		}
		if b, ok := p.Value.([]byte); ok {
			v.Value = append([]byte(nil), b...)
		}
	case gosnmp.ObjectIdentifier:
		v.Type = TypeOID
		if s, ok := p.Value.(string); ok {
			v.Value = trimDot(s)
		}
	case gosnmp.IPAddress:
		v.Type = TypeIPAddress
		if s, ok := p.Value.(string); ok {
			v.Value = s
		}
	case gosnmp.Null:
		v.Type = TypeNull
	case gosnmp.NoSuchObject:
		v.Type = TypeNoSuchObject
	case gosnmp.NoSuchInstance:
		v.Type = TypeNoSuchInstance
	case gosnmp.EndOfMibView:
		v.Type = TypeEndOfMibView
	}
	return v
}

/*
EngineIDer is implemented by SNMPv3 readers: EngineID is the authoritative
engine ID the agent revealed during discovery, or nil for SNMPv2c or before
the first answered request.
*/
type EngineIDer interface {
	EngineID() []byte
}

/* EngineID returns a copy of the learned authoritative engine ID of a v3 session. */
func (s *session) EngineID() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.g.Version != gosnmp.Version3 {
		return nil
	}
	if usm, ok := s.g.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok && usm.AuthoritativeEngineID != "" {
		return []byte(usm.AuthoritativeEngineID)
	}
	return nil
}
