package eventd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/internal/events/syslog"
)

const (
	tlsHandshakeTimeout = 10 * time.Second
	handshakeLogEvery   = time.Minute
	maxConnsPerSource   = 16
	frameBuf            = 16 << 10
)

var errFrame = errors.New("eventd: bad syslog frame")

/*
handleSyslog processes one syslog message (a datagram or a TCP frame) from the
peer address ip. It reports false when ip is not a known source.
*/
func (s *server) handleSyslog(ip netip.Addr, raw []byte) bool {
	d, release, ok := s.src.acquire(ip)
	if !ok {
		s.st.unknownSource.Add(1)
		return false
	}
	defer release()
	m, err := syslog.Parse(raw, s.now())
	if err != nil {
		s.st.malformed.Add(1)
		return true
	}
	s.admit(d, kindSyslog, event{
		kind: kindSyslog, ts: m.TS, dev: d.id, facility: int16(m.Facility), severity: int16(m.Severity),
		host: m.Host, app: m.App, msg: m.Text, rawLen: int32(len(raw)), // #nosec G115 -- at most 8 KiB
	})
	return true
}

/*
readFrame reads one RFC 6587 frame: octet counting ("LEN SP MSG") or a
LF-terminated line, told apart by the first byte (a digit or '<'). Frames over
the syslog limit, and anything else, are errors: the stream cannot be resynced
and the connection is closed.
*/
func readFrame(br *bufio.Reader, buf []byte) ([]byte, error) {
	var c byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != '\n' && b != '\r' { /* blank lines between LF-framed messages */
			c = b
			break
		}
	}
	if err := br.UnreadByte(); err != nil {
		return nil, err
	}
	switch {
	case c >= '1' && c <= '9':
		var n int
		for i := 0; ; i++ {
			b, err := br.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == ' ' {
				break
			}
			if i >= 5 || b < '0' || b > '9' {
				return nil, errFrame
			}
			n = n*10 + int(b-'0')
		}
		if n < 1 || n > syslog.MaxMessage {
			return nil, errFrame
		}
		if _, err := io.ReadFull(br, buf[:n]); err != nil {
			return nil, err
		}
		return buf[:n], nil
	case c == '<':
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errFrame
		}
		if err != nil && (!errors.Is(err, io.EOF) || len(line) == 0) {
			return nil, err
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) > syslog.MaxMessage {
			return nil, errFrame
		}
		return line, nil
	}
	return nil, errFrame
}

/* conns counts open stream connections: in total and per peer address. */
type conns struct {
	mu    sync.Mutex
	total int
	max   int
	per   map[netip.Addr]int
}

func (c *conns) enter(ip netip.Addr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.total >= c.max || c.per[ip] >= maxConnsPerSource {
		return false
	}
	c.total++
	c.per[ip]++
	return true
}

func (c *conns) leave(ip netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total--
	if c.per[ip]--; c.per[ip] <= 0 {
		delete(c.per, ip)
	}
}

/*
serveStream accepts syslog connections on l (TCP, or TLS when cfg is set). An
unknown peer is refused before any byte is read, and before the TLS
handshake. The listener is closed by the caller to stop.
*/
func (s *server) serveStream(l net.Listener, cfg *tls.Config, wg *sync.WaitGroup, done <-chan struct{}) {
	for {
		c, err := l.Accept()
		if err != nil {
			select {
			case <-done:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.log.Warn("syslog accept failed", slog.String("err", err.Error()))
			select {
			case <-done:
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		ip := peerIP(c.RemoteAddr())
		if !s.known(ip) {
			s.st.received.Add(1)
			s.st.unknownSource.Add(1)
			_ = c.Close()
			continue
		}
		if !s.conns.enter(ip) {
			s.st.received.Add(1)
			s.st.dropped.Add(1)
			_ = c.Close()
			continue
		}
		wg.Go(func() {
			defer s.conns.leave(ip)
			defer c.Close() //nolint:errcheck // nothing to do about a failed close
			s.stream(c, ip, cfg, done)
		})
	}
}

/*
logHandshake logs a failed TLS handshake (peer address and error text only) at
most once per handshakeLogEvery; the failures in between are only counted.
*/
func (s *server) logHandshake(ip netip.Addr, err error) {
	now := time.Now().UnixNano()
	last := s.hsLast.Load()
	if now-last < int64(handshakeLogEvery) || !s.hsLast.CompareAndSwap(last, now) {
		s.hsSkip.Add(1)
		return
	}
	s.log.Warn("syslog tls handshake failed", slog.String("peer", ip.String()), slog.String("err", err.Error()), slog.Int64("suppressed", s.hsSkip.Swap(0)))
}

func (s *server) stream(c net.Conn, ip netip.Addr, cfg *tls.Config, done <-chan struct{}) {
	if cfg != nil {
		t := tls.Server(c, cfg)
		_ = t.SetDeadline(time.Now().Add(tlsHandshakeTimeout))
		if err := t.Handshake(); err != nil {
			s.logHandshake(ip, err)
			return
		}
		c = t
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() { /* shutdown unblocks the read */
		select {
		case <-done:
			_ = c.Close()
		case <-stop:
		}
	}()
	br := bufio.NewReaderSize(c, frameBuf)
	buf := make([]byte, syslog.MaxMessage)
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.cfg.TCPIdle))
		frame, err := readFrame(br, buf)
		if err != nil {
			if errors.Is(err, errFrame) {
				s.st.malformed.Add(1)
			}
			return
		}
		s.st.received.Add(1)
		/* The device may have been removed meanwhile: every message is looked up again. */
		known := true
		s.safely(func() { known = s.handleSyslog(ip, frame) })
		if !known {
			return
		}
	}
}

/* peerIP is the address of a peer as the device table has it: IPv4-mapped IPv6 unmapped, no zone. */
func peerIP(a net.Addr) netip.Addr {
	var ap netip.AddrPort
	switch v := a.(type) {
	case *net.TCPAddr:
		ap = v.AddrPort()
	case *net.UDPAddr:
		ap = v.AddrPort()
	default:
		p, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.Addr{}
		}
		ap = p
	}
	return ap.Addr().Unmap().WithZone("")
}
