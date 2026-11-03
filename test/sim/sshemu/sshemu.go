/*
Package sshemu is an in-process SSH server that imitates a network device CLI
for tests. It records every line the client sends and every authentication
attempt, so tests can prove what did (and did not) reach the device.
*/
package sshemu

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	gossh "golang.org/x/crypto/ssh"
)

// Config describes the emulated device.
type Config struct {
	HostKey       gossh.Signer                    /* required */
	Prompt        string                          /* initial prompt, e.g. "sw1#" */
	Responses     map[string]string               /* exact command line -> output ("\n" is sent as "\r\n") */
	Lookup        func(cmd string) (string, bool) /* consulted when Responses has no entry; nil: none */
	PromptAfter   map[string]string               /* command line -> prompt shown from then on */
	Username      string                          /* accepted user; empty accepts any */
	Password      string                          /* accepted password; empty disables password auth */
	AuthorizedKey gossh.PublicKey                 /* accepted client key; nil disables public key auth */

	/*
		Shell, when set, serves every shell session instead of the
		Responses/Lookup shell: it gets the authenticated user and the channel
		and returns when done (devemu.Device.Serve). Log.Commands stays empty;
		the shell keeps its own journal.
	*/
	Shell               func(user string, ch io.ReadWriteCloser)
	KeyExchanges        []string /* offered KEX algorithms; empty: the x/crypto defaults */
	Ciphers             []string /* empty: the x/crypto defaults */
	HostKeyAlgorithms   []string /* signature algorithms offered for HostKey (e.g. only "ssh-rsa"); empty: all it supports */
	KeyboardInteractive bool     /* also accept Password through keyboard-interactive (one "Password:" question) */
	NoClientAuth        bool     /* accept any client without authentication (in-band login inside the channel) */
	DisconnectAfter     int      /* drop the connection once this many input lines arrived: the last one reaches the shell, its output does not; 0: never */
}

/* NewRSAHostKey returns a fresh 2048-bit RSA host key (MES 6.x has only RSA/DSA host keys [R §4]). */
func NewRSAHostKey(t testing.TB) gossh.Signer {
	t.Helper()
	s, err := RSAHostKey()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

/* RSAHostKey returns a fresh 2048-bit RSA host key. */
func RSAHostKey() (gossh.Signer, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(k)
}

// Log records what clients sent to the emulator.
type Log struct {
	mu       sync.Mutex
	commands []string
	auths    []string
}

// Commands returns every command line received, in order (exec requests are prefixed "exec:").
func (l *Log) Commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.commands...)
}

/*
AuthAttempts returns every authentication attempt as "method" or, for
passwords, "password:<value>".
*/
func (l *Log) AuthAttempts() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.auths...)
}

func (l *Log) add(dst *[]string, s string) {
	l.mu.Lock()
	*dst = append(*dst, s)
	l.mu.Unlock()
}

// NewHostKey returns a fresh Ed25519 host key.
func NewHostKey(t testing.TB) gossh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := gossh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Start runs the emulator on 127.0.0.1 until the test ends.
func Start(t testing.TB, cfg Config) (netip.AddrPort, *Log) {
	t.Helper()
	log := &Log{}
	sc := serverConfig(cfg, log)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
		wg    sync.WaitGroup
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				serve(c, sc, cfg, log)
			}()
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String()), log
}

/*
Serve runs the emulator on ln until ln is closed (the standalone emulator of
the e2e stack, sshemud). log may be nil.
*/
func Serve(ln net.Listener, cfg Config, log *Log) error {
	if log == nil {
		log = &Log{}
	}
	sc := serverConfig(cfg, log)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go serve(c, sc, cfg, log)
	}
}

func serverConfig(cfg Config, log *Log) *gossh.ServerConfig {
	sc := &gossh.ServerConfig{
		NoClientAuth: cfg.NoClientAuth,
		AuthLogCallback: func(_ gossh.ConnMetadata, method string, _ error) {
			if method != "password" { /* passwords are logged with their value below */
				log.add(&log.auths, method)
			}
		},
	}
	if cfg.Password != "" {
		sc.PasswordCallback = func(m gossh.ConnMetadata, pw []byte) (*gossh.Permissions, error) {
			log.add(&log.auths, "password:"+string(pw))
			if (cfg.Username == "" || m.User() == cfg.Username) && string(pw) == cfg.Password {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
	if cfg.AuthorizedKey != nil {
		sc.PublicKeyCallback = func(m gossh.ConnMetadata, k gossh.PublicKey) (*gossh.Permissions, error) {
			if (cfg.Username == "" || m.User() == cfg.Username) && string(k.Marshal()) == string(cfg.AuthorizedKey.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
	if cfg.Password != "" && cfg.KeyboardInteractive {
		sc.KeyboardInteractiveCallback = func(m gossh.ConnMetadata, ask gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			ans, err := ask("", "", []string{"Password:"}, []bool{false})
			if err != nil || len(ans) != 1 {
				return nil, errors.New("denied")
			}
			log.add(&log.auths, "keyboard-interactive:"+ans[0])
			if (cfg.Username == "" || m.User() == cfg.Username) && ans[0] == cfg.Password {
				return nil, nil
			}
			return nil, errors.New("denied")
		}
	}
	sc.KeyExchanges, sc.Ciphers = cfg.KeyExchanges, cfg.Ciphers
	hk := cfg.HostKey
	if len(cfg.HostKeyAlgorithms) > 0 {
		as, ok := hk.(gossh.AlgorithmSigner)
		if !ok {
			panic("sshemu: HostKeyAlgorithms needs an AlgorithmSigner host key")
		}
		var err error
		if hk, err = gossh.NewSignerWithAlgorithms(as, cfg.HostKeyAlgorithms); err != nil {
			panic("sshemu: " + err.Error())
		}
	}
	sc.AddHostKey(hk)
	return sc
}

func serve(c net.Conn, sc *gossh.ServerConfig, cfg Config, log *Log) {
	defer func() { _ = c.Close() }()
	sconn, chans, reqs, err := gossh.NewServerConn(c, sc)
	if err != nil {
		return
	}
	go gossh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(gossh.UnknownChannelType, "unsupported")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go session(ch, creqs, cfg, log, sconn.User(), c)
	}
}

func session(ch gossh.Channel, reqs <-chan *gossh.Request, cfg Config, log *Log, user string, conn net.Conn) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			var rw io.ReadWriteCloser = ch
			if cfg.DisconnectAfter > 0 {
				rw = &lineLimit{ch: ch, conn: conn, left: cfg.DisconnectAfter}
			}
			if cfg.Shell != nil {
				go gossh.DiscardRequests(reqs)
				cfg.Shell(user, rw)
			} else {
				shell(rw, cfg, log)
			}
			return
		case "exec":
			var p struct{ Cmd string }
			_ = gossh.Unmarshal(req.Payload, &p)
			log.add(&log.commands, "exec:"+p.Cmd)
			_ = req.Reply(false, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

/*
lineLimit passes input until the left-th line terminator has been read; from
then on output is dropped and the connection is cut, as a link that fails
right after the device received a line.
*/
type lineLimit struct {
	ch     gossh.Channel
	conn   net.Conn
	left   int  /* lines still passed; read side only */
	lastCR bool /* the previous byte read was CR; read side only */
	mu     sync.Mutex
	cut    bool
}

func (l *lineLimit) Read(p []byte) (int, error) {
	l.mu.Lock()
	cut := l.cut
	l.mu.Unlock()
	if cut {
		_ = l.conn.Close()
		return 0, io.EOF
	}
	n, err := l.ch.Read(p)
	for i := 0; i < n; i++ {
		crlf := p[i] == 0x0a && l.lastCR /* LF right after CR ends the same line */
		l.lastCR = p[i] == 0x0d
		if (p[i] == 0x0d || p[i] == 0x0a) && !crlf {
			if l.left--; l.left == 0 {
				l.mu.Lock()
				l.cut = true
				l.mu.Unlock()
				return i + 1, err
			}
		}
	}
	return n, err
}

func (l *lineLimit) Write(p []byte) (int, error) {
	l.mu.Lock()
	cut := l.cut
	l.mu.Unlock()
	if cut {
		return len(p), nil
	}
	return l.ch.Write(p)
}

func (l *lineLimit) Close() error { return l.ch.Close() }

/* shell echoes nothing; it answers each line with its response and the prompt. */
func shell(ch io.ReadWriter, cfg Config, log *Log) {
	prompt := cfg.Prompt
	if _, err := io.WriteString(ch, "\r\nWelcome\r\n"+prompt); err != nil {
		return
	}
	var line []byte
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf)
		for _, b := range buf[:n] {
			if b != '\r' && b != '\n' {
				line = append(line, b)
				continue
			}
			cmd := string(line)
			line = line[:0]
			if cmd == "" {
				continue
			}
			log.add(&log.commands, cmd)
			out, ok := cfg.Responses[cmd]
			if !ok && cfg.Lookup != nil {
				out, ok = cfg.Lookup(cmd)
			}
			if !ok {
				out = "% Unrecognized command"
			}
			if p, ok := cfg.PromptAfter[cmd]; ok {
				prompt = p
			}
			if out != "" {
				out = strings.ReplaceAll(out, "\n", "\r\n") + "\r\n"
			}
			if _, err := io.WriteString(ch, out+prompt); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
