/*
Package sshemu is an in-process SSH server that imitates a network device CLI
for tests. It records every line the client sends and every authentication
attempt, so tests can prove what did (and did not) reach the device.
*/
package sshemu

import (
	"crypto/ed25519"
	"crypto/rand"
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
	HostKey       gossh.Signer      /* required */
	Prompt        string            /* initial prompt, e.g. "sw1#" */
	Responses     map[string]string /* exact command line -> output ("\n" is sent as "\r\n") */
	PromptAfter   map[string]string /* command line -> prompt shown from then on */
	Username      string            /* accepted user; empty accepts any */
	Password      string            /* accepted password; empty disables password auth */
	AuthorizedKey gossh.PublicKey   /* accepted client key; nil disables public key auth */
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
	sc := &gossh.ServerConfig{
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
	sc.AddHostKey(cfg.HostKey)

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

func serve(c net.Conn, sc *gossh.ServerConfig, cfg Config, log *Log) {
	defer func() { _ = c.Close() }()
	_, chans, reqs, err := gossh.NewServerConn(c, sc)
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
		go session(ch, creqs, cfg, log)
	}
}

func session(ch gossh.Channel, reqs <-chan *gossh.Request, cfg Config, log *Log) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			shell(ch, cfg, log)
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

/* shell echoes nothing; it answers each line with its response and the prompt. */
func shell(ch gossh.Channel, cfg Config, log *Log) {
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
