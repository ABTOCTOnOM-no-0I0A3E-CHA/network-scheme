package devemu

import (
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

const testPW = "emu-test-pw-1"

func creds(c *sshemu.Config) { c.Username, c.Password = "admin", testPW }

func dial(addr netip.AddrPort, cc *gossh.ClientConfig) (*gossh.Client, error) {
	cc.Timeout = 10 * time.Second
	if cc.User == "" {
		cc.User = "admin"
	}
	if cc.Auth == nil {
		cc.Auth = []gossh.AuthMethod{gossh.Password(testPW)}
	}
	return gossh.Dial("tcp", addr.String(), cc)
}

/* shellIO opens a shell and returns its stdin and a reader of its stdout. */
func shellIO(t *testing.T, c *gossh.Client) (io.WriteCloser, *outReader) {
	t.Helper()
	s, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	in, err := s.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	r := &outReader{ch: make(chan string, 64)}
	go func() {
		b := make([]byte, 4096)
		for {
			n, err := out.Read(b)
			if n > 0 {
				r.ch <- string(b[:n])
			}
			if err != nil {
				close(r.ch)
				return
			}
		}
	}()
	return in, r
}

type outReader struct {
	ch  chan string
	buf string
	eof bool
}

/* until reads until the output ends with suffix; it fails on EOF or after 5 s. */
func (r *outReader) until(t *testing.T, suffix string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for !strings.HasSuffix(r.buf, suffix) {
		select {
		case s, ok := <-r.ch:
			if !ok {
				t.Fatalf("EOF waiting for %q; got %q", suffix, r.buf)
			}
			r.buf += s
		case <-deadline:
			t.Fatalf("timeout waiting for %q; got %q", suffix, r.buf)
		}
	}
	out := r.buf
	r.buf = ""
	return out
}

/* closed waits until the device closes the channel and returns what came before. */
func (r *outReader) closed(t *testing.T) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case s, ok := <-r.ch:
			if !ok {
				return r.buf
			}
			r.buf += s
		case <-deadline:
			t.Fatalf("channel still open; got %q", r.buf)
		}
	}
}

/* TestSSHShell: over SSH the device echoes, prompts and journals like the in-memory session. */
func TestSSHShell(t *testing.T) {
	d := NewLine(t, "esr", Options{})
	addr, hk, _ := StartSSH(t, d, creds)
	c, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	in, out := shellIO(t, c)
	out.until(t, "esr-lab-01#")
	_, _ = io.WriteString(in, "configure\r")
	if got := out.until(t, "esr-lab-01(config)#"); got != "configure\r\nesr-lab-01(config)#" {
		t.Fatalf("echo %q", got)
	}
	d.ExpectLines(t, "configure")
}

/* TestSSHAlgorithms: ESR offers no curve25519, MES 6.x signs its RSA host key only with ssh-rsa [R §4]. */
func TestSSHAlgorithms(t *testing.T) {
	esr := NewLine(t, "esr", Options{})
	addr, hk, _ := StartSSH(t, esr, creds)
	if _, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk),
		Config: gossh.Config{KeyExchanges: []string{gossh.KeyExchangeCurve25519}}}); err == nil {
		t.Fatal("esr: curve25519-only client connected")
	}
	if c, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk),
		Config: gossh.Config{KeyExchanges: []string{gossh.KeyExchangeECDHP256}}}); err != nil {
		t.Fatalf("esr: ecdh-sha2-nistp256: %v", err)
	} else {
		_ = c.Close()
	}

	mes := NewLine(t, "mes6", Options{})
	addr, hk, _ = StartSSH(t, mes, creds)
	if hk.Type() != gossh.KeyAlgoRSA {
		t.Fatalf("mes6 host key %s", hk.Type())
	}
	if _, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk),
		HostKeyAlgorithms: []string{gossh.KeyAlgoRSASHA256, gossh.KeyAlgoRSASHA512}}); err == nil {
		t.Fatal("mes6: rsa-sha2 client connected")
	}
	c, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk), HostKeyAlgorithms: []string{gossh.KeyAlgoRSA}})
	if err != nil {
		t.Fatalf("mes6: ssh-rsa: %v", err)
	}
	_ = c.Close()
}

/* TestSSHKeyboardInteractive: MES 6.x takes the password through keyboard-interactive too [R §4]. */
func TestSSHKeyboardInteractive(t *testing.T) {
	d := NewLine(t, "mes6", Options{})
	addr, hk, log := StartSSH(t, d, creds)
	ki := gossh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
		return []string{testPW}, nil
	})
	c, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk), HostKeyAlgorithms: []string{gossh.KeyAlgoRSA},
		Auth: []gossh.AuthMethod{ki}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if a := log.AuthAttempts(); !strings.Contains(strings.Join(a, ","), "keyboard-interactive:"+testPW) {
		t.Fatalf("auth attempts %v", a)
	}
}

/* TestSSHInbandLogin: without SSH authentication the device asks User Name:/Password: in the channel [R §4]. */
func TestSSHInbandLogin(t *testing.T) {
	d := NewLine(t, "mes6", Options{InbandLogin: true, Users: map[string]User{"admin": {Password: testPW, Privilege: 15}}})
	addr, hk, _ := StartSSH(t, d, nil)
	c, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk), HostKeyAlgorithms: []string{gossh.KeyAlgoRSA},
		Auth: []gossh.AuthMethod{}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	in, out := shellIO(t, c)
	out.until(t, "User Name:")
	_, _ = io.WriteString(in, "admin\r")
	out.until(t, "Password:")
	_, _ = io.WriteString(in, testPW+"\r")
	if got := out.until(t, "sw-lab-01#"); strings.Contains(got, testPW) {
		t.Fatalf("password echoed: %q", got)
	}
}

/* TestSSHDisconnectAfter: the link drops right after the Nth line reached the device; its output never arrives. */
func TestSSHDisconnectAfter(t *testing.T) {
	d := NewLine(t, "esr", Options{})
	addr, hk, _ := StartSSH(t, d, func(c *sshemu.Config) { creds(c); c.DisconnectAfter = 3 })
	c, err := dial(addr, &gossh.ClientConfig{HostKeyCallback: gossh.FixedHostKey(hk)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	in, out := shellIO(t, c)
	out.until(t, "esr-lab-01#")
	_, _ = io.WriteString(in, "configure\r")
	out.until(t, "(config)#")
	_, _ = io.WriteString(in, "hostname cut\r")
	out.until(t, "(config)#")
	_, _ = io.WriteString(in, "do commit\r")
	if rest := out.closed(t); strings.Contains(rest, "Commit timer") {
		t.Fatalf("output after the cut: %q", rest)
	}
	d.ExpectLines(t, "configure", "hostname cut", "do commit")
	if d.Pending().IsZero() {
		t.Fatal("the last line reached the device: commit should be pending")
	}
}
