package devices

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

/* HandshakeTimeout bounds the SSH handshake of a probe (after the TCP connect). */
var HandshakeTimeout = 15 * time.Second

/* errProbed stops a probe's handshake at the host key: nothing more is sent. */
var errProbed = errors.New("devices: host key read, nothing more is sent")

/* keyTypes are the host key types the registry may pin (write_device.hostkey_algo). */
var keyTypes = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA}

/*
hostKeyAlgorithms are the signature algorithms a probe offers for the host
key: every type the registry may pin (RSA: SHA-2, and ssh-rsa with SHA-1
only with allow_ssh_rsa_sha1 [R §9.10]). Connections to a pinned key are
package transport's alone.
*/
func hostKeyAlgorithms(sha1 bool) []string {
	var out []string
	for _, t := range keyTypes {
		if t == ssh.KeyAlgoRSA {
			out = append(out, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
			if sha1 {
				out = append(out, ssh.KeyAlgoRSA)
			}
			continue
		}
		out = append(out, t)
	}
	return out
}

/* Key is a host key as the registry pins it: its type and SHA-256 fingerprint. */
type Key struct{ Algo, FP string }

func keyOf(k ssh.PublicKey) Key { return Key{Algo: k.Type(), FP: ssh.FingerprintSHA256(k)} }

/* handshake runs the SSH client handshake on conn within HandshakeTimeout. */
func handshake(conn net.Conn, addr string, cfg *ssh.ClientConfig) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	_ = conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err == nil {
		_ = conn.SetDeadline(time.Time{})
	}
	return c, chans, reqs, err
}

/*
Probe reads the host key of t's address WITHOUT authentication: the
handshake stops at the host key check (no authentication request, no
credential is ever sent), so nothing but the key exchange reaches the
device. The address passes the network guard first. Probes are bounded in
number (one connection each).
*/
func (s *Service) Probe(ctx context.Context, t Target) (Key, error) {
	if err := s.checkTarget(t); err != nil {
		return Key{}, err
	}
	select {
	case s.probes <- struct{}{}:
		defer func() { <-s.probes }()
	case <-ctx.Done():
		return Key{}, ctx.Err()
	}
	ap := netip.AddrPortFrom(t.Address, uint16(t.Port)) // #nosec G115 -- checkTarget bounds the port
	conn, err := s.Net.Dial(ctx, ap)
	if err != nil {
		return Key{}, wrapRefusal(fmt.Errorf("device %d: cannot reach %s: %w", t.ID, ap, err))
	}
	defer func() { _ = conn.Close() }()
	var got ssh.PublicKey
	_, _, _, err = handshake(conn, ap.String(), &ssh.ClientConfig{
		User:              "nms-hostkey-probe",
		HostKeyAlgorithms: hostKeyAlgorithms(t.AllowSHA1),
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			got = k
			return errProbed
		},
	})
	if got == nil {
		return Key{}, wrapRefusal(fmt.Errorf("device %d: no host key read from %s: %w", t.ID, ap, err))
	}
	k := keyOf(got)
	if !slices.Contains(keyTypes, k.Algo) {
		return Key{}, refuse("device %d presents a host key of type %q, which cannot be pinned", t.ID, k.Algo)
	}
	return k, nil
}
