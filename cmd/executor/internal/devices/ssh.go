package devices

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

/* KindHostKeyMismatch is the alert of a host key that is not the pinned one (internal/triggers: high, about the device). */
const KindHostKeyMismatch = "hostkey_mismatch_write"

/* HandshakeTimeout bounds the SSH handshake of a probe or a dial (after the TCP connect). */
var HandshakeTimeout = 15 * time.Second

/* Errors of the SSH side. */
var (
	ErrHostKeyMismatch = errors.New("devices: the device presented another host key than the pinned one")
	ErrUnconfirmed     = errors.New("devices: the device is not confirmed (no pinned host key): accept its host key first")
	errProbed          = errors.New("devices: host key read, nothing more is sent")
)

/* keyTypes are the host key types the registry may pin (write_device.hostkey_algo). */
var keyTypes = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA}

/*
hostKeyAlgorithms are the signature algorithms offered for the server's host
key: for a pinned key only its own type (RSA: SHA-2, and ssh-rsa with SHA-1
only with the registry's allow_ssh_rsa_sha1 [R §9.10]); unpinned (a probe)
every type the registry may pin.
*/
func hostKeyAlgorithms(pinned string, sha1 bool) []string {
	var out []string
	for _, t := range keyTypes {
		if pinned != "" && t != pinned {
			continue
		}
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
		return Key{}, fmt.Errorf("devices: probe %s: %w", ap, err)
	}
	defer func() { _ = conn.Close() }()
	var got ssh.PublicKey
	_, _, _, err = handshake(conn, ap.String(), &ssh.ClientConfig{
		User:              "nms-hostkey-probe",
		HostKeyAlgorithms: hostKeyAlgorithms("", t.AllowSHA1),
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			got = k
			return errProbed
		},
	})
	if got == nil {
		return Key{}, fmt.Errorf("devices: probe %s: no host key: %w", ap, err)
	}
	k := keyOf(got)
	if !slices.Contains(keyTypes, k.Algo) {
		return Key{}, refuse("device %d presents a host key of type %q, which cannot be pinned", t.ID, k.Algo)
	}
	return k, nil
}

/*
Dial opens an SSH connection to d, a device of a verified registry
snapshot: its address and port, and only its pinned host key (type and
fingerprint). Another key fails the handshake at the host key check,
before any authentication method is tried, so no credential is sent; it
raises a high alert about the device. An unconfirmed device (no pin) is
never dialed.
*/
func (s *Service) Dial(ctx context.Context, d Device, user string, auth []ssh.AuthMethod) (*ssh.Client, error) {
	if !d.Pinned() {
		return nil, ErrUnconfirmed
	}
	if d.Protocol != "ssh" {
		return nil, fmt.Errorf("devices: device %d: protocol %q is not supported", d.ID, d.Protocol)
	}
	ap := netip.AddrPortFrom(d.Address, uint16(d.Port)) // #nosec G115 -- the registry's CHECK bounds the port
	conn, err := s.Net.Dial(ctx, ap)
	if err != nil {
		return nil, fmt.Errorf("devices: dial %s: %w", ap, err)
	}
	var seen *Key
	c, chans, reqs, err := handshake(conn, ap.String(), &ssh.ClientConfig{
		User: user, Auth: auth,
		HostKeyAlgorithms: hostKeyAlgorithms(d.Algo, d.AllowSHA1),
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if got := keyOf(k); got != (Key{d.Algo, d.FP}) {
				seen = &got
				return ErrHostKeyMismatch
			}
			return nil
		},
	})
	if err != nil {
		_ = conn.Close()
		if seen != nil {
			s.Guard.AlertDevice(ctx, KindHostKeyMismatch, "high", d.ID, fmt.Sprintf(
				"device %d at %s presented host key %s %s, pinned %s %s: refused before authentication", d.ID, ap, seen.Algo, seen.FP, d.Algo, d.FP))
			return nil, fmt.Errorf("devices: device %d: %w", d.ID, ErrHostKeyMismatch)
		}
		if strings.Contains(err.Error(), "no common algorithm for host key") {
			/* Only the pinned type is offered: a device that has no key of that type any more has another key. */
			s.Guard.AlertDevice(ctx, KindHostKeyMismatch, "high", d.ID, fmt.Sprintf(
				"device %d at %s offers no host key of the pinned type %s: refused before authentication", d.ID, ap, d.Algo))
			return nil, fmt.Errorf("devices: device %d: %w", d.ID, ErrHostKeyMismatch)
		}
		return nil, fmt.Errorf("devices: device %d: %w", d.ID, err)
	}
	return ssh.NewClient(c, chans, reqs), nil
}
