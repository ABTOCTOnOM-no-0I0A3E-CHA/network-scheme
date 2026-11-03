package devemu

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/netip"
	"slices"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/test/sim/sshemu"
)

/*
SSHConfig returns the transport of the profile serving d: a fresh host key of
the profile's type, its KEX, cipher and host-key algorithm limits [R §4],
keyboard-interactive when the profile lists it, no SSH authentication with
Options.InbandLogin, and d as the shell. The caller sets Username and Password
and may change anything else.
*/
func (d *Device) SSHConfig() (sshemu.Config, error) {
	ssh := d.P.SSH
	var (
		key gossh.Signer
		err error
	)
	switch ssh.HostKey {
	case "rsa":
		key, err = sshemu.RSAHostKey()
	case "ecdsa":
		var k *ecdsa.PrivateKey
		if k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err == nil {
			key, err = gossh.NewSignerFromKey(k)
		}
	default:
		var k ed25519.PrivateKey
		if _, k, err = ed25519.GenerateKey(rand.Reader); err == nil {
			key, err = gossh.NewSignerFromKey(k)
		}
	}
	if err != nil {
		return sshemu.Config{}, err
	}
	return sshemu.Config{
		HostKey:             key,
		KeyExchanges:        ssh.KeyExchanges,
		Ciphers:             ssh.Ciphers,
		HostKeyAlgorithms:   ssh.HostKeyAlgorithms,
		KeyboardInteractive: slices.Contains(ssh.Auth, "keyboard-interactive"),
		NoClientAuth:        d.opt.InbandLogin,
		Shell:               d.Serve,
	}, nil
}

/*
StartSSH serves d over SSH on 127.0.0.1 until the test ends; edit may change
the configuration (credentials, DisconnectAfter) first. It returns the
address, the host key and the transport log.
*/
func StartSSH(t testing.TB, d *Device, edit func(*sshemu.Config)) (netip.AddrPort, gossh.PublicKey, *sshemu.Log) {
	t.Helper()
	cfg, err := d.SSHConfig()
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(&cfg)
	}
	t.Cleanup(d.Disconnect)
	addr, log := sshemu.Start(t, cfg)
	return addr, cfg.HostKey.PublicKey(), log
}
