package transport

import (
	"errors"
	"slices"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"github.com/beekamai/network-scheme/test/sim/devemu"
)

/*
C5: a device that no longer has a key of the pinned type (an RSA key
pinned, the device now offers only ed25519) is a host key mismatch: refused
before any authentication, with the high hostkey_mismatch_write alert. An
RSA device signing only with ssh-rsa while the SHA-1 flag is off still has
its pinned key: a handshake failure without that alert.
*/
func TestNoKeyOfThePinnedTypeIsAMismatch(t *testing.T) {
	r := start(t, "mes10", devemu.Options{}, nil) /* the MES 10.x profile has an ed25519 host key */
	r.src.t.hostAlgo, r.src.t.hostFP = gossh.KeyAlgoRSA, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := r.dial(t); !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("no key of the pinned type: %v", err)
	}
	if len(r.log.AuthAttempts()) != 0 || len(r.d.Journal()) != 0 {
		t.Fatalf("credential or input reached the device: %q %v", r.log.AuthAttempts(), r.d.Journal())
	}
	if got := r.al.list(); !slices.Equal(got, []string{KindHostKeyMismatch + "/high"}) {
		t.Fatalf("alerts %q", got)
	}

	r = start(t, "mes6", devemu.Options{}, nil)
	r.src.t.rsaSHA1 = false
	if _, err := r.dial(t); errors.Is(err, ErrHostKeyMismatch) || !errors.Is(err, ErrHandshake) || len(r.al.list()) != 0 {
		t.Fatalf("ssh-rsa without the flag: %v, alerts %q", err, r.al.list())
	}
}
