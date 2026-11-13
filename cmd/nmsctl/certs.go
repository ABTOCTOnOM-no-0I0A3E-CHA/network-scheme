package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/beekamai/network-scheme/internal/install"
)

/* executorYAMLPath is the executor's configuration on the host (the gateway pin); tests point it elsewhere. */
var executorYAMLPath = filepath.Join(install.DefaultEtc, "config", "executor.yaml")

var pinRe = regexp.MustCompile(`(?m)^gateway_spki_sha256:.*$`)

const certsUsage = "usage: nmsctl certs rotate [executor|gateway|syslog|web|all]"

/*
certsCmd is "nmsctl certs rotate [NAME|all]" (on the host; all by default):
each certificate is reissued from the internal CA (install.ReissueCert),
staged as NAME.crt.next/NAME.key.next and only then renamed into place, the
key first; the gateway's also pins the executor to its new key (setPin)
before the swap. Then the services that load them restart. Interrupted, the
command run again resumes from the staged pairs. A web certificate the
internal CA did not issue (a corporate one) is skipped by "all".
*/
func certsCmd(ctx context.Context, d deps, args []string) error {
	names := install.LeafCertNames
	switch {
	case len(args) == 0 || (len(args) == 1 && args[0] == "all"):
	case len(args) == 1 && slices.Contains(install.LeafCertNames, args[0]):
		names = args[:1]
	default:
		return errors.New(certsUsage)
	}
	var restart []string
	for _, n := range names {
		c := install.LeafCerts[n]
		crtP, keyP := filepath.Join(secretsDir, c.Stem+".crt"), filepath.Join(secretsDir, c.Stem+".key")
		crt, err := stagedCert(crtP, keyP, c.UID, d, func() ([]byte, []byte, error) { return install.ReissueCert(secretsDir, n) })
		if errors.Is(err, install.ErrForeignCert) && len(names) > 1 {
			printf(d.out, "%s certificate: %v; kept\n", n, err)
			continue
		}
		if err != nil {
			return fmt.Errorf("%s certificate: %w", n, err)
		}
		if n == "gateway" {
			if err := setPin(crt); err != nil {
				return err
			}
		}
		if _, err := os.Stat(keyP + install.NextSuffix); err == nil {
			if err := install.PromoteSecret(keyP); err != nil {
				return err
			}
		}
		if err := install.PromoteSecret(crtP); err != nil {
			return err
		}
		for _, s := range c.Services {
			if !slices.Contains(restart, s) {
				restart = append(restart, s)
			}
		}
		printf(d.out, "%s certificate reissued from the internal CA\n", n)
	}
	if len(restart) == 0 {
		return nil
	}
	if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, append([]string{"restart"}, restart...)...); err != nil {
		return fmt.Errorf("restart %v: %w", restart, err)
	}
	return nil
}

/*
stagedCert returns the staged certificate of crtP: the pair an interrupted
rotation left (resumed: crtP.next with keyP.next, or with keyP when the key
was already renamed into place), or a new pair from gen, staged key first
(crtP.next is staged last, so it marks a complete pair).
*/
func stagedCert(crtP, keyP string, uid int, d deps, gen func() ([]byte, []byte, error)) ([]byte, error) {
	if crt, err := os.ReadFile(crtP + install.NextSuffix); err == nil { // #nosec G304 -- a file of the secrets directory
		key, err := os.ReadFile(keyP + install.NextSuffix) // #nosec G304 -- a file of the secrets directory
		if errors.Is(err, os.ErrNotExist) {
			key, err = os.ReadFile(keyP) // #nosec G304 -- a file of the secrets directory
		}
		if err == nil {
			_, err = tls.X509KeyPair(crt, key)
		}
		clear(key)
		if err == nil {
			printf(d.errw, "resuming the rotation staged in %s%s\n", crtP, install.NextSuffix)
			return crt, nil
		}
		if err := os.Remove(crtP + install.NextSuffix); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Remove(keyP + install.NextSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	crt, key, err := gen()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if err := install.StageSecret(keyP, key, uid, d.sys.Chown); err != nil {
		return nil, err
	}
	return crt, install.StageSecret(crtP, crt, uid, d.sys.Chown)
}

/* setPin sets gateway_spki_sha256 in executor.yaml to the SHA-256 of the public key of the certificate crt (replacing or adding the line). */
func setPin(crt []byte) error {
	b, _ := pem.Decode(crt)
	if b == nil {
		return errors.New("gateway certificate: no PEM block")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	line := fmt.Appendf(nil, "gateway_spki_sha256: %q", hex.EncodeToString(sum[:]))
	y, err := os.ReadFile(executorYAMLPath) // #nosec G304 -- the install's executor.yaml
	if err != nil {
		return err
	}
	switch len(pinRe.FindAll(y, -1)) {
	case 0:
		if len(y) > 0 && !bytes.HasSuffix(y, []byte("\n")) {
			y = append(y, '\n')
		}
		y = append(append(y, line...), '\n')
	case 1:
		y = pinRe.ReplaceAllLiteral(y, line)
	default:
		return fmt.Errorf("%s: more than one gateway_spki_sha256 line", executorYAMLPath)
	}
	return install.ReplaceFile(executorYAMLPath, y)
}
