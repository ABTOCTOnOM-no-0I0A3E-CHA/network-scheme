package install

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/beekamai/network-scheme/internal/pki"
)

/*
Internal certificate rotation (nmsctl certs rotate): a leaf certificate is
reissued from the internal CA under a new key, with the names of the one it
replaces, valid a year; its consumer restarts. The CA itself is not
rotated: the devices trust ca.crt for TLS syslog, put there by hand, so a
new CA needs every device reconfigured, which no host command can do; its
key never leaves the host (root, 0400) and it lives 10 years. A leaked
service key is answered by reissuing the leaf. With one CA an old leaf
still verifies until it expires: for the one client certificate that
matters (the gateway's, the only client the executor accepts) the rotation
pins the executor to the new key (gateway_spki_sha256), so the old one is
refused from the executor's restart on.
*/

/* LeafCert is a certificate nmsctl certs rotate reissues: its file stem in the secrets directory, its consumer's uid, the services that load it. */
type LeafCert struct {
	Stem     string
	UID      int
	Services []string
}

/* LeafCertNames are the rotatable certificates, in rotation order (LeafCerts). */
var LeafCertNames = []string{"executor", "gateway", "syslog", "web"}

/* LeafCerts are the rotatable certificates by name. */
var LeafCerts = map[string]LeafCert{
	"executor": {"executor_tls", ExecutorUID, []string{"executor"}},
	"gateway":  {"gateway_client", ContainerUID, []string{"gateway", "executor"}}, /* executor: the pin */
	"syslog":   {"syslog", ContainerUID, []string{"eventd"}},
	"web":      {"web", ContainerUID, []string{"gateway"}},
}

/* ErrForeignCert means the current certificate was not issued by the internal CA (a corporate web certificate): it is not reissued. */
var ErrForeignCert = errors.New("not issued by the internal CA")

/*
ReissueCert issues a new certificate and key (PEM) for the leaf name from
the CA in dir: the gateway's a clientAuth certificate with CN gateway, the
executor's a server certificate for its xnet name, the others server
certificates for the names of the current one, which must chain to the CA
(an expired one too).
*/
func ReissueCert(dir, name string) (crtPEM, keyPEM []byte, err error) {
	c, ok := LeafCerts[name]
	if !ok {
		return nil, nil, fmt.Errorf("install: no certificate %q", name)
	}
	caCrt, err := os.ReadFile(filepath.Join(dir, "ca.crt")) // #nosec G304 -- the installation's secrets
	if err != nil {
		return nil, nil, fmt.Errorf("install: %w", err)
	}
	caKey, err := os.ReadFile(filepath.Join(dir, "ca.key")) // #nosec G304 -- the installation's secrets
	if err != nil {
		return nil, nil, fmt.Errorf("install: %w", err)
	}
	defer clear(caKey)
	raw, err := os.ReadFile(filepath.Join(dir, c.Stem+".crt")) // #nosec G304 -- the installation's secrets
	if err != nil {
		return nil, nil, fmt.Errorf("install: %w", err)
	}
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("install: %s.crt: no PEM certificate", c.Stem)
	}
	cur, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("install: %s.crt: %w", c.Stem, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caCrt) {
		return nil, nil, errors.New("install: ca.crt: no PEM certificate")
	}
	if _, err := cur.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: cur.NotBefore,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, nil, fmt.Errorf("%s.crt: %w", c.Stem, ErrForeignCert)
	}
	switch name {
	case "gateway":
		return pki.IssueClientCert(caCrt, caKey, gatewayClientCN, webValidity)
	case "executor":
		return pki.IssueServerCert(caCrt, caKey, []string{executorServerName}, nil, webValidity)
	}
	return pki.IssueServerCert(caCrt, caKey, cur.DNSNames, cur.IPAddresses, webValidity)
}
