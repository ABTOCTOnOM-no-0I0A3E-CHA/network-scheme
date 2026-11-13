package web

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/pki"
)

/*
After nmsctl certs rotate (install.ReissueCert for the executor and the
gateway, the pin set to the new gateway key), the restarted server serves
its reissued certificate to the reissued gateway and refuses the previous
gateway certificate, although it chains to the same CA with CN gateway.
*/
func TestRotatedCertificates(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, err := pki.NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldGw, oldGwKey, err := pki.IssueClientCert(ca, caKey, "gateway", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	oldEx, _, err := pki.IssueServerCert(ca, caKey, []string{"executor"}, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"ca.crt": ca, "ca.key": caKey, "gateway_client.crt": oldGw, "executor_tls.crt": oldEx} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	exCrt, exKey, err := install.ReissueCert(dir, "executor")
	if err != nil {
		t.Fatal(err)
	}
	gwCrt, gwKey, err := install.ReissueCert(dir, "gateway")
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"executor.crt": exCrt, "executor.key": exKey} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := &certs{dir: dir, roots: x509.NewCertPool(), clients: map[string]tls.Certificate{}}
	c.roots.AppendCertsFromPEM(ca)
	for name, pair := range map[string][2][]byte{"gateway": {gwCrt, gwKey}, "old": {oldGw, oldGwKey}} {
		kp, err := tls.X509KeyPair(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		c.clients[name] = kp
	}
	h := startWith(t, c, func(cfg *Config) { cfg.GatewaySPKI = spki(t, c.clients["gateway"]) })
	get := func(cl *http.Client) error {
		req, _ := http.NewRequest(http.MethodGet, "https://executor/x/status", nil)
		req.Host = "nms.test:8443"
		req.Header.Set("X-Forwarded-For", "192.0.2.10")
		resp, err := cl.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := get(h.client("gateway")); err != nil {
		t.Fatalf("the reissued gateway: %v", err)
	}
	if err := get(h.client("old")); err == nil {
		t.Fatal("the previous gateway certificate was served after the rotation")
	}
}
