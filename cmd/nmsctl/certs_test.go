package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/pki"
)

func leaf(t *testing.T, crt string) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode([]byte(crt))
	if b == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pinOf(t *testing.T, crt string) string {
	t.Helper()
	s := sha256.Sum256(leaf(t, crt).RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}

/* certSecrets is a secrets directory with the internal CA, its leaves and a corporate web certificate; executor.yaml pins the gateway. */
func certSecrets(t *testing.T, pinned bool) (dir, yaml string) {
	t.Helper()
	ca, caKey, err := pki.NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	corp, corpKey, err := pki.NewCA("corporate CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"ca.crt": string(ca), "ca.key": string(caKey)}
	for stem, issue := range map[string]func() ([]byte, []byte, error){
		"gateway_client": func() ([]byte, []byte, error) { return pki.IssueClientCert(ca, caKey, "gateway", time.Hour) },
		"executor_tls":   func() ([]byte, []byte, error) { return pki.IssueServerCert(ca, caKey, []string{"executor"}, nil, time.Hour) },
		"syslog":         func() ([]byte, []byte, error) { return pki.IssueServerCert(ca, caKey, []string{"nms.test"}, nil, time.Hour) },
		"web":            func() ([]byte, []byte, error) { return pki.IssueServerCert(corp, corpKey, []string{"nms.test"}, nil, time.Hour) },
	} {
		crt, key, err := issue()
		if err != nil {
			t.Fatal(err)
		}
		files[stem+".crt"], files[stem+".key"] = string(crt), string(key)
	}
	dir = withSecrets(t, files)
	yaml = filepath.Join(t.TempDir(), "executor.yaml")
	y := "listen_xnet: \"10.0.0.2:8443\"\n"
	if pinned {
		y += "gateway_spki_sha256: \"" + pinOf(t, files["gateway_client.crt"]) + "\"\nstate_dir: \"/var/lib/executor\"\n"
	}
	if err := os.WriteFile(yaml, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	old := executorYAMLPath
	executorYAMLPath = yaml
	t.Cleanup(func() { executorYAMLPath = old })
	return dir, yaml
}

/*
certs rotate (all) reissues every leaf of the internal CA under a new key
with the same names, pins the executor to the new gateway key, keeps a
corporate web certificate, and restarts the services that load them once.
*/
func TestCertsRotateAll(t *testing.T) {
	dir, yaml := certSecrets(t, true)
	before := map[string]string{}
	for _, f := range []string{"gateway_client.crt", "executor_tls.crt", "syslog.crt", "web.crt", "web.key"} {
		before[f] = read(t, filepath.Join(dir, f))
	}
	sys := &rotator{}
	code, out := hostRun(t, sys, "certs", "rotate")
	if code != 0 || !strings.Contains(out, "web certificate") {
		t.Fatalf("%d %s", code, out)
	}
	if got := strings.Join(sys.argv(), "\n"); got != "docker compose -f /etc/nms/compose.yaml restart executor gateway eventd" {
		t.Fatalf("commands:\n%s", got)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(read(t, filepath.Join(dir, "ca.crt"))))
	for stem, eku := range map[string]x509.ExtKeyUsage{"gateway_client": x509.ExtKeyUsageClientAuth, "executor_tls": x509.ExtKeyUsageServerAuth,
		"syslog": x509.ExtKeyUsageServerAuth} {
		crt := read(t, filepath.Join(dir, stem+".crt"))
		if crt == before[stem+".crt"] {
			t.Errorf("%s not reissued", stem)
		}
		if _, err := tls.X509KeyPair([]byte(crt), []byte(read(t, filepath.Join(dir, stem+".key")))); err != nil {
			t.Errorf("%s: %v", stem, err)
		}
		if _, err := leaf(t, crt).Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{eku}}); err != nil {
			t.Errorf("%s: %v", stem, err)
		}
		if _, err := os.Stat(filepath.Join(dir, stem+".crt"+install.NextSuffix)); err == nil {
			t.Errorf("%s: staged file left", stem)
		}
	}
	if c := leaf(t, read(t, filepath.Join(dir, "gateway_client.crt"))); c.Subject.CommonName != "gateway" {
		t.Errorf("gateway CN %q", c.Subject.CommonName)
	}
	if c := leaf(t, read(t, filepath.Join(dir, "syslog.crt"))); len(c.DNSNames) != 1 || c.DNSNames[0] != "nms.test" {
		t.Errorf("syslog names %v", c.DNSNames)
	}
	if read(t, filepath.Join(dir, "web.crt")) != before["web.crt"] || read(t, filepath.Join(dir, "web.key")) != before["web.key"] {
		t.Error("the corporate web certificate was replaced")
	}
	want := "listen_xnet: \"10.0.0.2:8443\"\ngateway_spki_sha256: \"" + pinOf(t, read(t, filepath.Join(dir, "gateway_client.crt"))) +
		"\"\nstate_dir: \"/var/lib/executor\"\n"
	if read(t, yaml) != want {
		t.Errorf("executor.yaml:\n%s", read(t, yaml))
	}
	if code, _ := hostRun(t, &rotator{}, "certs", "rotate", "web"); code == 0 {
		t.Error("a corporate web certificate named alone was reissued")
	}
	if code, _ := hostRun(t, &rotator{}, "certs", "rotate", "ca"); code == 0 {
		t.Error("certs rotate ca was accepted")
	}
}

/*
Interrupted after the new gateway key was renamed into place but before its
certificate, the command run again finishes with the staged certificate
(not a third pair), adds the pin when there was none, and restarts the
gateway and the executor.
*/
func TestCertsRotateResumes(t *testing.T) {
	dir, yaml := certSecrets(t, false)
	crtP, keyP := filepath.Join(dir, "gateway_client.crt"), filepath.Join(dir, "gateway_client.key")
	staged, err := stagedCert(crtP, keyP, 0, deps{errw: &strings.Builder{}, sys: &fakeSys{}},
		func() ([]byte, []byte, error) { return install.ReissueCert(dir, "gateway") })
	if err != nil {
		t.Fatal(err)
	}
	if err := install.PromoteSecret(keyP); err != nil {
		t.Fatal(err)
	}
	sys := &rotator{}
	if code, out := hostRun(t, sys, "certs", "rotate", "gateway"); code != 0 || !strings.Contains(out, "resuming") {
		t.Fatalf("%d %s", code, out)
	}
	if read(t, crtP) != string(staged) {
		t.Fatal("the staged certificate was not the one put in place")
	}
	if _, err := tls.X509KeyPair([]byte(read(t, crtP)), []byte(read(t, keyP))); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(read(t, yaml), "\ngateway_spki_sha256: \""+pinOf(t, string(staged))+"\"\n") {
		t.Errorf("executor.yaml:\n%s", read(t, yaml))
	}
	if got := strings.Join(sys.argv(), "\n"); got != "docker compose -f /etc/nms/compose.yaml restart gateway executor" {
		t.Fatalf("commands:\n%s", got)
	}
}
