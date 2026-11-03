package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("no pem")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestServerCertChainsToCA(t *testing.T) {
	caCert, caKey, err := NewCA("nms test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca := parse(t, caCert)
	if !ca.IsCA || !ca.MaxPathLenZero || ca.MaxPathLen != 0 {
		t.Fatal("CA constraints wrong")
	}
	cert, key, err := IssueServerCert(caCert, caKey, []string{"nms.example"}, []net.IP{net.ParseIP("10.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if blk, _ := pem.Decode(key); blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatal("key must be PKCS#8 PRIVATE KEY")
	}
	leaf := parse(t, cert)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	for _, opts := range []x509.VerifyOptions{
		{Roots: pool, DNSName: "nms.example", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	} {
		if _, err := leaf.Verify(opts); err != nil {
			t.Fatal(err)
		}
	}
	if err := leaf.VerifyHostname("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if leaf.VerifyHostname("other.example") == nil {
		t.Fatal("wrong SAN accepted")
	}
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("leaf must not be CA")
	}
	if len(leaf.SubjectKeyId) == 0 || string(leaf.AuthorityKeyId) != string(ca.SubjectKeyId) {
		t.Fatal("key ids wrong")
	}
	if leaf.SerialNumber.BitLen() < 100 {
		t.Fatal("serial too small")
	}
	if !leaf.NotBefore.Before(time.Now()) {
		t.Fatal("NotBefore should be in the past")
	}
}

func TestIssueServerCertValidation(t *testing.T) {
	caCert, caKey, _ := NewCA("ca", time.Hour)
	if _, _, err := IssueServerCert(caCert, caKey, nil, nil, time.Hour); err == nil {
		t.Fatal("expected error without SANs")
	}
	if _, _, err := IssueServerCert([]byte("x"), caKey, []string{"a"}, nil, time.Hour); err == nil {
		t.Fatal("expected error on bad CA")
	}
	if _, _, err := IssueServerCert(caCert, caKey, []string{"a"}, nil, 0); err == nil {
		t.Fatal("expected error on zero validity")
	}
	if _, _, err := NewCA("ca", 0); err == nil {
		t.Fatal("expected error on zero validity")
	}
}

/* A client certificate verifies as clientAuth under its CA only, never as a server certificate, and carries its CN and validity. */
func TestClientCertClientAuthOnly(t *testing.T) {
	caCert, caKey, err := NewCA("nms test CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := IssueClientCert(caCert, caKey, "gateway", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if blk, _ := pem.Decode(key); blk == nil || blk.Type != "PRIVATE KEY" {
		t.Fatal("key must be PKCS#8 PRIVATE KEY")
	}
	leaf := parse(t, cert)
	if leaf.Subject.CommonName != "gateway" || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 {
		t.Fatalf("subject %q, SANs %v %v", leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatalf("EKU %v, CA %v, key usage %v", leaf.ExtKeyUsage, leaf.IsCA, leaf.KeyUsage)
	}
	if d := time.Until(leaf.NotAfter); d > 2*time.Hour || d < 2*time.Hour-time.Minute || !leaf.NotBefore.Before(time.Now()) {
		t.Fatalf("validity %v .. %v", leaf.NotBefore, leaf.NotAfter)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parse(t, caCert))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client certificate accepted for serverAuth")
	}
	otherCert, _, err := NewCA("other CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	other := x509.NewCertPool()
	other.AddCert(parse(t, otherCert))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: other, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("client certificate verified under a foreign CA")
	}
	if _, _, err := IssueClientCert(caCert, caKey, "", time.Hour); err == nil {
		t.Fatal("expected error without a common name")
	}
	if _, _, err := IssueClientCert(caCert, caKey, "gateway", 0); err == nil {
		t.Fatal("expected error on zero validity")
	}
	if _, _, err := IssueClientCert([]byte("x"), caKey, "gateway", time.Hour); err == nil {
		t.Fatal("expected error on bad CA")
	}
}
