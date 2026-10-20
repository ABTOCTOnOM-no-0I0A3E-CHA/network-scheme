// Package pki issues the internal ECDSA P-256 CA and server certificates.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

/* skew backdates NotBefore to tolerate clock differences between hosts. */
const skew = 5 * time.Minute

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

/* keyID is SHA-256 of the public point truncated to 160 bits (RFC 7093 method 1 style). */
func keyID(pub *ecdsa.PublicKey) []byte {
	pt, err := pub.ECDH()
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(pt.Bytes())
	return sum[:20]
}

func encodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// NewCA creates a self-signed ECDSA P-256 CA (IsCA, MaxPathLen 0) and returns PEM cert and PKCS#8 key.
func NewCA(cn string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	if validity <= 0 {
		return nil, nil, errors.New("validity must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-skew),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          keyID(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}

// IssueServerCert issues an ECDSA P-256 server-auth certificate signed by the given CA.
// At least one DNS name or IP is required.
func IssueServerCert(caCertPEM, caKeyPEM []byte, dnsNames []string, ips []net.IP, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	if len(dnsNames) == 0 && len(ips) == 0 {
		return nil, nil, errors.New("at least one DNS name or IP is required")
	}
	if validity <= 0 {
		return nil, nil, errors.New("validity must be positive")
	}
	cb, _ := pem.Decode(caCertPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, errors.New("invalid CA certificate PEM")
	}
	ca, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	kb, _ := pem.Decode(caKeyPEM)
	if kb == nil {
		return nil, nil, errors.New("invalid CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}
	caKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("CA key is not ECDSA")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	cn := ""
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	} else {
		cn = ips[0].String()
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-skew),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		SubjectKeyId:          keyID(&key.PublicKey),
		AuthorityKeyId:        ca.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err = encodeKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM, nil
}
