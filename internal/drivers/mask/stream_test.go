package mask_test

import (
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers/mask"
)

/* A block one piece opens goes on being masked in the next pieces, until its end; then lines are masked as usual again. */
func TestStreamKeepsBlocksAcrossPieces(t *testing.T) {
	var s mask.Stream
	pieces := []string{"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA", "PemBody88Tt\nmore", "-----END RSA PRIVATE KEY-----\nhostname a",
		"crypto certificate c1 import", "CertBody77Rr", ".", "hostname b"}
	var out []string
	for _, p := range pieces {
		out = append(out, s.Secrets(p))
	}
	all := strings.Join(out, "\n")
	for _, secret := range []string{"MIIEpAIBAAKCAQEA", "PemBody88Tt", "more", "CertBody77Rr"} {
		if strings.Contains(all, secret) {
			t.Fatalf("%q in %q", secret, out)
		}
	}
	if !strings.HasSuffix(out[2], "hostname a") || out[5] != "." || out[6] != "hostname b" {
		t.Fatalf("after the blocks: %q", out)
	}
}
