package mask_test

import (
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers/mask"
)

/* blocked runs lines through a Stream and returns the ones it masks whole. */
func blocked(lines ...string) []string {
	var s mask.Stream
	var out []string
	for _, l := range lines {
		if s.Block(l) {
			out = append(out, l)
		}
	}
	return out
}

/* A block one answer opens goes on across answers while its lines are key material, until its end. */
func TestStreamKeepsBlocksAcrossPieces(t *testing.T) {
	b64 := strings.Repeat("MIIEpAIBAAKCAQEA", 4)
	got := blocked("-----BEGIN RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED", "", b64, "PemBody88Tt", "Ag==",
		"-----END RSA PRIVATE KEY-----", "hostname a",
		"crypto certificate c1 import", "-----BEGIN CERTIFICATE-----", b64, "-----END CERTIFICATE-----", ".", "hostname b")
	want := []string{"Proc-Type: 4,ENCRYPTED", b64, "PemBody88Tt", "Ag==", "-----BEGIN CERTIFICATE-----", b64, "-----END CERTIFICATE-----"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("masked %q, want %q", got, want)
	}
}

/*
I1: an opener the device did not take (its answer is an error, a prompt or
any ordinary line) ends the block: the lines after it are not hidden, on the
output side; a word such as "shutdown" is never taken for key material.
*/
func TestStreamOpenerDoesNotHideLaterLines(t *testing.T) {
	for _, opener := range []string{"crypto certificate 1 import bogus", "-----BEGIN junk"} {
		if got := blocked(opener, "% Unrecognized command", "shutdown", "username evil password x privilege 15", "hostname pwned"); len(got) != 0 {
			t.Fatalf("%q hid %q", opener, got)
		}
		if got := blocked(opener, "shutdown", "exit", "reload"); len(got) != 0 {
			t.Fatalf("%q hid words %q", opener, got)
		}
	}
	for _, w := range []string{"shutdown", "exit", "end", "hostname", "ShUtDoWn"} {
		if mask.KeyMaterial(w) {
			t.Fatalf("%q taken for key material", w)
		}
	}
	for _, k := range []string{"Ag==", "PemBody88Tt", strings.Repeat("abcdEFGH", 3)} {
		if !mask.KeyMaterial(k) {
			t.Fatalf("%q not taken for key material", k)
		}
	}
}
