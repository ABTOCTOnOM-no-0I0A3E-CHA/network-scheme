package ticket

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	pub, priv   = keyPair(1)
	otherPub, _ = keyPair(2)
	t0          = time.Unix(1_800_000_000, 0)
)

func keyPair(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	k := ed25519.NewKeyFromSeed(s)
	return k.Public().(ed25519.PublicKey), k
}

/* signRaw signs arbitrary payload bytes: a ticket the api's key signed but Sign would never produce. */
func signRaw(payload string) string {
	sig := ed25519.Sign(priv, append([]byte(domain), payload...))
	return b64.EncodeToString([]byte(payload)) + "." + b64.EncodeToString(sig)
}

/* flip changes the character of tok at i to another base64url character. */
func flip(tok string, i int) string {
	c := byte('A')
	if tok[i] == 'A' {
		c = 'B'
	}
	return tok[:i] + string(c) + tok[i+1:]
}

func reason(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	if err == nil {
		return "accepted"
	}
	return "other: " + err.Error()
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	tok, c, err := Issue(priv, 7, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	if c.V != 1 || c.Aud != "executor" || c.UserID != 7 || c.Username != "alice" || c.Expires != c.IssuedAt+60 || c.Nonce == ([16]byte{}) {
		t.Fatalf("claims %+v", c)
	}
	got, err := Verify(pub, tok, t0.Add(59*time.Second))
	if err != nil || got != c {
		t.Fatalf("verify: %+v %v", got, err)
	}
	payload, _ := b64.DecodeString(strings.Split(tok, ".")[0])
	want := `{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"` + b64.EncodeToString(c.Nonce[:]) + `"}`
	if string(payload) != want {
		t.Fatalf("payload %s, want %s", payload, want)
	}
	tok2, c2, _ := Issue(priv, 7, "alice", t0)
	if tok2 == tok || c2.Nonce == c.Nonce {
		t.Fatal("two tickets share a nonce")
	}
}

func TestIssueRefusesBadFields(t *testing.T) {
	for _, tc := range []struct {
		id   int64
		name string
	}{{0, "a"}, {-1, "a"}, {1, ""}, {1, strings.Repeat("я", 65)}, {1, "a\x00b"}, {1, "a\u202eb"}, {1, "\xff"}} {
		if _, _, err := Issue(priv, tc.id, tc.name, t0); err == nil {
			t.Errorf("issued for %d %q", tc.id, tc.name)
		}
	}
	if _, _, err := Issue(priv, 1, strings.Repeat("я", 64), t0); err != nil {
		t.Errorf("64 characters: %v", err)
	}
}

/* Every way to bend a ticket is refused, each with its reason. */
func TestVerifyRefuses(t *testing.T) {
	good := Claims{V: 1, Aud: "executor", UserID: 7, Username: "alice", IssuedAt: t0.Unix(), Expires: t0.Unix() + 60, Nonce: [16]byte{1, 2, 3}}
	sign := func(mut func(*Claims)) string {
		c := good
		mut(&c)
		tok, err := Sign(priv, c)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	tok := sign(func(*Claims) {})
	payload, _ := b64.DecodeString(strings.Split(tok, ".")[0])
	nonce := b64.EncodeToString(good.Nonce[:])
	body := func(s string) string { return strings.ReplaceAll(s, "NONCE", nonce) }
	for name, tc := range map[string]struct {
		tok, want string
		key       ed25519.PublicKey
		at        time.Time
	}{
		"forged (other key)":    {tok: tok, want: "signature", key: otherPub},
		"tampered user_id":      {tok: b64.EncodeToString([]byte(strings.Replace(string(payload), `"user_id":7`, `"user_id":8`, 1))) + "." + strings.Split(tok, ".")[1], want: "signature"},
		"tampered signature":    {tok: flip(tok, len(tok)-10), want: "signature"},
		"expired":               {tok: tok, want: "expired", at: t0.Add(60 * time.Second)},
		"issued in the future":  {tok: tok, want: "future", at: t0.Add(-6 * time.Second)},
		"wrong aud":             {tok: sign(func(c *Claims) { c.Aud = "api" }), want: "audience"},
		"wrong version":         {tok: sign(func(c *Claims) { c.V = 2 }), want: "version"},
		"long lifetime":         {tok: sign(func(c *Claims) { c.Expires += 3600 }), want: "lifetime"},
		"no user":               {tok: sign(func(c *Claims) { c.UserID = 0 }), want: "fields"},
		"bidi in name":          {tok: sign(func(c *Claims) { c.Username = "adm\u202ein" }), want: "fields"},
		"oversize":              {tok: strings.Repeat("A", MaxLen+1), want: "oversize"},
		"no dot":                {tok: strings.ReplaceAll(tok, ".", ""), want: "malformed"},
		"two dots":              {tok: tok + ".AA", want: "malformed"},
		"padded base64":         {tok: strings.Split(tok, ".")[0] + "=." + strings.Split(tok, ".")[1], want: "malformed"},
		"std base64 alphabet":   {tok: strings.NewReplacer("-", "+", "_", "/").Replace(tok), want: "malformed"},
		"duplicate key":         {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":8,"user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "encoding"},
		"unknown key":           {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE","admin":true}`)), want: "encoding"},
		"other key order":       {tok: signRaw(body(`{"aud":"executor","v":1,"user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "encoding"},
		"whitespace":            {tok: signRaw(body(`{"v":1, "aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "encoding"},
		"escaped character":     {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":7,"username":"` + "\x5cu0061" + `lice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "encoding"},
		"number form":           {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":7.0,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "encoding"},
		"missing nonce":         {tok: signRaw(`{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060}`), want: "encoding"},
		"short nonce":           {tok: signRaw(`{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"AAAA"}`), want: "encoding"},
		"non-canonical nonce":   {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"` + nonce[:21] + `B"}`)), want: "encoding"},
		"trailing data":         {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}{}`)), want: "encoding"},
		"null user_id":          {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":null,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "encoding"},
		"canonical raw payload": {tok: signRaw(body(`{"v":1,"aud":"executor","user_id":7,"username":"alice","iat":1800000000,"exp":1800000060,"nonce":"NONCE"}`)), want: "accepted"},
	} {
		key, at := pub, t0
		if tc.key != nil {
			key = tc.key
		}
		if !tc.at.IsZero() {
			at = tc.at
		}
		_, err := Verify(key, tc.tok, at)
		if got := reason(err); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
		if tc.want != "accepted" && !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v is not ErrInvalid", name, err)
		}
	}
}

func TestBadKeysDoNotPanic(t *testing.T) {
	if _, err := Parse(pub[:31], "a.b"); err == nil {
		t.Error("short public key accepted")
	}
	if _, err := Sign(priv[:10], Claims{}); err == nil {
		t.Error("short private key accepted")
	}
}

/*
FuzzTicket: a payload decode accepts encodes back to exactly the same bytes
(no two encodings of one ticket), and a token Parse accepts is exactly the one
Sign produces for its claims (Ed25519 is deterministic).
*/
func FuzzTicket(f *testing.F) {
	tok, _, _ := Issue(priv, 7, "alice", t0)
	payload, _ := b64.DecodeString(strings.Split(tok, ".")[0])
	f.Add(payload, tok)
	f.Add([]byte(`{"v":1,"aud":"executor","user_id":7,"user_id":7,"username":"a","iat":1,"exp":61,"nonce":"AAAAAAAAAAAAAAAAAAAAAA"}`), "x.y")
	f.Add([]byte(`{"v":1,"aud":"executor","user_id":1,"username":"\u00e9","iat":1,"exp":61,"nonce":"AAAAAAAAAAAAAAAAAAAAAA"}`), "")
	f.Fuzz(func(t *testing.T, payload []byte, token string) {
		if c, err := decode(payload); err == nil {
			again, err := encode(c)
			if err != nil || string(again) != string(payload) {
				t.Fatalf("decode accepted a non-canonical payload %q (canonical %q)", payload, again)
			}
		}
		for _, tk := range []string{token, signRaw(string(payload))} {
			c, err := Parse(pub, tk)
			if err != nil {
				continue
			}
			again, err := Sign(priv, c)
			if err != nil || again != tk {
				t.Fatalf("Parse accepted %q, Sign gives %q", tk, again)
			}
		}
	})
}

/* The signature covers exactly "nms/ticket/v1" NUL payload (a known-answer check of the domain label, independent of the constant). */
func TestSignatureDomainLabel(t *testing.T) {
	tok, _, err := Issue(priv, 7, "alice", t0)
	if err != nil {
		t.Fatal(err)
	}
	p, s, _ := strings.Cut(tok, ".")
	payload, _ := b64.DecodeString(p)
	sig, _ := b64.DecodeString(s)
	msg := append([]byte("nms/ticket/v1\x00"), payload...)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("the signature does not cover the domain label and the payload")
	}
	if ed25519.Verify(pub, payload, sig) {
		t.Fatal("the signature covers the bare payload")
	}
}
