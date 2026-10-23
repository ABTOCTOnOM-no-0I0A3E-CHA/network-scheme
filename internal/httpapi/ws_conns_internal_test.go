package httpapi

import "testing"

func TestWSConnsCapPerUserAcrossSessions(t *testing.T) {
	var c wsConns
	var rel []func()
	for i := range wsMaxPerUser {
		/* Four sockets per session, so the user cap is reached over several sessions. */
		r, ok := c.acquire(string(rune('a'+i/wsMaxPerSession)), 7)
		if !ok {
			t.Fatalf("socket %d refused below the caps", i)
		}
		rel = append(rel, r)
	}
	if _, ok := c.acquire("fresh-session", 7); ok {
		t.Fatal("socket over the per-user cap accepted")
	}
	if _, ok := c.acquire("other-user-session", 8); !ok {
		t.Fatal("another user must be unaffected")
	}
	rel[0]()
	if _, ok := c.acquire("fresh-session", 7); !ok {
		t.Fatal("a released slot was not reusable")
	}
}
