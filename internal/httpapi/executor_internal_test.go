package httpapi

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/*
The ticket handler reads the user again itself: a session still taken as
live (the middleware passed it a moment before the user was disabled or
deleted) gets no ticket. The handler is called directly, past the session
middleware that would otherwise refuse first.
*/
func TestExecutorTicketHandlerRereadsUser(t *testing.T) {
	env := testdb.New(t)
	ctx := context.Background()
	s := newServer(Deps{Pool: env.Pool("nms_api"), TicketKey: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		Clock: time.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	var id int64
	name := "ticket-reread-" + t.Name()
	if err := env.Pool("postgres").QueryRow(ctx, `INSERT INTO core."user" (username, password_phc, disabled) VALUES ($1, 'x', true) RETURNING id`,
		name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []int64{id, id + 1000000} { /* disabled, deleted */
		r := httptest.NewRequest(http.MethodPost, "/api/executor/ticket", nil)
		rc := context.WithValue(r.Context(), keyClientIP, netip.MustParseAddr("192.0.2.1"))
		rc = context.WithValue(rc, keySession, sessionCtx{sess: auth.Session{UserID: uid, Username: name}, valid: true})
		w := httptest.NewRecorder()
		s.executorTicket(w, r.WithContext(rc))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("user %d: %d %s", uid, w.Code, w.Body.String())
		}
	}
}
