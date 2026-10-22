package secret_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/secret"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func logged(t *testing.T, a slog.Attr) string {
	t.Helper()
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "msg", a)
	var jbuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&jbuf, nil)).LogAttrs(t.Context(), slog.LevelInfo, "msg", a)
	return buf.String() + jbuf.String()
}

func TestSecretNeverPrints(t *testing.T) {
	s := secret.New("hunter2-very-secret")
	for _, out := range []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q", s, s, s, s, s),
		fmt.Sprint(&s), fmt.Sprintf("%v %#v", &s, &s),
		mustJSON(t, struct{ P secret.Secret }{s}),
		logged(t, slog.Any("p", s)),
	} {
		if strings.Contains(out, "hunter2") {
			t.Fatalf("leak: %s", out)
		}
	}
	if s.Reveal() != "hunter2-very-secret" {
		t.Fatal("reveal")
	}
	if !secret.New("").IsZero() {
		t.Fatal("zero")
	}
	if s.IsZero() {
		t.Fatal("non-zero reported zero")
	}
	if got := s.String(); got != "***" {
		t.Fatalf("String = %q", got)
	}
}

func TestWipeClearsBytes(t *testing.T) {
	s := secret.New("hunter2-very-secret")
	alias := s /* copies share the bytes */
	s.Wipe()
	if strings.Trim(alias.Reveal(), "\x00") != "" || len(alias.Reveal()) != len("hunter2-very-secret") {
		t.Fatalf("after Wipe: %q", alias.Reveal())
	}
	secret.Secret{}.Wipe() /* no-op on the zero value */
}
