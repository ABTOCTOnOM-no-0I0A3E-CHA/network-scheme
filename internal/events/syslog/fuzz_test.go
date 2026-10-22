package syslog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf8"
)

func FuzzParse(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join(fixtureDir, "*.txt"))
	for _, p := range files {
		if b, err := os.ReadFile(p); err == nil {
			f.Add(b)
		}
	}
	for _, s := range []string{"<13>", "<>", "<13>1 - - - - - -", "<13>1 - h a 1 2 [a b=\"\\\"]", "<13>Feb 29 00:00:00 h t[1]: x"} {
		f.Add([]byte(s))
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b, now)
		if err != nil {
			if len(b) <= MaxMessage && err == ErrTooLarge {
				t.Fatal("ErrTooLarge for small input")
			}
			return
		}
		if len(b) > MaxMessage {
			t.Fatal("oversized input accepted")
		}
		if m.Facility > 23 || m.Severity > 7 {
			t.Fatalf("bad PRI: %+v", m)
		}
		if len(m.Host) > MaxHost || len(m.App) > MaxApp || len(m.Text) > MaxMessage {
			t.Fatalf("limits: %d %d %d", len(m.Host), len(m.App), len(m.Text))
		}
		if m.TS.IsZero() || m.TS.After(now.Add(maxFuture)) || m.TS.Before(now.Add(-24*time.Hour)) {
			t.Fatalf("bad TS %v", m.TS)
		}
		for _, s := range []string{m.Host, m.App, m.Text} {
			if !utf8.ValidString(s) {
				t.Fatalf("invalid UTF-8 %q", s)
			}
			for _, r := range s {
				if badRune(r) {
					t.Fatalf("control char in %q", s)
				}
			}
		}
	})
}
