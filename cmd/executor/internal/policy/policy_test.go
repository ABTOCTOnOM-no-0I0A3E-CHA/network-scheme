package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

/* The holder rereads the file when its mtime changes, and a missing or invalid file disables the executor. */
func TestReloadByMtime(t *testing.T) {
	p := filepath.Join(t.TempDir(), "executor.yaml")
	h := New(p)
	if h.Current().Enabled() {
		t.Fatal("enabled before the first read")
	}
	at := time.Now()
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		at = at.Add(time.Second)
		if err := os.Chtimes(p, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write("enabled: true\n")
	if _, cur, changed := h.Reload(false); !changed || !cur.Enabled() {
		t.Fatalf("%+v %v", cur, changed)
	}
	if _, _, changed := h.Reload(false); changed {
		t.Fatal("unchanged file reported as changed")
	}
	write("enabled: true\nsession_minutes: 1\n")
	if _, cur, changed := h.Reload(false); !changed || cur.Enabled() || cur.Err == nil {
		t.Fatalf("invalid: %+v", cur)
	}
	write("enabled: true\n")
	if _, cur, _ := h.Reload(false); !cur.Enabled() {
		t.Fatalf("valid again: %+v", cur)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, cur, changed := h.Reload(false); !changed || cur.Enabled() {
		t.Fatalf("missing: %+v", cur)
	}
	/* Same content again after a missing file: enforced again, and an mtime-only change is no change. */
	write("enabled: true\n")
	h.Reload(false)
	write("enabled: true\n")
	if _, _, changed := h.Reload(false); changed {
		t.Fatal("same content reported as changed")
	}
}
