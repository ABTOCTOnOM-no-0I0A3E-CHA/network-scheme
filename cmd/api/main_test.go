package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDataKey(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 32)
	dir := t.TempDir()
	cases := map[string][]byte{
		"raw":       want,
		"raw-nl":    append(bytes.Clone(want), '\n'), /* 33 bytes: neither raw nor base64 */
		"b64":       []byte(base64.StdEncoding.EncodeToString(want) + "\n"),
		"b64url":    []byte(base64.RawURLEncoding.EncodeToString(want)),
		"short-b64": []byte(base64.StdEncoding.EncodeToString(want[:16])),
	}
	cases["raw-nl"] = append(append([]byte{}, want...), '\n')
	for name, content := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		key, err := loadDataKey(p)
		ok := name == "raw" || name == "b64" || name == "b64url"
		if ok != (err == nil) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if ok && !bytes.Equal(key[:], want) {
			t.Fatalf("%s: wrong key", name)
		}
	}
}
