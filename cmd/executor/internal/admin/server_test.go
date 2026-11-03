package admin

import (
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/execadmin"
)

/* The request line is read strictly: one JSON object of known fields, bounded, ending in a newline. */
func TestReadRequest(t *testing.T) {
	if req, err := readRequest(strings.NewReader(`{"v":1,"cmd":"registry-verify"}` + "\n")); err != nil || req.Cmd != "registry-verify" {
		t.Fatalf("%+v %v", req, err)
	}
	for name, in := range map[string]string{
		"no newline":    `{"v":1,"cmd":"registry-verify"}`,
		"unknown field": `{"v":1,"cmd":"registry-verify","as_root":true}` + "\n",
		"two values":    `{"v":1} {"v":1}` + "\n",
		"not json":      "grant alice write-admin\n",
		"too large":     `{"v":1,"reason":"` + strings.Repeat("x", execadmin.MaxRequest) + `"}` + "\n",
		"empty":         "",
	} {
		if req, err := readRequest(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted %+v", name, req)
		}
	}
}

/* Review M1: a request well over the old 4 KiB buffer but within MaxRequest is read whole. */
func TestReadRequestUpToMaxRequest(t *testing.T) {
	note := strings.Repeat("я", 1000)
	in := `{"v":1,"cmd":"model-verify","driver":"esr","model":"x","firmware":"y","note":"` + note + `","reason":"` + strings.Repeat("r", 20000) + `"}` + "\n"
	if req, err := readRequest(strings.NewReader(in)); err != nil || req.Note != note {
		t.Fatalf("%v", err)
	}
}
