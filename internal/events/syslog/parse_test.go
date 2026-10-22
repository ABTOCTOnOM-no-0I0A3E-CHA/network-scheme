package syslog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var testNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const fixtureDir = "../../../test/fixtures/syslog"

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustParse(t *testing.T, in string, now time.Time) Message {
	t.Helper()
	m, err := Parse([]byte(in), now)
	if err != nil {
		t.Fatalf("Parse(%q): %v", in, err)
	}
	return m
}

func TestRFC3164(t *testing.T) {
	m := mustParse(t, string(fixture(t, "rfc3164_basic.txt")), testNow)
	want := Message{
		TS: time.Date(2026, 10, 22, 11, 59, 1, 0, time.UTC), Facility: 4, Severity: 2,
		Host: "mymachine", App: "su", Text: "'su root' failed on /dev/pts/8",
	}
	if m != want {
		t.Fatalf("got %+v, want %+v", m, want)
	}
	m = mustParse(t, string(fixture(t, "rfc3164_padded_day.txt")), testNow)
	if m.TS != time.Date(2026, 10, 2, 8, 15, 0, 0, time.UTC) || m.Host != "gw1" || m.App != "cron" || m.Text != "job done" {
		t.Fatalf("padded day: %+v", m)
	}
}

func TestRFC3164Year(t *testing.T) {
	m := mustParse(t, string(fixture(t, "rfc3164_with_year.txt")), testNow)
	if m.TS != time.Date(2026, 10, 22, 11, 30, 0, 0, time.UTC) || m.Host != "gw1" || m.App != "kernel" {
		t.Fatalf("with year: %+v", m)
	}
	m = mustParse(t, "<13>Oct 22 2025 11:30:00 gw1 x: y", testNow)
	if m.TS.Year() != 2025 {
		t.Fatalf("explicit year ignored: %v", m.TS)
	}
}

func TestRFC3164NewYear(t *testing.T) {
	jan1 := time.Date(2027, 1, 1, 0, 0, 30, 0, time.UTC)
	m := mustParse(t, string(fixture(t, "rfc3164_newyear.txt")), jan1)
	if want := time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC); m.TS != want {
		t.Fatalf("Dec message just after new year: %v, want %v", m.TS, want)
	}
	/* device clock a few minutes ahead across the boundary */
	dec31 := time.Date(2026, 12, 31, 23, 58, 0, 0, time.UTC)
	m = mustParse(t, "<13>Jan  1 00:00:10 gw1 x: y", dec31)
	if want := time.Date(2027, 1, 1, 0, 0, 10, 0, time.UTC); m.TS != want {
		t.Fatalf("Jan message just before new year: %v, want %v", m.TS, want)
	}
}

func TestFutureTimestampUsesNow(t *testing.T) {
	m := mustParse(t, "<13>1 2026-10-22T13:30:00Z h a - - - x", testNow)
	if m.TS != testNow {
		t.Fatalf("future >1h: %v", m.TS)
	}
	m = mustParse(t, "<13>1 2026-10-22T12:30:00Z h a - - - x", testNow)
	if want := time.Date(2026, 10, 22, 12, 30, 0, 0, time.UTC); m.TS != want {
		t.Fatalf("future <1h must be kept: %v", m.TS)
	}
	m = mustParse(t, "<13>Oct 22 15:00:00 h a: x", testNow)
	if m.TS != testNow {
		t.Fatalf("3164 future >1h: %v", m.TS)
	}
}

func TestRFC3164NoTimestamp(t *testing.T) {
	m := mustParse(t, "<13>hello: world", testNow)
	if m.TS != testNow || m.Host != "" || m.App != "" || m.Text != "hello: world" {
		t.Fatalf("%+v", m)
	}
}

func TestRFC3164ISO(t *testing.T) {
	m := mustParse(t, "<14>2026-10-22T18:59:00+07:00 esr-1 ESR: up", testNow)
	if m.TS != time.Date(2026, 10, 22, 11, 59, 0, 0, time.UTC) || m.Host != "esr-1" || m.App != "ESR" || m.Text != "up" {
		t.Fatalf("%+v", m)
	}
}

func TestRFC5424(t *testing.T) {
	m := mustParse(t, string(fixture(t, "rfc5424_sd.txt")), testNow)
	want := Message{
		TS: time.Date(2026, 10, 22, 11, 59, 0, 3000000, time.UTC), Facility: 20, Severity: 5,
		Host: "core1.example.net", App: "evntslog", Text: "An application event log entry",
	}
	if m != want {
		t.Fatalf("got %+v, want %+v", m, want)
	}
	m = mustParse(t, string(fixture(t, "rfc5424_nil.txt")), testNow)
	if m.Host != "" || m.App != "" || m.Text != "nil fields only" || m.TS != time.Date(2026, 10, 22, 4, 59, 0, 0, time.UTC) {
		t.Fatalf("nil: %+v", m)
	}
	m = mustParse(t, "<13>1 - h a 1 2 - ", testNow)
	if m.TS != testNow || m.Text != "" {
		t.Fatalf("empty msg: %+v", m)
	}
	m = mustParse(t, `<13>1 - h a 1 2 [x@1 k="v\"]"] text`, testNow)
	if m.Text != "text" {
		t.Fatalf("escapes in SD: %+v", m)
	}
}

func TestRFC5424Malformed(t *testing.T) {
	for _, in := range []string{
		"<13>1 - h a 1 2",
		"<13>1 2026-99-99T00:00:00Z h a 1 2 - x",
		"<13>1 - h a 1 2 [unterminated x",
		`<13>1 - h a 1 2 [x k="v] text`,
		"<13>1 - h a 1 2 -x",
		"<13>1 - h\x01 a 1 2 - x",
		"<13>1 - " + strings.Repeat("h", 256) + " a 1 2 - x",
		"<13>1 - h " + strings.Repeat("a", 49) + " 1 2 - x",
	} {
		if _, err := Parse([]byte(in), testNow); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: err = %v, want ErrMalformed", in, err)
		}
	}
}

func TestEltex(t *testing.T) {
	cases := []struct {
		file                string
		sev                 uint8
		host, app, textPref string
	}{
		{"eltex_mes_link.txt", 6, "mes-sw1", "LINK", "%LINK-I-Up: gi1/0/3"},
		{"eltex_mes_down.txt", 4, "mes-sw1", "LINK", "%LINK-W-Down:"},
		{"eltex_esr_cli.txt", 6, "esr-1", "CLI", "%CLI-I-CMDEXEC:"},
		{"eltex_esr_tag.txt", 6, "esr-1", "ESR_SYSTEM", "process started"},
		{"eltex_no_header.txt", 6, "", "STP", "%STP-I-PORTSTATUS:"},
	}
	for _, c := range cases {
		m := mustParse(t, string(fixture(t, c.file)), testNow)
		if m.Severity != c.sev || m.Host != c.host || m.App != c.app || !strings.HasPrefix(m.Text, c.textPref) {
			t.Errorf("%s: %+v", c.file, m)
		}
	}
	/* the mnemonic severity wins over PRI; facility is kept */
	m := mustParse(t, string(fixture(t, "eltex_mes_link.txt")), testNow)
	if m.Facility != 23 {
		t.Errorf("facility = %d", m.Facility)
	}
	/* not a mnemonic: severity stays from PRI, text intact */
	m = mustParse(t, "<189>Oct 22 11:59:12 sw1 %LINK-X-Up: z", testNow)
	if m.Severity != 5 || m.Text != "%LINK-X-Up: z" {
		t.Errorf("unknown letter: %+v", m)
	}
	m = mustParse(t, "<189>Oct 22 11:59:12 sw1 %foo bar", testNow)
	if m.Severity != 5 || m.App != "" {
		t.Errorf("not a mnemonic: %+v", m)
	}
}

func TestTooLarge(t *testing.T) {
	big := "<13>" + strings.Repeat("a", MaxMessage)
	if _, err := Parse([]byte(big), testNow); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	ok := "<13>" + strings.Repeat("a", MaxMessage-4)
	m, err := Parse([]byte(ok), testNow)
	if err != nil || len(m.Text) != MaxMessage-4 {
		t.Fatalf("exact limit: %v", err)
	}
	/* invalid bytes expand to 3 bytes each; output must stay within the cap */
	m, err = Parse([]byte("<13>"+strings.Repeat("\xff", MaxMessage-4)), testNow)
	if err != nil || len(m.Text) > MaxMessage || !utf8.ValidString(m.Text) {
		t.Fatalf("expansion: %v len=%d", err, len(m.Text))
	}
}

func TestMalformedPRI(t *testing.T) {
	for _, in := range []string{
		"", "<", "<>", "<>x", "<13", "13>x", "<abc>x", "<192>x", "<1234>x", "<013>x", "<-1>x", "hello", " <13>x",
	} {
		if _, err := Parse([]byte(in), testNow); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: err = %v, want ErrMalformed", in, err)
		}
	}
	for _, in := range []string{"<0>", "<191>x", "<13>"} {
		if _, err := Parse([]byte(in), testNow); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	m := mustParse(t, "<191>x", testNow)
	if m.Facility != 23 || m.Severity != 7 {
		t.Errorf("%+v", m)
	}
}

func TestSanitize(t *testing.T) {
	m := mustParse(t, "<13>Oct 22 11:59:00 h a: x\x00y\x1bz\x7f\tq\xff\xfe\nw", testNow)
	if want := "x�y�z�\tq���w"; m.Text != want {
		t.Fatalf("text = %q, want %q", m.Text, want)
	}
	m = mustParse(t, "<13>Oct 22 11:59:00 h a: буквы", testNow)
	if m.Text != "буквы" {
		t.Fatalf("valid UTF-8 must pass: %q", m.Text)
	}
	m = mustParse(t, "<13>1 - h a 1 2 - x\r\n\r\n", testNow)
	if m.Text != "x" {
		t.Fatalf("trailing newlines: %q", m.Text)
	}
}

func TestFixturesParse(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(fixtureDir, "*.txt"))
	if len(files) < 10 {
		t.Fatalf("fixtures missing: %d", len(files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if _, err := Parse(b, testNow); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
