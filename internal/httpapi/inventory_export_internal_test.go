package httpapi

import (
	"strings"
	"testing"
	"time"
)

func TestTextCellNeutralizesFormulas(t *testing.T) {
	nbsp := string(rune(0xA0))
	for in, want := range map[string]string{
		"=cmd|' /C calc'!A0": "'=cmd|' /C calc'!A0",
		"+1":                 "'+1",
		"-1":                 "'-1",
		"@SUM(A1)":           "'@SUM(A1)",
		"\tx":                "'\tx",
		"\rx":                "'\rx",
		"  =1":               "'  =1",
		nbsp + "=1":          "'" + nbsp + "=1",
		" " + nbsp + " @x":   "'" + " " + nbsp + " @x",
		"Gi1/0/1":            "Gi1/0/1",
		"a=b":                "a=b",
		"":                   "",
		"   ":                "   ",
	} {
		if got := textCell(in); got != want {
			t.Errorf("textCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteCSVRowQuotes(t *testing.T) {
	var sb strings.Builder
	if err := writeCSVRow(&sb, []string{`say "hi"`, "a,b", "line\nbreak", ""}); err != nil {
		t.Fatal(err)
	}
	if want := "\"say \"\"hi\"\"\",\"a,b\",\"line\nbreak\",\"\"\r\n"; sb.String() != want {
		t.Fatalf("got %q, want %q", sb.String(), want)
	}
}

func TestRowCells(t *testing.T) {
	type row struct {
		Name   string    `json:"name"`
		N      int       `json:"n"`
		Up     bool      `json:"up"`
		Addr   *string   `json:"addr"`
		SeenAt time.Time `json:"seen_at"`
	}
	keys, cells, err := rowCells(row{Name: "=HYPERLINK(1)", N: -5, Up: true, SeenAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "name,n,up,addr,seen_at" {
		t.Errorf("keys %v", keys)
	}
	/* text is neutralized, a number is not; null is empty */
	if want := []string{"'=HYPERLINK(1)", "-5", "true", "", "2026-10-01T00:00:00Z"}; strings.Join(cells, "|") != strings.Join(want, "|") {
		t.Errorf("cells %q, want %q", cells, want)
	}
}

/* A row whose fields differ from the header (an omitted field) fails instead of shifting cells into other columns. */
func TestHeaderCellsRefusesShiftedRows(t *testing.T) {
	type row struct {
		A string  `json:"a"`
		B *string `json:"b,omitempty"`
		C string  `json:"c"`
	}
	b := "x"
	header, _, err := rowCells(row{B: &b})
	if err != nil {
		t.Fatal(err)
	}
	if cells, err := headerCells(header, row{A: "1", B: &b, C: "3"}); err != nil || strings.Join(cells, "|") != "1|x|3" {
		t.Fatalf("matching row: %q, %v", cells, err)
	}
	if _, err := headerCells(header, row{A: "1", C: "3"}); err == nil {
		t.Fatal("a row without b was accepted")
	}
}
