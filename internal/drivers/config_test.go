package drivers

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/ssh"
)

type runner struct {
	out string
	err error
	got []ssh.ShowCommand
}

func (r *runner) Run(_ context.Context, c ssh.ShowCommand) (string, error) {
	r.got = append(r.got, c)
	return r.out, r.err
}

var testDialect = ssh.Dialect{ExecPrompt: regexp.MustCompile(`^[\w.-]+# ?$`)}

func TestFetchRunning(t *testing.T) {
	cmd := ssh.ShowCommand{Name: "show running-config"}
	cases := map[string]struct {
		out  string
		err  error
		want error
	}{
		"ok":            {out: "hostname sw1\ninterface gi1\n exit\n"},
		"nul":           {out: "hostname sw1\x00\x01\n", want: ErrConfigGarbage},
		"binary":        {out: strings.Repeat("\xff\xfe\x80", 100), want: ErrConfigGarbage},
		"prompt":        {out: "hostname sw1\nsw1#\ninterface gi1\n", want: ErrConfigGarbage},
		"config prompt": {out: "hostname sw1\nsw1(config)#\n", want: ErrConfigGarbage},
		"rejected":      {out: "% Unrecognized command\n", want: ErrConfigRejected},
		"empty":         {out: "  \n", want: ErrConfigRejected},
		"too large":     {out: strings.Repeat("a", MaxConfigSize+1), want: ErrConfigTooLarge},
		"runner large":  {err: ssh.ErrOutputTooLarge, want: ErrConfigTooLarge},
		"timeout":       {err: ssh.ErrTimeout, want: ssh.ErrTimeout},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := &runner{out: c.out, err: c.err}
			got, err := FetchRunning(context.Background(), r, testDialect, cmd)
			if !errors.Is(err, c.want) || (c.want != nil) != (got == "" && err != nil) {
				t.Fatalf("got %q, %v; want %v", got, err, c.want)
			}
			if len(r.got) != 1 || r.got[0].Name != cmd.Name {
				t.Fatalf("ran %v", r.got)
			}
		})
	}
}

func TestFetchSanitizes(t *testing.T) {
	r := &runner{out: "hostname sw1\x07\x1b[0m\ndescr \xff end\t\r\n"}
	got, err := FetchRunning(context.Background(), r, testDialect, ssh.ShowCommand{Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, "\x07\x1b") || !strings.Contains(got, "descr \uFFFD end\t\r\n") {
		t.Fatalf("sanitised: %q", got)
	}
}

func TestNormalizeText(t *testing.T) {
	a := "! Last configuration change at 10:21:33 UTC Mon Oct 20 2026\r\n! NVRAM config last updated at 10:22:01\r\nBuilding configuration...\r\nCurrent configuration : 4821 bytes\r\nhostname sw1  \r\nclock timezone +3\r\nsystem uptime is 3 days\r\nMon Oct 20 10:21:33 2026\r\n2026-10-20 10:21:33 saved\r\ninterface gi1\r\n exit\r\n\r\n\r\n"
	b := strings.NewReplacer("10:21:33", "11:59:59", "10:22:01", "12:00:00", "4821", "4825", "3 days", "9 days", "Oct 20", "Oct 21", "2026-10-20", "2026-10-21").Replace(a)
	na, nb := NormalizeText(a), NormalizeText(b)
	if na != nb {
		t.Fatalf("differ:\n%q\n%q", na, nb)
	}
	if want := "hostname sw1\nclock timezone +3\ninterface gi1\n exit\n"; na != want {
		t.Fatalf("got %q want %q", na, want)
	}
	if NormalizeText(na) != na {
		t.Fatal("not idempotent")
	}
	if NormalizeText("hostname other\n") == na {
		t.Fatal("real change must differ")
	}
}

func TestSplitSections(t *testing.T) {
	cfg := "! header\nhostname sw1\nvlan database\nvlan 10\nexit\ninterface gi1\n description x\nexit\nip route 0.0.0.0 0.0.0.0 1.1.1.1\nip routing\nsnmp-server community *** ro\nlogging host 1.1.1.1\nusername a password ***\nline console\n exec-timeout 5\nexit\n"
	got := map[string][]string{}
	n := 0
	for _, s := range SplitSections(cfg) {
		got[s.Name] = s.Lines
		n += len(s.Lines)
	}
	want := map[string]int{SectionGeneral: 2, SectionVLAN: 3, SectionInterfaces: 3, SectionRouting: 2, SectionSNMP: 1, SectionSyslog: 1, SectionAAA: 1, SectionOther: 3}
	for k, v := range want {
		if len(got[k]) != v {
			t.Errorf("%s: %q, want %d lines", k, got[k], v)
		}
	}
	if n != 16 {
		t.Errorf("%d lines in sections, want 16", n)
	}
}

func TestResolveShow(t *testing.T) {
	defs := []ShowDef{
		{Spec: showspec.Spec{Key: "v"}, Name: "show version"},
		{Spec: showspec.Spec{Key: "i", Args: []showspec.ArgKind{showspec.InterfaceName}}, Name: "show interfaces status"},
		{Spec: showspec.Spec{Key: "l", Args: []showspec.ArgKind{showspec.VLANID}}, Name: "show vlan tag"},
	}
	if c, err := ResolveShow(defs, "i", []string{"gi1/0/1"}); err != nil || c.Name != "show interfaces status" || len(c.Args) != 1 {
		t.Fatalf("%v %v", c, err)
	}
	for _, bad := range []struct {
		key  string
		args []string
	}{{"v", []string{"x"}}, {"i", nil}, {"i", []string{"gi1; reload"}}, {"l", []string{"0"}}, {"l", []string{"4095"}}, {"l", []string{"a"}}, {"nope", nil}} {
		if _, err := ResolveShow(defs, bad.key, bad.args); !errors.Is(err, ErrUnknownShow) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if len(Allowlist(defs)) != 3 || len(Specs(defs)) != 3 {
		t.Fatal("allowlist/specs size")
	}
}
