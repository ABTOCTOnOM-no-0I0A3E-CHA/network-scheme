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
	a := "! Last configuration change at 10:21:33 UTC Mon Oct 20 2026\r\n! NVRAM config last updated at 10:22:01\r\nBuilding configuration...\r\nCurrent configuration : 4821 bytes\r\nsystem uptime is 3 days\r\nMon Oct 20 10:21:33 2026\r\n2026-10-20 10:21:33 saved\r\nhostname sw1  \r\nclock timezone +3\r\ninterface gi1\r\n exit\r\n! Last configuration change at 11:00:00\r\nntp clock-period 17179869\r\n\r\n\r\n"
	b := strings.NewReplacer("10:21:33", "11:59:59", "10:22:01", "12:00:00", "4821", "4825", "3 days", "9 days", "Oct 20", "Oct 21", "2026-10-20", "2026-10-21", "17179869", "17179999").Replace(a)
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

/* Real configuration lines that look like volatile ones must survive. */
func TestNormalizeKeepsRealLines(t *testing.T) {
	keep := []string{
		"uptime-monitor enable", " uptime 5", "Uptime is shown on login", "  00:11:22:33:44:55", " 12:30:00 periodic",
		"  mon jan 1 08:00", "2026-01-01 10:00 change-window", "! generated policy", "Building configuration...",
		"Current configuration : 12 bytes", "2026-10-20 10:21:33 note", "# uptime: 5", "clock timezone +3", "! Last configuration change",
	}
	/* after the first command none of the header patterns apply, and indented lines never do */
	cfg := "hostname sw1\n" + strings.Join(keep, "\n") + "\n"
	got := NormalizeText(cfg)
	for _, k := range keep {
		if !strings.Contains(got, k+"\n") {
			t.Errorf("line %q was dropped", k)
		}
	}
	/* in the header block (before any command) only the exact forms go */
	hdr := "! generated policy\nuptime-monitor enable\n"
	if got := NormalizeText(hdr); got != hdr {
		t.Errorf("header kept lines: %q", got)
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
	if c, err := ResolveShow(defs, "i", []string{"gi1/0/1"}, false); err != nil || c.Name != "show interfaces status" || len(c.Args) != 1 {
		t.Fatalf("%v %v", c, err)
	}
	for _, bad := range []struct {
		key  string
		args []string
	}{{"v", []string{"x"}}, {"i", nil}, {"i", []string{"gi1; reload"}}, {"l", []string{"0"}}, {"l", []string{"4095"}}, {"l", []string{"a"}}, {"nope", nil}} {
		if _, err := ResolveShow(defs, bad.key, bad.args, false); !errors.Is(err, ErrUnknownShow) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if len(Allowlist(defs, false)) != 3 || len(Allowlist(defs, true)) != 4 || len(Specs(defs)) != 3 {
		t.Fatal("allowlist/specs size")
	}
}

func TestResolveShowLongInterface(t *testing.T) {
	defs := []ShowDef{{Spec: showspec.Spec{Key: "i", Args: []showspec.ArgKind{showspec.InterfaceName}}, Name: "show interfaces status"}}
	c, err := ResolveShow(defs, "i", []string{"gigabitethernet 1/0/1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := (ssh.Dialect{Allowlist: Allowlist(defs, true)}); len(got.Allowlist) != 2 || len(c.Args) != 1 {
		t.Fatalf("%v %v", got.Allowlist, c.Args)
	}
	for _, bad := range []string{"gigabitethernet 1/0/1; reload", "gi 1 2", "a b", "gigabitethernet  1", "gigabitethernet 1/0/1 x"} {
		if _, err := ResolveShow(defs, "i", []string{bad}, true); !errors.Is(err, ErrUnknownShow) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := ResolveShow(defs, "i", []string{"gigabitethernet 1/0/1"}, false); !errors.Is(err, ErrUnknownShow) {
		t.Errorf("long form without longIf: %v", err)
	}
}

/* A definition that names a configuration command never resolves. */
func TestResolveShowNeverConfig(t *testing.T) {
	defs := []ShowDef{{Spec: showspec.Spec{Key: "cfg"}, Name: "show running-config"}, {Spec: showspec.Spec{Key: "s"}, Name: "show startup-config"}}
	for _, k := range []string{"cfg", "s", "show running-config", "running_config"} {
		if _, err := ResolveShow(defs, k, nil, false); !errors.Is(err, ErrUnknownShow) {
			t.Errorf("%q: %v", k, err)
		}
	}
}
