package identify

import (
	"errors"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/strategy"
	"github.com/beekamai/network-scheme/test/sim/devemu"
)

func fixture(t *testing.T, line, cmd string) string {
	t.Helper()
	fx, err := devemu.LoadLine(line)
	if err != nil {
		t.Fatal(err)
	}
	return fx.Show[cmd]
}

/* The fixtures of every line parse to their line, model and firmware. */
func TestParseFixtures(t *testing.T) {
	for line, want := range map[string]Identity{
		"esr":   {strategy.ESR, "ESR-1000", "1.23.3"},
		"mes6":  {strategy.MES6, "MES2324", "6.6.2"},
		"mes10": {strategy.MES10, "", "10.4.5.2"}, /* the mes10 fixture has no show system */
	} {
		got, err := Parse(fixture(t, line, "show version"), fixture(t, line, "show system"))
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", line, got, err, want)
		}
	}
	got, err := Parse(fixture(t, "mes10", "show version"), "System Description:   MES2424 24-port")
	if err != nil || got.Model != "MES2424" {
		t.Errorf("mes10 with a model: %+v %v", got, err)
	}
}

func TestParseRefuses(t *testing.T) {
	esrV, mes6V, mes10V := fixture(t, "esr", "show version"), fixture(t, "mes6", "show version"), fixture(t, "mes10", "show version")
	for name, c := range map[string][2]string{
		"empty":                {"", ""},
		"error":                {"% Unrecognized command", ""},
		"two lines":            {esrV + "\n" + mes6V, ""},
		"two mes6 versions":    {mes6V + "\n  Version: 6.5.1", ""},
		"MES 10.x model, 6.x":  {mes6V, "System Description:   MES2424 24-port"},
		"MES 6.x model, 10.x":  {mes10V, "System Description:   MES2324 28-port"},
		"ESR model, MES":       {mes6V, "System type:  Eltex ESR-1000 Service Router"},
		"MES model, ESR":       {esrV, "System Description: MES2324"},
		"both families":        {esrV, "System type: ESR-10 MES2324"},
		"two system lines":     {esrV, "System type: Eltex ESR-1000\nSystem Description: x"},
		"version 7.x":          {"Active-image: x\n  Version: 7.1.0", ""},
		"oversized":            {strings.Repeat("a", maxOutput+1), ""},
		"escape in the number": {"SW version:\n  1.\x1b[2J23", ""},
	} {
		if _, err := Parse(c[0], c[1]); !errors.Is(err, ErrUnknown) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func prof(id int64, line strategy.Line, model, fw string, st map[string]string) Profile {
	return Profile{ID: id, WriteDriver: line, ModelRe: "^(?:" + model + ")$", FirmwareRe: "^(?:" + fw + ")$", Strategies: st}
}

func TestDecide(t *testing.T) {
	esr := Identity{strategy.ESR, "ESR-1000", "1.23.3"}
	/* a line other than the registered one: no session at all */
	if _, err := Decide(strategy.MES6, nil, Identity{strategy.MES10, "MES2424", "10.4.5.2"}); !errors.Is(err, ErrLineMismatch) {
		t.Errorf("MES 10.x registered as mes6: %v", err)
	}
	if _, err := Decide("ios", nil, esr); !errors.Is(err, ErrLineMismatch) {
		t.Errorf("unknown registered line: %v", err)
	}
	cases := map[string]struct {
		profiles []Profile
		write    bool
		profile  int64
	}{
		"no profile":            {nil, false, 0},
		"one profile":           {[]Profile{prof(3, strategy.ESR, "ESR-1000", `1\.23\..*`, map[string]string{"errors": "strict"})}, true, 3},
		"other model":           {[]Profile{prof(3, strategy.ESR, "ESR-100", ".*", nil)}, false, 0},
		"model prefix only":     {[]Profile{prof(3, strategy.ESR, "ESR-10", ".*", nil)}, false, 0},
		"other firmware":        {[]Profile{prof(3, strategy.ESR, ".*", `1\.24\..*`, nil)}, false, 0},
		"other line's profile":  {[]Profile{prof(3, strategy.MES6, ".*", ".*", nil)}, false, 0},
		"two matching":          {[]Profile{prof(3, strategy.ESR, ".*", ".*", nil), prof(4, strategy.ESR, "ESR-1000", ".*", nil)}, false, 0},
		"unknown strategy key":  {[]Profile{prof(3, strategy.ESR, ".*", ".*", map[string]string{"shell": "x"})}, false, 0},
		"unknown variant":       {[]Profile{prof(3, strategy.ESR, ".*", ".*", map[string]string{"auth": "none"})}, false, 0},
		"pattern not anchored":  {[]Profile{{ID: 3, WriteDriver: strategy.ESR, ModelRe: ".*", FirmwareRe: "^(?:.*)$"}}, false, 0},
		"bad pattern":           {[]Profile{{ID: 3, WriteDriver: strategy.ESR, ModelRe: "^(?:[)$", FirmwareRe: "^(?:.*)$"}}, false, 0},
		"unreadable strategies": {[]Profile{{ID: 3, WriteDriver: strategy.ESR, ModelRe: "^(?:.*)$", FirmwareRe: "^(?:.*)$", Err: errors.New("x")}}, false, 0},
		"bad mes6 profile":      {[]Profile{prof(3, strategy.ESR, ".*", ".*", nil), {ID: 4, WriteDriver: strategy.MES6, ModelRe: "x"}}, true, 3},
	}
	for name, c := range cases {
		d, err := Decide(strategy.ESR, c.profiles, esr)
		if err != nil || d.Write != c.write || d.Profile != c.profile {
			t.Errorf("%s: %+v %v", name, d, err)
			continue
		}
		if !d.Write && d.Reason == "" {
			t.Errorf("%s: refused without a reason", name)
		}
		if d.Set.Prompt == nil {
			t.Errorf("%s: no usable strategies for reading", name)
		}
	}
	d, _ := Decide(strategy.ESR, cases["one profile"].profiles, esr)
	if d.Set.Errors != "strict" || d.Set.KEX != "no-curve25519" {
		t.Errorf("the profile's strategies do not override the defaults: %+v", d.Set)
	}
	/* stored patterns are matched as stored: "^(?:^MES2424)$" (as admin_test shows) still matches the whole model only */
	mes := Identity{strategy.MES6, "MES2324P", "6.6.2"}
	d, _ = Decide(strategy.MES6, []Profile{{ID: 1, WriteDriver: strategy.MES6, ModelRe: "^(?:^MES2324)$", FirmwareRe: "^(?:6\\..*)$"}}, mes)
	if d.Write {
		t.Error("MES2324 profile allows MES2324P")
	}
}
