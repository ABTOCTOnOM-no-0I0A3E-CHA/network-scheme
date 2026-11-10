package changeset

import (
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/drvtest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/esr"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes10"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
)

/* the drivers' C4 fixtures: the line's driver, its configure command and its management interface (VLAN 99 too) */
var c4 = map[string]struct {
	d             drivers.WriteDriver
	cfg           string
	mgmtIf, other string
}{
	"mes6":  {mes6.New(), "configure", "gi1/0/24", "gi1/0/23"},
	"mes10": {mes10.New(), "configure terminal", "gi0/24", "gi0/23"},
	"esr":   {esr.New(), "configure", "gi1/0/24", "gi1/0/23"},
}

func plan(ls ...string) []Rendered {
	out := make([]Rendered, len(ls))
	for i, l := range ls {
		out[i] = Rendered{Step: i + 1, Line: l}
	}
	return out
}

/*
D2 against the C4 table of Phase 4: no dangerous command of any line passes
a dry-run, typed after the lines that reach its mode, and the refusal names
its line in the device's plan; a line of the management interface's context
is refused too, and a safe plan passes whole.
*/
func TestWalkRefusesEveryDangerousLine(t *testing.T) {
	for name, f := range c4 {
		a, ok1 := f.d.Targets("interface", f.mgmtIf)
		b, ok2 := f.d.Targets("vlan", "99")
		if !ok1 || !ok2 {
			t.Fatal("management targets")
		}
		ctx := core.Context{Mgmt: append(a, b...)}
		for _, p := range drvtest.Dangerous[name] {
			ls := append(append([]string{}, p.Mode...), p.Plain())
			_, _, ref := walk(f.d, plan(ls...), ctx, "")
			if ref == nil || ref.N != len(ls) || ref.Code != "not_safe" {
				t.Errorf("%s: %q after %v: %+v", name, p.Plain(), p.Mode, ref)
			}
		}
		/* the management interface itself: entering it is navigation, anything in it is not */
		_, _, ref := walk(f.d, plan(f.cfg, "interface "+f.mgmtIf, "description x"), ctx, "")
		if ref == nil || ref.N != 3 || ref.Class != "dangerous" || ref.Reason != string(core.ReasonMgmt) {
			t.Errorf("%s: management interface: %+v", name, ref)
		}
		lines, pv, ref := walk(f.d, plan(f.cfg, "interface "+f.other, "description lab", "end"), ctx, "")
		if ref != nil || len(lines) != 4 || len(pv.Lines) != 4 {
			t.Errorf("%s: a safe plan: %v %+v %+v", name, lines, pv, ref)
		}
		/* snapshot files of the executor are no line's business */
		if _, _, ref := walk(f.d, plan("delete flash:nms-pre-x"), ctx, ""); ref == nil {
			t.Errorf("%s: a snapshot file passed", name)
		}
	}
}
