package all

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/ssh"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* The table the api offers is the table of the driver the poller resolves with. */
func TestShowSpecTableMatchesDrivers(t *testing.T) {
	for _, name := range []string{"eltex-mes", "eltex-esr", drivers.GenericName} {
		got, want := byName(t, name).ShowCommands(), showspec.For(name)
		if len(got) == 0 && len(want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: driver %v, showspec %v", name, got, want)
		}
	}
}

/* sampleArgs builds valid string arguments for a spec. */
func sampleArgs(s showspec.Spec, long bool) []string {
	var out []string
	for _, k := range s.Args {
		switch {
		case k == showspec.VLANID:
			out = append(out, "100")
		case long:
			out = append(out, "gigabitethernet 1/0/1")
		default:
			out = append(out, "gi1/0/1")
		}
	}
	return out
}

/*
Every show command of every driver is sent over a real Runner to an emulator:
the device sees exactly the resolved command, never a configuration read, and
whatever else is asked (unlisted names, foreign arguments, config reads) is
refused before the wire.
*/
func TestShowCommandsOnlyAllowlistedOnTheWire(t *testing.T) {
	env := testdb.New(t)
	for _, name := range []string{"eltex-mes", "eltex-esr"} {
		t.Run(name, func(t *testing.T) {
			d := byName(t, name)
			long := name == "eltex-esr"
			responses := map[string]string{}
			var want []string
			for _, s := range d.ShowCommands() {
				cmd, err := d.ShowCommand(s.Key, sampleArgs(s, long))
				if err != nil {
					t.Fatalf("%s: %v", s.Key, err)
				}
				if strings.Contains(strings.ToLower(cmd.String()), "config") {
					t.Fatalf("%s resolves to a configuration read: %q", s.Key, cmd)
				}
				responses[cmd.String()] = "out of " + s.Key
				want = append(want, cmd.String())
			}
			r, log := dial(t, env, d, responses)
			for _, s := range d.ShowCommands() {
				cmd, _ := d.ShowCommand(s.Key, sampleArgs(s, long))
				if out, err := r.Run(context.Background(), cmd); err != nil || out != "out of "+s.Key {
					t.Errorf("%s: %q, %v", s.Key, out, err)
				}
			}
			if got := log.Commands(); !slices.Equal(got[1:], want) { /* the first is the pager-off command of the dialect */
				t.Fatalf("device saw %q, want %q", got, want)
			}
			/* Commands outside the dialect never reach the device. */
			for _, bad := range []string{"show startup-config", "show version | include x", "reload", "show version\nreload"} {
				if _, err := r.Run(context.Background(), ssh.ShowCommand{Name: bad}); !errors.Is(err, ssh.ErrNotAllowed) {
					t.Errorf("%q: %v", bad, err)
				}
			}
			/* The show path resolves only its own keys: never a configuration read, never loose arguments. */
			for _, key := range []string{"running_config", "running-config", "startup_config", "config", "show running-config", ""} {
				if cmd, err := d.ShowCommand(key, nil); !errors.Is(err, drivers.ErrUnknownShow) {
					t.Errorf("key %q resolved to %q, %v", key, cmd, err)
				}
			}
			bad := map[string][][]string{
				"interface_status": {nil, {"gi1/0/1 | include x"}, {"gi1/0/1\nreload"}, {"gi1/0/1;x"}, {"gi1/0/1", "gi1/0/2"}, {""}},
				"version":          {{"gi1/0/1"}},
			}
			if name == "eltex-mes" {
				bad["vlan_tag"] = [][]string{nil, {"0"}, {"4095"}, {"-1"}, {"1e1"}, {"gi1/0/1"}, {"1", "2"}}
				bad["interface_status"] = append(bad["interface_status"], []string{"gigabitethernet 1/0/1"}) /* the long form is ESR only */
			}
			for key, list := range bad {
				for _, args := range list {
					if cmd, err := d.ShowCommand(key, args); err == nil {
						t.Errorf("%s %q resolved to %q", key, args, cmd)
					}
				}
			}
			if got := log.Commands(); !slices.Equal(got[1:], want) {
				t.Errorf("device saw %q after the refused ones, want %q", got, want)
			}
			for _, c := range log.Commands() {
				if strings.Contains(c, "config") || strings.ContainsAny(c, "|;&\n") {
					t.Errorf("device saw %q", c)
				}
			}
		})
	}
}
