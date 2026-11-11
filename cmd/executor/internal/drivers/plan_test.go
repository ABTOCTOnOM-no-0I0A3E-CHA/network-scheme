package drivers_test

import (
	"slices"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers"
	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/mes6"
)

/* Plan: root lines and context bodies, dropped lines by the grammar's shortest known "no" form, unknown ones literally. */
func TestPlan(t *testing.T) {
	from := "hostname a\nlogging host 192.0.2.5\n!\ninterface gigabitethernet1/0/2\n description lab\n shutdown\nexit\ninterface gigabitethernet1/0/3\n shutdown\nexit\n"
	to := "hostname b\n!\ninterface gigabitethernet1/0/2\n shutdown\nexit\ninterface gigabitethernet1/0/4\n description new\n shutdown\nexit\n"
	got, err := mes6.New().Plan(drivers.NewConfig(from), drivers.NewConfig(to))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"configure", "no logging host 192.0.2.5", "hostname b",
		"interface gigabitethernet1/0/2", "no description", "exit",
		"interface gigabitethernet1/0/4", "description new", "shutdown", "exit",
		"no interface gigabitethernet1/0/3", "end"}
	if !slices.Equal(got, want) {
		t.Fatalf("plan\n%q\nwant\n%q", got, want)
	}
	if p, err := mes6.New().Plan(drivers.NewConfig(from), drivers.NewConfig(from)); err != nil || p != nil {
		t.Fatalf("same configuration: %q %v", p, err)
	}
}
