package drivers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/snmp"
	"github.com/beekamai/network-scheme/internal/ssh"
)

type fakeDriver struct{ name string }

func (f fakeDriver) Name() string              { return f.name }
func (f fakeDriver) Match(string, string) bool { return true }
func (f fakeDriver) Dialect() ssh.Dialect      { return ssh.Dialect{} }
func (f fakeDriver) Identify(context.Context, snmp.Reader) (Identity, error) {
	return Identity{}, nil
}
func (f fakeDriver) Collect(context.Context, snmp.Reader) (Sample, error) { return Sample{}, nil }
func (f fakeDriver) Inventory(context.Context, snmp.Reader, ShowRunner) (Inventory, error) {
	return Inventory{}, nil
}

func TestDefaultOrder(t *testing.T) {
	/* registration order must not matter: eltex-esr, eltex-mes, others, generic-snmp */
	for _, n := range []string{"generic-snmp", "zz-other", "eltex-mes", "eltex-esr"} {
		Register(fakeDriver{n})
	}
	defer func() { registered = nil }()
	var got []string
	for _, d := range Default().drivers {
		got = append(got, d.Name())
	}
	want := "eltex-esr,eltex-mes,zz-other,generic-snmp"
	if strings.Join(got, ",") != want {
		t.Fatalf("order %v, want %s", got, want)
	}
	if n := Default().Select("1.3.6.1.4.1.32473", "x").Name(); n != "eltex-esr" {
		t.Fatalf("Select = %s", n)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registration did not panic")
		}
	}()
	Register(fakeDriver{"eltex-mes"})
}

type unverifiedDriver struct{ fakeDriver }

func (unverifiedDriver) Verified() bool { return false }

type verifiedDriver struct{ fakeDriver }

func (verifiedDriver) Verified() bool { return true }

func TestUnverified(t *testing.T) {
	Register(fakeDriver{GenericName})
	Register(unverifiedDriver{fakeDriver{"eltex-mes"}})
	Register(verifiedDriver{fakeDriver{"zz-verified"}})
	Register(unverifiedDriver{fakeDriver{"eltex-esr"}})
	defer func() { registered = nil }()
	if got := strings.Join(Unverified(), ","); got != "eltex-esr,eltex-mes" {
		t.Fatalf("Unverified() = %s", got)
	}
}

type noMatch struct{ fakeDriver }

func (noMatch) Match(string, string) bool { return false }

func mustPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s did not panic", name)
		}
	}()
	fn()
}

func TestRegistryAlwaysHasFallback(t *testing.T) {
	/* nothing registered in this test binary: Default must fail fast, not return an empty registry */
	mustPanic(t, "Default without generic", func() { Default() })
	mustPanic(t, "NewRegistry()", func() { NewRegistry() })
	mustPanic(t, "fallback not last", func() { NewRegistry(fakeDriver{GenericName}, fakeDriver{"eltex-mes"}) })

	/* even if the fallback declines, Select never returns nil */
	r := NewRegistry(noMatch{fakeDriver{"eltex-mes"}}, noMatch{fakeDriver{GenericName}})
	if d := r.Select("1.3", ""); d == nil || d.Name() != GenericName {
		t.Fatalf("Select = %v", d)
	}
}

func TestRegistryByName(t *testing.T) {
	r := NewRegistry(fakeDriver{"eltex-mes"}, fakeDriver{GenericName})
	if d := r.ByName("eltex-mes"); d == nil || d.Name() != "eltex-mes" {
		t.Fatalf("ByName(eltex-mes) = %v", d)
	}
	if d := r.ByName("auto"); d != nil {
		t.Fatalf("ByName(auto) = %v", d)
	}
}

func TestCleanText(t *testing.T) {
	long := strings.Repeat("я", 600) /* 1200 bytes */
	for in, want := range map[string]string{
		"  sw1\x00\x00 ":                      "sw1",
		"a\x1b[31mb\r\nc\td":                  "a[31mbcd",
		"bad" + string([]byte{0xff}) + "utf8": "bad" + string(rune(0xfffd)) + "utf8",
		"rtl" + string(rune(0x202e)) + "evil": "rtlevil",
		long:                                  strings.Repeat("я", 512),
	} {
		if got := CleanText([]byte(in)); got != want {
			t.Errorf("CleanText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormatMAC(t *testing.T) {
	if s, ok := FormatMAC([]byte{0, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}); !ok || s != "00:aa:bb:cc:dd:01" {
		t.Fatalf("got %q %v", s, ok)
	}
	for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 8)} {
		if _, ok := FormatMAC(b); ok {
			t.Fatalf("accepted %x", b)
		}
	}
}

/* listReader serves Walk from a fixed list of vars. */
type listReader struct {
	snmp.Reader
	vars []snmp.Var
}

func (l listReader) Walk(ctx context.Context, root string, fn func(snmp.Var) error) error {
	for _, v := range l.vars {
		if strings.HasPrefix(v.OID, root+".") {
			if err := fn(v); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func TestWalkColumn(t *testing.T) {
	r := listReader{vars: []snmp.Var{
		{OID: "1.3.6.1.2.1.2.2.1.2.1", Type: snmp.TypeOctetString, Value: []byte("a")},
		{OID: "1.3.6.1.2.1.2.2.1.2.2.7", Type: snmp.TypeOctetString, Value: []byte("b")},
		{OID: "1.3.6.1.2.1.2.2.1.2.99999999999", Type: snmp.TypeOctetString, Value: []byte("c")},
	}}
	var idx [][]uint32
	n, err := WalkColumn(context.Background(), r, "1.3.6.1.2.1.2.2.1.2", 10, func(i []uint32, _ snmp.Var) {
		idx = append(idx, i)
	})
	if err != nil || n != 3 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if len(idx) != 3 || idx[0][0] != 1 || len(idx[1]) != 2 || idx[2] != nil {
		t.Fatalf("indexes %v (an unparsable suffix must come back as nil)", idx)
	}
	n, err = WalkColumn(context.Background(), r, "1.3.6.1.2.1.2.2.1.2", 2, func([]uint32, snmp.Var) {})
	if !errors.Is(err, ErrTooManyRows) || n != 2 {
		t.Fatalf("limit: n=%d err=%v", n, err)
	}
}

func TestBudget(t *testing.T) {
	if BudgetFrom(context.Background()).SkipHeavy {
		t.Fatal("default budget skips heavy tables")
	}
	if !BudgetFrom(WithBudget(context.Background(), Budget{SkipHeavy: true})).SkipHeavy {
		t.Fatal("budget lost")
	}
}
