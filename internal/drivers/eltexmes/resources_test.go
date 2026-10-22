package eltexmes

import (
	"context"
	"strings"
	"testing"

	"github.com/beekamai/network-scheme/internal/snmp"
)

/* staticReader serves Get and Walk from a fixed variable list, without a simulator. */
type staticReader []snmp.Var

func (s staticReader) Get(_ context.Context, oids ...string) ([]snmp.Var, error) {
	var out []snmp.Var
	for _, o := range oids {
		for _, v := range s {
			if v.OID == o {
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (s staticReader) Walk(ctx context.Context, root string, fn func(snmp.Var) error) error {
	for _, v := range s {
		if strings.HasPrefix(v.OID, root+".") {
			if err := fn(v); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

func (staticReader) BulkGet(context.Context, []string) ([]snmp.Var, error) { return nil, nil }

func i(oid string, n int64) snmp.Var { return snmp.Var{OID: oid, Type: snmp.TypeInteger, Value: n} }

func TestPSUStates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f, tr := false, true
	for name, c := range map[string]struct {
		vars []snmp.Var
		want *bool
	}{
		"absent":             {nil, nil},
		"main normal":        {[]snmp.Var{i(psuMain+".1", 1)}, &tr},
		"redundant missing":  {[]snmp.Var{i(psuMain+".1", 1), i(psuRedundant+".1", 5)}, &tr},
		"main critical":      {[]snmp.Var{i(psuMain+".1", 3), i(psuRedundant+".1", 1)}, &f},
		"redundant failed":   {[]snmp.Var{i(psuMain+".1", 1), i(psuRedundant+".1", 6)}, &f},
		"second unit failed": {[]snmp.Var{i(psuMain+".1", 1), i(psuMain+".2", 4)}, &f},
		"only redundant row": {[]snmp.Var{i(psuRedundant+".1", 1)}, nil},
	} {
		got := psu(ctx, staticReader(c.vars))
		if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
			t.Errorf("%s: got %v, want %v", name, deref(got), deref(c.want))
		}
	}
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func TestCPUOutOfRangeIsNil(t *testing.T) {
	t.Parallel()
	for _, n := range []int64{-1, 101, 1000} {
		if v := cpu(context.Background(), staticReader{i(cpuLastMinute, n)}); v != nil {
			t.Errorf("cpu(%d) = %v, want nil", n, *v)
		}
	}
	if v := cpu(context.Background(), staticReader{{OID: cpuLastMinute, Type: snmp.TypeOctetString, Value: []byte("50")}}); v != nil {
		t.Errorf("cpu(OctetString) = %v, want nil", *v)
	}
}
