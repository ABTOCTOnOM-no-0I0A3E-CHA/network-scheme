package topology

import (
	"context"
	"testing"
)

func TestMergeNull(t *testing.T) {
	in := []link{
		{a: 1, ai: 1, b: 2, source: "mac", conf: 40},
		{a: 1, ai: 1, b: 2, bi: 2, source: "lldp", conf: 80},
		{a: 1, b: 2, source: "mac", conf: 90},
		{a: 1, ai: 3, b: 2, bi: 4, source: "lldp", conf: 100},
		{a: 5, ai: 1, b: 6, source: "mac", conf: 40}, /* other pair: untouched */
	}
	out, _ := mergeNull(context.Background(), in)
	if len(out) != 3 {
		t.Fatalf("%+v", out)
	}
	for _, l := range out {
		if l.a == 1 && l.ai == 1 && (l.bi != 2 || l.conf != 80 || l.source != "lldp") {
			t.Errorf("merged link %+v", l)
		}
	}
	/* a single candidate takes over the stronger evidence */
	out, _ = mergeNull(context.Background(), []link{{a: 1, ai: 1, b: 2, source: "lldp", conf: 80}, {a: 1, ai: 1, b: 2, bi: 2, source: "mac", conf: 40}})
	if len(out) != 1 || out[0].conf != 80 || out[0].source != "lldp" || out[0].bi != 2 {
		t.Errorf("%+v", out)
	}
}

/* (A,1,B,NULL) and (A,NULL,B,2) are two different statements, not one cable: both stay. */
func TestMergeNullKeepsIncomparable(t *testing.T) {
	out, _ := mergeNull(context.Background(), []link{{a: 1, ai: 1, b: 2, conf: 50}, {a: 1, b: 2, bi: 2, conf: 50}})
	if len(out) != 2 {
		t.Errorf("%+v", out)
	}
}
