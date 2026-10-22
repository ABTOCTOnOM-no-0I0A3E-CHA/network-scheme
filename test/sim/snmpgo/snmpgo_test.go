package snmpgo

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

const fixture = `# comment
1.3.6.1.2.1.1.1.0|4|switch
1.3.6.1.2.1.1.5.0|4x|6e616d65
1.3.6.1.2.1.2.2.1.8.2|2|2
1.3.6.1.2.1.2.2.1.8.1|2|1
1.3.6.1.2.1.31.1.1.1.6.1|70|18446744073709551615
1.3.6.1.2.1.1.3.0|67|360000
1.3.6.1.2.1.2.2.1.10.1|65|7
`

func start(t *testing.T) *gosnmp.GoSNMP {
	t.Helper()
	mib, err := ParseSnmprec(strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), "secret-community-ro", mib)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return &gosnmp.GoSNMP{Target: a.Addr().Addr().String(), Port: a.Addr().Port(), Version: gosnmp.Version2c,
		Community: "secret-community-ro", Timeout: time.Second, Retries: 0}
}

func connect(t *testing.T, c *gosnmp.GoSNMP) {
	t.Helper()
	if err := c.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Conn.Close() })
}

func TestGet(t *testing.T) {
	c := start(t)
	connect(t, c)
	r, err := c.Get([]string{".1.3.6.1.2.1.1.5.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.31.1.1.1.6.1",
		".1.3.6.1.2.1.1.1.1", ".1.3.6.1.4.1.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	v := r.Variables
	if string(v[0].Value.([]byte)) != "name" || v[1].Value.(uint32) != 360000 || v[2].Value.(uint64) != 18446744073709551615 {
		t.Errorf("values: %+v", v[:3])
	}
	if v[3].Type != gosnmp.NoSuchInstance || v[4].Type != gosnmp.NoSuchObject {
		t.Errorf("missing: %v %v", v[3].Type, v[4].Type)
	}
}

func TestGetNext(t *testing.T) {
	c := start(t)
	connect(t, c)
	r, err := c.GetNext([]string{".1.3.6.1.2.1.1", ".1.3.6.1.2.1.2.2.1.8.1", ".1.3.6.1.2.1.31.1.1.1.6.1"})
	if err != nil {
		t.Fatal(err)
	}
	v := r.Variables
	if v[0].Name != ".1.3.6.1.2.1.1.1.0" || v[1].Name != ".1.3.6.1.2.1.2.2.1.8.2" || v[2].Type != gosnmp.EndOfMibView ||
		v[2].Name != ".1.3.6.1.2.1.31.1.1.1.6.1" {
		t.Errorf("%+v", v)
	}
}

func TestGetBulk(t *testing.T) {
	c := start(t)
	connect(t, c)
	r, err := c.GetBulk([]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.2.2.1.8"}, 1, 5)
	if err != nil {
		t.Fatal(err)
	}
	v := r.Variables
	/* one non-repeater, then 5 rows of the one repeater: 8.1 8.2 10.1 ... */
	if len(v) != 6 || v[0].Name != ".1.3.6.1.2.1.1.3.0" || v[1].Name != ".1.3.6.1.2.1.2.2.1.8.1" ||
		v[2].Name != ".1.3.6.1.2.1.2.2.1.8.2" || v[3].Name != ".1.3.6.1.2.1.2.2.1.10.1" {
		t.Errorf("%d varbinds: %+v", len(v), v)
	}
}

func TestBulkWalkEndsAtEndOfMibView(t *testing.T) {
	c := start(t)
	connect(t, c)
	var names []string
	if err := c.BulkWalk(".1.3", func(p gosnmp.SnmpPDU) error { names = append(names, p.Name); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(names) != 7 {
		t.Errorf("walked %d objects: %v", len(names), names)
	}
	r, err := c.GetBulk([]string{".1.3.6.1.2.1.31.1.1.1.6.1"}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Variables) != 1 || r.Variables[0].Type != gosnmp.EndOfMibView {
		t.Errorf("past the end: %+v", r.Variables)
	}
}

func TestWrongCommunityAndVersionAreSilent(t *testing.T) {
	c := start(t)
	c.Community = "another-community-ro"
	connect(t, c)
	if _, err := c.Get([]string{".1.3.6.1.2.1.1.1.0"}); err == nil {
		t.Error("wrong community answered")
	}
	c2 := start(t)
	c2.Version = gosnmp.Version1
	connect(t, c2)
	if _, err := c2.Get([]string{".1.3.6.1.2.1.1.1.0"}); err == nil {
		t.Error("SNMPv1 answered")
	}
}

func TestParseRejectsVariation(t *testing.T) {
	if _, err := ParseSnmprec(strings.NewReader("1.3.6.1.2.1.1.3.0|65:numeric|initial=1\n")); err == nil {
		t.Error("variation tag accepted")
	}
}
