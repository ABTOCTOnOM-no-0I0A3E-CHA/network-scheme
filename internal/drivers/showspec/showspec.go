/*
Package showspec describes the on-demand show commands a driver offers. It is
a leaf package (no SSH or SNMP imports) so the api can list the commands and
validate argument kinds without linking any device-access code. Mapping a
spec to the exact allowlisted command is done by the driver.
*/
package showspec

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

/* ArgKind is the type of one command argument. */
type ArgKind string

/* Argument kinds. */
const (
	/*
		InterfaceName is an interface name taken from the device inventory. The
		caller must check membership in the inventory; the driver only validates
		the syntax ("gi1/0/1", or on ESR "gigabitethernet 1/0/1").
	*/
	InterfaceName ArgKind = "interface"
	/* VLANID is a VLAN id in 1..4094. */
	VLANID ArgKind = "vlan"
)

/* Spec is one command: a stable key (the UI translates it) and its typed arguments; none means a bare command. */
type Spec struct {
	Key  string
	Args []ArgKind
}

/*
For returns the show commands of the driver called name; nil for an unknown
driver, one without show commands (generic-snmp) or one not yet identified
("auto"). The table is what the api offers and validates against; the drivers
carry the same list with the command texts, and a test keeps both equal.
*/
func For(name string) []Spec { return table[name] }

var (
	ifArg   = []ArgKind{InterfaceName}
	vlanArg = []ArgKind{VLANID}

	common = []Spec{
		{Key: "version"},
		{Key: "system"},
		{Key: "interfaces_status"},
		{Key: "interface_status", Args: ifArg},
		{Key: "interface_counters", Args: ifArg},
	}
	table = map[string][]Spec{
		"eltex-mes": append(append([]Spec{}, common...),
			Spec{Key: "vlan_list"},
			Spec{Key: "vlan_tag", Args: vlanArg},
			Spec{Key: "mac_table"},
			Spec{Key: "mac_table_vlan", Args: vlanArg},
			Spec{Key: "arp"},
			Spec{Key: "lldp_neighbors"},
			Spec{Key: "ip_routes"}),
		"eltex-esr": append(append([]Spec{}, common...),
			Spec{Key: "mac_table"},
			Spec{Key: "arp"},
			Spec{Key: "lldp_neighbors"},
			Spec{Key: "ip_routes"}),
	}
)

/* maxInterfaceArg bounds an interface argument (the driver regexps allow 64 characters). */
const maxInterfaceArg = 64

/*
ParseArgs checks the "args" object of a request or of a stored row against s
and returns the arguments in command order, as strings, plus the canonical
JSON to store. The object must hold exactly one member per argument, named
after its kind: an interface is a JSON string of ASCII letters, digits and
"/.:-" (and one space between a kind and a number, ESR style), at most 64
bytes; a VLAN is a JSON integer in 1..4094. Nothing else passes: no extra
members, strings for numbers, fractions, exponents or control characters.
That an interface belongs to the device is the caller's check.
*/
func ParseArgs(s Spec, raw json.RawMessage) (vals []string, canon json.RawMessage, err error) {
	var m map[string]json.RawMessage
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, nil, errBadArgs
	}
	if len(m) != len(s.Args) {
		return nil, nil, errBadArgs
	}
	out := make(map[string]any, len(s.Args))
	for _, k := range s.Args {
		v, ok := m[string(k)]
		if !ok {
			return nil, nil, errBadArgs
		}
		switch k {
		case InterfaceName:
			var str string
			if json.Unmarshal(v, &str) != nil || !validInterface(str) {
				return nil, nil, errBadArgs
			}
			vals, out[string(k)] = append(vals, str), str
		case VLANID:
			n, convErr := strconv.Atoi(string(bytes.TrimSpace(v)))
			if convErr != nil || n < 1 || n > 4094 || strconv.Itoa(n) != string(bytes.TrimSpace(v)) {
				return nil, nil, errBadArgs
			}
			vals, out[string(k)] = append(vals, strconv.Itoa(n)), n
		default:
			return nil, nil, errBadArgs
		}
	}
	canon, err = json.Marshal(out)
	return vals, canon, err
}

/* errBadArgs is the only error of ParseArgs: callers answer with a fixed text. */
var errBadArgs = errors.New("showspec: invalid arguments")

/* validInterface: 1..64 bytes of [A-Za-z0-9/.:-], optionally with single spaces between non-empty parts. */
func validInterface(s string) bool {
	if s == "" || len(s) > maxInterfaceArg || s[0] == ' ' || s[len(s)-1] == ' ' || strings.Contains(s, "  ") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '/', c == '.', c == ':', c == '-', c == ' ':
		default:
			return false
		}
	}
	return true
}
