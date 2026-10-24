/*
Package showspec describes the on-demand show commands a driver offers. It is
a leaf package (no SSH or SNMP imports) so the api can list the commands and
validate argument kinds without linking any device-access code. Mapping a
spec to the exact allowlisted command is done by the driver.
*/
package showspec

/* ArgKind is the type of one command argument. */
type ArgKind string

/* Argument kinds. */
const (
	/* InterfaceName is an interface name taken from the device inventory. */
	InterfaceName ArgKind = "interface"
	/* VLANID is a VLAN id in 1..4094. */
	VLANID ArgKind = "vlan"
)

/* Spec is one command: a stable key (the UI translates it) and its typed arguments; none means a bare command. */
type Spec struct {
	Key  string
	Args []ArgKind
}
