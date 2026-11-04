package drivers

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/beekamai/network-scheme/cmd/executor/internal/drivers/core"
)

/* FormKind is a GUI form of a change session (architecture.md 6.4). */
type FormKind string

/* Form kinds. */
const (
	FormDescription FormKind = "interface-description" /* Interface, Description ("" removes it) */
	FormState       FormKind = "interface-state"       /* Interface, Up */
	FormAccessVLAN  FormKind = "access-vlan"           /* Interface, VLAN (0 removes it) */
	FormVLANCreate  FormKind = "vlan-create"           /* VLAN */
	FormVLANName    FormKind = "vlan-name"             /* VLAN, Name */
	FormVLANDelete  FormKind = "vlan-delete"           /* VLAN */
)

/* Form is a typed GUI change; its fields never reach a device but through RenderForm. */
type Form struct {
	Kind        FormKind
	Interface   string /* one interface, any spelling the line's grammar knows ("gi1/0/1") */
	Description string
	Up          bool
	VLAN        int
	Name        string
}

var (
	/* descRe: printable ASCII without quotes, '\', ';', '|', '?', single spaces inside (or none). */
	descRe   = regexp.MustCompile(`^[!#-&(-:<->@-\[\]-{}~]+(?: [!#-&(-:<->@-\[\]-{}~]+)*$`)
	oneWord  = regexp.MustCompile(`^[!#-&(-:<->@-\[\]-{}~]+$`)
	ifnameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9/.-]{0,63}$`)
)

/* Check validates the fields of f: maxDesc bytes of description, spaces in it only when spaces is set. */
func (f Form) Check(maxDesc int, spaces bool) error {
	bad := func(what string) error { return fmt.Errorf("%w: %s", ErrForm, what) }
	switch f.Kind {
	case FormDescription, FormState, FormAccessVLAN:
		if !ifnameRe.MatchString(f.Interface) {
			return bad("interface")
		}
	case FormVLANCreate, FormVLANName, FormVLANDelete:
	default:
		return bad("kind")
	}
	switch f.Kind {
	case FormDescription:
		re := descRe
		if !spaces {
			re = oneWord
		}
		if f.Description != "" && (len(f.Description) > maxDesc || !re.MatchString(f.Description)) {
			return bad("description")
		}
	case FormAccessVLAN:
		if f.VLAN != 0 && !VLAN.Match(strconv.Itoa(f.VLAN)) {
			return bad("vlan")
		}
	case FormVLANCreate, FormVLANName, FormVLANDelete:
		if f.VLAN < 1 || f.VLAN > 4094 {
			return bad("vlan")
		}
		if f.Kind == FormVLANName && !VName.Match(f.Name) {
			return bad("name")
		}
	}
	return nil
}

/* PortLines are the interface-mode lines of a checked interface form (the same on every line). */
func (f Form) PortLines() []string {
	switch f.Kind {
	case FormDescription:
		if f.Description == "" {
			return []string{"no description"}
		}
		return []string{"description " + f.Description}
	case FormState:
		if f.Up {
			return []string{"no shutdown"}
		}
		return []string{"shutdown"}
	case FormAccessVLAN:
		if f.VLAN == 0 {
			return []string{"no switchport access vlan"}
		}
		return []string{"switchport access vlan " + strconv.Itoa(f.VLAN)}
	}
	return nil
}

/* Show are the safe show commands every line has [R §5, read allowlist], with the line's filter keywords on show running-config. */
func Show(filters ...string) []core.Cmd {
	cmds := []core.Cmd{}
	for _, p := range []string{"show running-config", "show version", "show system", "show interfaces status",
		"show vlan", "show mac address-table", "show arp", "show ip route", "show users", "show clock",
		"show lldp neighbors", "show logging"} {
		cmds = append(cmds, Safe(p))
	}
	for _, f := range filters {
		cmds = append(cmds, Safe("show running-config | "+f+" <filter>"))
	}
	return cmds
}
