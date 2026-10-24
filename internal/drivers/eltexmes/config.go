package eltexmes

import (
	"context"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
runningConfig is the configuration read command. Source: [UM] §5 (privileged
EXEC "show running-config"). The assumption that it works for a read-only
account is not verified on hardware.
*/
const runningConfig = "show running-config"

var (
	ifArg   = []showspec.ArgKind{showspec.InterfaceName}
	vlanArg = []showspec.ArgKind{showspec.VLANID}
)

/*
showDefs are the on-demand show commands (never a configuration dump: those
would hand full configs to the api). Source: [UM] §5 command tables; not
verified on hardware.
*/
var showDefs = []drivers.ShowDef{
	{Spec: showspec.Spec{Key: "version"}, Name: "show version"},
	{Spec: showspec.Spec{Key: "system"}, Name: "show system"},
	{Spec: showspec.Spec{Key: "interfaces_status"}, Name: "show interfaces status"},
	{Spec: showspec.Spec{Key: "interface_status", Args: ifArg}, Name: "show interfaces status"},
	{Spec: showspec.Spec{Key: "interface_counters", Args: ifArg}, Name: "show interfaces counters"},
	{Spec: showspec.Spec{Key: "vlan_list"}, Name: "show vlan"},
	{Spec: showspec.Spec{Key: "vlan_tag", Args: vlanArg}, Name: "show vlan tag"},
	{Spec: showspec.Spec{Key: "mac_table"}, Name: "show mac address-table"},
	{Spec: showspec.Spec{Key: "mac_table_vlan", Args: vlanArg}, Name: "show mac address-table vlan"},
	{Spec: showspec.Spec{Key: "arp"}, Name: "show arp"},
	{Spec: showspec.Spec{Key: "lldp_neighbors"}, Name: "show lldp neighbors"},
	{Spec: showspec.Spec{Key: "ip_routes"}, Name: "show ip route"},
}

/* ShowCommands lists the on-demand show commands. */
func (Driver) ShowCommands() []showspec.Spec { return drivers.Specs(showDefs) }

/* ShowCommand maps a key and arguments to the allowlisted command. */
func (Driver) ShowCommand(key string, args []string) (ssh.ShowCommand, error) {
	return drivers.ResolveShow(showDefs, key, args)
}

/* FetchConfig reads "show running-config" and returns sanitised text. */
func (d Driver) FetchConfig(ctx context.Context, sh drivers.ShowRunner) (string, error) {
	return drivers.FetchRunning(ctx, sh, d.Dialect(), ssh.ShowCommand{Name: runningConfig})
}

/*
ConfigNeedsWrite is false by assumption: the MES documentation shows
"show running-config" in privileged EXEC, which the read prompt (#) already
is, and says nothing about a write right. The hardware stand must confirm it.
*/
func (Driver) ConfigNeedsWrite() bool { return false }
