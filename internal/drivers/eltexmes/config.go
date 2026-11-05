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
	return drivers.ResolveShow(showDefs, key, args, false)
}

/* FetchConfig reads "show running-config" and returns sanitised text. */
func (d Driver) FetchConfig(ctx context.Context, sh drivers.ShowRunner) (string, error) {
	return drivers.FetchRunning(ctx, sh, d.Dialect(), ssh.ShowCommand{Name: runningConfig, LongOutput: true})
}

/*
ConfigNeedsWrite reports, per firmware line, whether "show running-config"
needs a write-privileged account. Source: research [R §3] (ruling Q4).
  - MES 10.x: true. Levels 1..14 give access but no configuration and level 15
    gives both ([UM10] p. 75); no per-command "privilege" exists in 10.x, so the
    read is taken to need 15.
  - MES 6.x: false. "privilege exec 4 show running-config" lowers the level of
    exactly that command ([UM6] §4.5.1).
  - unknown line: false; the poller tries the read and records a refusal by
    the device as needs_write.
Not verified on hardware.
*/
func (d Driver) ConfigNeedsWrite() bool { return d.line == LineMES10 }
