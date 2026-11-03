package eltexesr

import (
	"context"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/*
runningConfig is the configuration read command. Source: [CLI] (privileged
mode "show running-config"). The assumption that it works for a read-only
account is not verified on hardware.
*/
const runningConfig = "show running-config"

var ifArg = []showspec.ArgKind{showspec.InterfaceName}

/*
showDefs are the on-demand show commands (never a configuration dump: those
would hand full configs to the api). Source: [CLI] and [MON] command examples; not
verified on hardware.
*/
var showDefs = []drivers.ShowDef{
	{Spec: showspec.Spec{Key: "version"}, Name: "show version"},
	{Spec: showspec.Spec{Key: "system"}, Name: "show system"},
	{Spec: showspec.Spec{Key: "interfaces_status"}, Name: "show interfaces status"},
	{Spec: showspec.Spec{Key: "interface_status", Args: ifArg}, Name: "show interfaces status"},
	{Spec: showspec.Spec{Key: "interface_counters", Args: ifArg}, Name: "show interfaces counters"},
	{Spec: showspec.Spec{Key: "mac_table"}, Name: "show mac address-table"},
	{Spec: showspec.Spec{Key: "arp"}, Name: "show arp"},
	{Spec: showspec.Spec{Key: "lldp_neighbors"}, Name: "show lldp neighbors"},
	{Spec: showspec.Spec{Key: "ip_routes"}, Name: "show ip route"},
}

/* ShowCommands lists the on-demand show commands. */
func (Driver) ShowCommands() []showspec.Spec { return drivers.Specs(showDefs) }

/* ShowCommand maps a key and arguments to the allowlisted command. */
func (Driver) ShowCommand(key string, args []string) (ssh.ShowCommand, error) {
	return drivers.ResolveShow(showDefs, key, args, true)
}

/* FetchConfig reads "show running-config" and returns sanitised text. */
func (d Driver) FetchConfig(ctx context.Context, sh drivers.ShowRunner) (string, error) {
	return drivers.FetchRunning(ctx, sh, d.Dialect(), ssh.ShowCommand{Name: runningConfig, LongOutput: true})
}

/*
ConfigNeedsWrite is true: "show running-config" needs privilege level 10,
and level 10 already allows configuring the device (ESR-Series CLI reference
1.28, pp. 24, 103; research [R §3], ruling Q4). A level 1..9 account with
"privilege root level <N> show running-config" is documented in syntax only.
Not verified on hardware.
*/
func (Driver) ConfigNeedsWrite() bool { return true }
