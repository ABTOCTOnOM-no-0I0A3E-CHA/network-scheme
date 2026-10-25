package generic

import (
	"context"
	"regexp"
	"strings"

	"github.com/beekamai/network-scheme/internal/drivers"
	"github.com/beekamai/network-scheme/internal/drivers/mask"
	"github.com/beekamai/network-scheme/internal/drivers/showspec"
	"github.com/beekamai/network-scheme/internal/ssh"
)

/* FetchConfig is not supported: the generic driver has no SSH profile. */
func (Driver) FetchConfig(context.Context, drivers.ShowRunner) (string, error) {
	return "", drivers.ErrNotSupported
}

/* NormalizeConfig applies the common normalization. */
func (Driver) NormalizeConfig(cfg string) string { return drivers.NormalizeText(cfg) }

/* MaskSecrets applies the shared masking rules and heuristic. */
func (Driver) MaskSecrets(cfg string) string { return mask.Secrets(cfg) }

/* ConfigSections splits by top-level command. */
func (Driver) ConfigSections(masked string) []drivers.Section { return drivers.SplitSections(masked) }

/* ConfigNeedsWrite is false: the generic driver reads no configuration at all. */
func (Driver) ConfigNeedsWrite() bool { return false }

/* ShowCommands returns nil: the generic driver offers no show commands. */
func (Driver) ShowCommands() []showspec.Spec { return nil }

/* ShowCommand always fails with drivers.ErrUnknownShow. */
func (Driver) ShowCommand(string, []string) (ssh.ShowCommand, error) {
	return ssh.ShowCommand{}, drivers.ErrUnknownShow
}

var sfpNameRe = regexp.MustCompile(`^(te|xe|fo|hu|twe|tengigabitethernet|fortygigabitethernet|hundredgige|twentyfivegige)[\d\s/]`)

/* ifType values treated as copper/fibre Ethernet: ethernetCsmacd, fastEther, gigabitEthernet. */
func ethernetType(t uint64) bool { return t == 6 || t == 62 || t == 117 }

/*
portKind classifies an interface: only Ethernet ifTypes are physical ports;
10G and faster speeds, names containing "sfp" and 10G+ name prefixes (te, xe,
tengigabitethernet, ...) are SFP cages, other Ethernet ports are RJ-45. The
name heuristic follows the Eltex naming (gi1/0/1, te1/0/1) and is
unverified on hardware.
*/
func portKind(ifType uint64, name string, speedBps uint64) drivers.PortKind {
	if !ethernetType(ifType) {
		return drivers.PortOther
	}
	n := strings.ToLower(name)
	if strings.Contains(n, "sfp") || sfpNameRe.MatchString(n) || speedBps >= 10_000_000_000 {
		return drivers.PortSFP
	}
	return drivers.PortRJ45
}
