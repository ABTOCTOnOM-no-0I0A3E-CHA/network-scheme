package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/beekamai/network-scheme/internal/devices"
)

/* egressChain is the Docker chain for user rules; Docker evaluates it before its own forwarding rules. */
const egressChain = "DOCKER-USER"

/* EgressFile is the egress configuration written by install, relative to Paths.Etc. */
const EgressFile = "config/egress.yaml"

/* egressDropIn makes Docker apply the egress rules before it starts; a failure keeps Docker down. */
const egressDropIn = "docker.service.d/nms-egress.conf"

/*
Egress limits where the devices network may send packets: only to the
management subnets. Everything else coming from DevicesSubnet is dropped in
the DOCKER-USER chain.
*/
type Egress struct {
	DevicesSubnet netip.Prefix   `yaml:"devices_subnet"`
	MgmtSubnets   []netip.Prefix `yaml:"mgmt_subnets"`
}

/*
ParseMgmtSubnets validates the management subnets given to install: at least
one, IPv4 network addresses (the devices network has no IPv6), none touching
a reserved range (the same rule as discovery scans, without the size limit).
*/
func ParseMgmtSubnets(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return nil, errors.New("at least one --mgmt-subnet is required")
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, fmt.Errorf("management subnet %q must be an IPv4 network address with prefix", s)
		}
		if err := devices.CheckScanPrefix(p); err != nil && !errors.Is(err, devices.ErrScanTooWide) {
			return nil, fmt.Errorf("management subnet %s is a reserved range", p)
		}
		out = append(out, p)
	}
	return out, nil
}

func (e Egress) validate() error {
	d := e.DevicesSubnet
	if !d.IsValid() || !d.Addr().Is4() || d != d.Masked() {
		return errors.New("egress: devices subnet must be an IPv4 network address with prefix")
	}
	list := make([]string, 0, len(e.MgmtSubnets))
	for _, p := range e.MgmtSubnets {
		list = append(list, p.String())
	}
	if _, err := ParseMgmtSubnets(list); err != nil {
		return fmt.Errorf("egress: %w", err)
	}
	return nil
}

/* egressYAML is the content of EgressFile. */
func egressYAML(e Egress) ([]byte, error) {
	body, err := yaml.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Written by nmsctl install. Docker applies it before it starts (nmsctl egress apply).\n"), body...), nil
}

// LoadEgress reads and validates the egress configuration of an installation.
func LoadEgress(path string) (Egress, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- installer-owned path
	if err != nil {
		return Egress{}, fmt.Errorf("egress: %w", err)
	}
	var e Egress
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&e); err != nil {
		return Egress{}, fmt.Errorf("egress: parse %s: %w", path, err)
	}
	return e, e.validate()
}

// ErrEgressBypassed means Docker does not send forwarded traffic through DOCKER-USER.
var ErrEgressBypassed = errors.New("install: Docker does not pass forwarded traffic through DOCKER-USER (egress rules would not apply)")

/*
CheckDockerUsesEgress verifies that the running Docker daemon jumps from
FORWARD to DOCKER-USER, so the egress rules are on the containers' path.
*/
func CheckDockerUsesEgress(ctx context.Context, sys System) error {
	if err := iptables(ctx, sys, "-w", "-C", "FORWARD", "-j", egressChain); err != nil {
		return fmt.Errorf("%w: %v", ErrEgressBypassed, err)
	}
	return nil
}

/* maxIPTablesStderr bounds the iptables message kept in an error. */
const maxIPTablesStderr = 512

/*
iptables runs iptables with args. On failure the error carries the start of
its stderr, so the reason reaches the caller (and the journal at boot).
*/
func iptables(ctx context.Context, sys System, args ...string) error {
	var stderr bytes.Buffer
	err := sys.Run(ctx, Cmd{Name: "iptables", Args: args, Stderr: &stderr})
	if err == nil {
		return nil
	}
	msg := stderr.Bytes()
	if len(msg) > maxIPTablesStderr {
		msg = msg[:maxIPTablesStderr]
	}
	if s := strings.TrimSpace(string(msg)); s != "" {
		return fmt.Errorf("%w: %s", err, s)
	}
	return err
}

/* rules returns the allow rules (in their final order) and the closing DROP rule. */
func (e Egress) rules() (allow [][]string, drop []string) {
	src := []string{"-s", e.DevicesSubnet.String()}
	allow = append(allow, append(append([]string{}, src...), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"))
	for _, m := range e.MgmtSubnets {
		allow = append(allow, append(append([]string{}, src...), "-d", m.String(), "-j", "RETURN"))
	}
	return allow, append(append([]string{}, src...), "-j", "DROP")
}

/*
ApplyEgress puts the rules of e at the top of DOCKER-USER: RETURN (Docker's
own rules decide next) for replies and for each management subnet, then DROP
for everything else from the devices subnet. It is idempotent: a rule is
inserted only when "iptables -C" does not find it. When the DROP rule is
missing, existing allow rules are removed first so that every allow rule ends
up above the DROP. The chain is created when Docker has not started yet (at
boot), so the rules are in place before any container runs.
*/
func ApplyEgress(ctx context.Context, sys System, e Egress) error {
	if err := e.validate(); err != nil {
		return err
	}
	ipt := func(args ...string) error { return iptables(ctx, sys, append([]string{"-w"}, args...)...) }
	has := func(rule []string) bool { return ipt(append([]string{"-C", egressChain}, rule...)...) == nil }
	insert := func(rule []string) error {
		if err := ipt(append([]string{"-I", egressChain, "1"}, rule...)...); err != nil {
			return fmt.Errorf("egress: iptables insert: %w", err)
		}
		return nil
	}

	if ipt("-n", "-L", egressChain) != nil {
		if err := ipt("-N", egressChain); err != nil {
			return fmt.Errorf("egress: create %s: %w", egressChain, err)
		}
	}
	allow, drop := e.rules()
	if !has(drop) {
		for _, r := range allow {
			if has(r) {
				if err := ipt(append([]string{"-D", egressChain}, r...)...); err != nil {
					return fmt.Errorf("egress: iptables delete: %w", err)
				}
			}
		}
		if err := insert(drop); err != nil {
			return err
		}
	}
	/* Inserted at the top in reverse, so they keep their order above the DROP. */
	for i := len(allow) - 1; i >= 0; i-- {
		if !has(allow[i]) {
			if err := insert(allow[i]); err != nil {
				return err
			}
		}
	}
	return nil
}
