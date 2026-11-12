// Package install renders and installs the compose deployment on a host.
package install

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/beekamai/network-scheme/deploy"
	"github.com/beekamai/network-scheme/internal/keys"
)

/*
DefaultDBImage is the database image: TimescaleDB 2.30.2 on PostgreSQL 17,
pinned by digest (the same reference the database tests run against).
*/
const DefaultDBImage = "timescale/timescaledb:2.30.2-pg17@sha256:b346edcdb51a1fd6020e3965e0bd1c9f3406fa6d5fbce1e28f4852587ef934e2"

/* Defaults applied by Render to zero-valued RenderInput fields. */
const (
	DefaultHTTPSPort  = 443
	DefaultCoreSubnet = "172.30.0.0/24"
	/* DefaultDevicesSubnet is the poller's network towards the devices (egress-filtered, not internal). */
	DefaultDevicesSubnet = "172.30.1.0/24"
	DefaultEtc           = "/etc/nms"
	DefaultVar           = "/var/lib/nms"

	/* DefaultExecutorPort is the host port of the executor origin (gateway, then xnet to the executor). */
	DefaultExecutorPort = 8443
	/* DefaultXnetSubnet is the internal network between the gateway and the executor only. */
	DefaultXnetSubnet = "172.30.2.0/24"
	/* DefaultEdgeSubnet is the gateway's routed network for the published ports; the executor origin listens only on its address there. */
	DefaultEdgeSubnet = "172.30.3.0/24"
)

/* dbName is the application database. */
const dbName = "nms"

/* initDBScript is shipped as-is next to compose.yaml and mounted into postgres. */
const initDBScript = "postgres/initdb/10-roles.sh"

// Paths are the host directories of an installation.
type Paths struct {
	Etc string /* /etc/nms: compose.yaml, Caddyfile, config/, secrets/ */
	Var string /* /var/lib/nms: gateway/keys.json, anchors/ */
}

// RenderInput parameterizes the deployment templates. Zero values take the defaults above.
type RenderInput struct {
	PublicHost   string /* DNS name (or IPv4) the browser uses for the panel */
	HTTPSPort    int    /* host port published for the panel, 443 */
	ImageTag     string /* tag of the api and gateway images */
	APIImage     string /* repository of the api image, without tag */
	GatewayImage string /* repository of the gateway image, without tag */
	DBImage      string /* full database image reference; DefaultDBImage */
	CoreSubnet   string /* IPv4 subnet of the internal core network */
	GatewayIP    string /* static gateway address in CoreSubnet; second host address by default */
	/* DevicesSubnet is the IPv4 subnet of the devices network; must not overlap CoreSubnet. */
	DevicesSubnet string
	Paths         Paths

	ExecutorImage string /* repository of the executor image, without tag; DefaultExecutorImage */
	ExecutorPort  int    /* host port of the executor origin; must differ from HTTPSPort */
	/* XnetSubnet is the IPv4 subnet of xnet; must overlap neither CoreSubnet nor DevicesSubnet. */
	XnetSubnet string
	/* EdgeSubnet is the IPv4 subnet of edge (published ports); must overlap none of the other three. */
	EdgeSubnet string
}

/* view is what the templates see: validated, defaulted, derived values. */
type view struct {
	RenderInput
	Authority      string /* host[:port] of the public origin */
	CoreIPRange    string /* upper half of CoreSubnet: dynamic addresses never collide with GatewayIP */
	DBName         string
	APIListenPort  int
	ReadKeyVersion int /* key_version of the read domain in keys.json written by the install */

	ExecutorAuthority string /* host[:port] of the executor origin */
	/* ExecutorIP is the static executor address in xnet (second host address), the only one it listens on. */
	ExecutorIP         string
	XnetIPRange        string /* upper half of XnetSubnet, as CoreIPRange */
	ExecutorListenPort int    /* port of the executor's xnet listener */
	/* GatewayEdgeIP is the gateway's static address in edge (second host address): the only address the executor origin listens on. */
	GatewayEdgeIP string
	EdgeIPRange   string /* upper half of EdgeSubnet */
}

var (
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	tagRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	repoRe  = regexp.MustCompile(`^([a-z0-9.-]+(:[0-9]{1,5})?/)?[a-z0-9]+([._/-][a-z0-9]+)*$`)
	imageRe = regexp.MustCompile(`^([a-z0-9.-]+(:[0-9]{1,5})?/)?[a-z0-9]+([._/-][a-z0-9]+)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)
	pathRe  = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)
)

/*
reservedHosts are the compose service names: inside the stack they resolve
to the services (and the internal certificates are issued for some), so the
public host is never one of them. localhost stays allowed (demo stand).
*/
var reservedHosts = map[string]bool{"postgres": true, "migrate": true, "api": true, "poller": true, "eventd": true,
	"executor": true, "gateway": true, "nmsctl": true}

var templates = template.Must(template.New("").Option("missingkey=error").ParseFS(deploy.FS, "templates/*.tmpl"))

/* outputs maps rendered file names (relative to Paths.Etc) to templates. */
var outputs = map[string]string{
	"compose.yaml":       "compose.yaml.tmpl",
	"Caddyfile":          "Caddyfile.tmpl",
	"config/api.yaml":    "api.yaml.tmpl",
	"config/poller.yaml": "poller.yaml.tmpl",
	"config/eventd.yaml": "eventd.yaml.tmpl",

	"config/executor.yaml": "executor.yaml.tmpl",
	/* Mounted read-only into the executor; changed only on the host. */
	"policies/executor.yaml": "executor-policy.yaml.tmpl",
}

/*
Render validates in and renders the deployment files, keyed by path relative
to Paths.Etc: "compose.yaml", "Caddyfile", "config/{api,poller,eventd,executor}.yaml", "policies/executor.yaml" and the postgres
init script "postgres/initdb/10-roles.sh" (to be written with mode 0755).
Every value reaching a template is validated against a strict pattern, so
input cannot inject YAML keys or Caddy directives. Output is deterministic.
*/
func Render(in RenderInput) (map[string][]byte, error) {
	v, err := prepare(in)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(outputs)+1)
	for name, tmpl := range outputs {
		var buf bytes.Buffer
		if err := templates.ExecuteTemplate(&buf, tmpl, v); err != nil {
			return nil, fmt.Errorf("render %s: %w", name, err)
		}
		out[name] = buf.Bytes()
	}
	script, err := deploy.FS.ReadFile(initDBScript)
	if err != nil {
		return nil, err
	}
	out[initDBScript] = script
	return out, nil
}

func prepare(in RenderInput) (view, error) {
	if in.HTTPSPort == 0 {
		in.HTTPSPort = DefaultHTTPSPort
	}
	if in.ExecutorPort == 0 {
		in.ExecutorPort = DefaultExecutorPort
	}
	if in.ExecutorImage == "" {
		in.ExecutorImage = DefaultExecutorImage
	}
	if in.DBImage == "" {
		in.DBImage = DefaultDBImage
	}
	if in.CoreSubnet == "" {
		in.CoreSubnet = DefaultCoreSubnet
	}
	if in.DevicesSubnet == "" {
		in.DevicesSubnet = DefaultDevicesSubnet
	}
	if in.XnetSubnet == "" {
		in.XnetSubnet = DefaultXnetSubnet
	}
	if in.EdgeSubnet == "" {
		in.EdgeSubnet = DefaultEdgeSubnet
	}
	if in.Paths.Etc == "" {
		in.Paths.Etc = DefaultEtc
	}
	if in.Paths.Var == "" {
		in.Paths.Var = DefaultVar
	}

	/* Browsers send the host lowercased in Origin; keep every rendered file identical to that. */
	in.PublicHost = strings.ToLower(in.PublicHost)
	switch {
	case !hostRe.MatchString(in.PublicHost) || len(in.PublicHost) > 253:
		return view{}, fmt.Errorf("public host %q is not a valid DNS name or IPv4 address", in.PublicHost)
	case reservedHosts[in.PublicHost]:
		return view{}, fmt.Errorf("public host %q is the name of an internal service", in.PublicHost)
	case in.HTTPSPort < 1 || in.HTTPSPort > 65535:
		return view{}, fmt.Errorf("https port %d out of range", in.HTTPSPort)
	case in.ExecutorPort < 1 || in.ExecutorPort > 65535:
		return view{}, fmt.Errorf("executor port %d out of range", in.ExecutorPort)
	case in.ExecutorPort == in.HTTPSPort:
		return view{}, fmt.Errorf("executor port %d must differ from the https port: the executor is a separate origin", in.ExecutorPort)
	case !tagRe.MatchString(in.ImageTag):
		return view{}, fmt.Errorf("image tag %q is invalid", in.ImageTag)
	}
	for name, repo := range map[string]string{"api": in.APIImage, "gateway": in.GatewayImage, "executor": in.ExecutorImage} {
		if !repoRe.MatchString(repo) {
			return view{}, fmt.Errorf("%s image %q must be a repository without tag or digest", name, repo)
		}
	}
	if !imageRe.MatchString(in.DBImage) {
		return view{}, fmt.Errorf("db image %q is invalid", in.DBImage)
	}
	for name, p := range map[string]string{"etc": in.Paths.Etc, "var": in.Paths.Var} {
		if !pathRe.MatchString(p) || path.Clean(p) != p {
			return view{}, fmt.Errorf("%s path %q must be a clean absolute path", name, p)
		}
	}

	subnet, err := parseSubnet("core", in.CoreSubnet)
	if err != nil {
		return view{}, err
	}
	devs, err := parseSubnet("devices", in.DevicesSubnet)
	if err != nil {
		return view{}, err
	}
	if devs.Overlaps(subnet) {
		return view{}, fmt.Errorf("devices subnet %s (--devices-subnet) overlaps the core subnet %s (--core-subnet)", devs, subnet)
	}
	xnet, err := parseSubnet("xnet", in.XnetSubnet)
	if err != nil {
		return view{}, err
	}
	if xnet.Overlaps(subnet) || xnet.Overlaps(devs) {
		return view{}, fmt.Errorf("xnet subnet %s (--xnet-subnet) overlaps the core subnet %s (--core-subnet) or the devices subnet %s (--devices-subnet)", xnet, subnet, devs)
	}
	edge, err := parseSubnet("edge", in.EdgeSubnet)
	if err != nil {
		return view{}, err
	}
	if edge.Overlaps(subnet) || edge.Overlaps(devs) || edge.Overlaps(xnet) {
		return view{}, fmt.Errorf("edge subnet %s (--edge-subnet) overlaps the core %s, devices %s or xnet %s subnet", edge, subnet, devs, xnet)
	}
	in.CoreSubnet, in.DevicesSubnet, in.XnetSubnet, in.EdgeSubnet = subnet.String(), devs.String(), xnet.String(), edge.String()
	ipRange := netip.PrefixFrom(upperHalf(subnet), subnet.Bits()+1)
	if in.GatewayIP == "" {
		in.GatewayIP = subnet.Addr().Next().Next().String()
	}
	gw, err := netip.ParseAddr(in.GatewayIP)
	if err != nil {
		return view{}, fmt.Errorf("gateway ip: %w", err)
	}
	/* Docker takes the first host address for the bridge itself. */
	if !subnet.Contains(gw) || ipRange.Contains(gw) || gw == subnet.Addr() || gw == subnet.Addr().Next() {
		return view{}, errors.New("gateway ip must be a host address in the lower half of the core subnet, above .1")
	}
	in.GatewayIP = gw.String()

	authority, exAuthority := in.PublicHost, in.PublicHost
	if in.HTTPSPort != DefaultHTTPSPort {
		authority += ":" + strconv.Itoa(in.HTTPSPort)
	}
	if in.ExecutorPort != DefaultHTTPSPort {
		exAuthority += ":" + strconv.Itoa(in.ExecutorPort)
	}
	return view{RenderInput: in, Authority: authority, CoreIPRange: ipRange.String(), DBName: dbName, APIListenPort: 8080,
		ReadKeyVersion: keys.InitialKeyVersion, ExecutorAuthority: exAuthority, ExecutorIP: xnet.Addr().Next().Next().String(),
		XnetIPRange: netip.PrefixFrom(upperHalf(xnet), xnet.Bits()+1).String(), ExecutorListenPort: 8444,
		GatewayEdgeIP: edge.Addr().Next().Next().String(), EdgeIPRange: netip.PrefixFrom(upperHalf(edge), edge.Bits()+1).String()}, nil
}

/* parseSubnet accepts an IPv4 network address with a /16../28 prefix. */
func parseSubnet(name, s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("%s subnet %q must be an IPv4 network address with prefix", name, s)
	}
	if p.Bits() < 16 || p.Bits() > 28 {
		return netip.Prefix{}, fmt.Errorf("%s subnet %s: prefix must be /16../28", name, p)
	}
	return p, nil
}

/* upperHalf returns the first address of the upper half of p: the first host bit set. */
func upperHalf(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	b := p.Bits()
	a[b/8] |= 0x80 >> (b % 8)
	return netip.AddrFrom4(a)
}
