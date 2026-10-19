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
	"text/template"

	"github.com/beekamai/network-scheme/deploy"
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
	DefaultEtc        = "/etc/nms"
	DefaultVar        = "/var/lib/nms"
)

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
	Paths        Paths
}

/* view is what the templates see: validated, defaulted, derived values. */
type view struct {
	RenderInput
	Authority     string /* host[:port] of the public origin */
	CoreIPRange   string /* upper half of CoreSubnet: dynamic addresses never collide with GatewayIP */
	DBName        string
	APIListenPort int
}

var (
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
	tagRe   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	repoRe  = regexp.MustCompile(`^([a-z0-9.-]+(:[0-9]{1,5})?/)?[a-z0-9]+([._/-][a-z0-9]+)*$`)
	imageRe = regexp.MustCompile(`^([a-z0-9.-]+(:[0-9]{1,5})?/)?[a-z0-9]+([._/-][a-z0-9]+)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)
	pathRe  = regexp.MustCompile(`^/[A-Za-z0-9._/-]*$`)
)

var templates = template.Must(template.New("").Option("missingkey=error").ParseFS(deploy.FS, "templates/*.tmpl"))

/* outputs maps rendered file names (relative to Paths.Etc) to templates. */
var outputs = map[string]string{
	"compose.yaml":    "compose.yaml.tmpl",
	"Caddyfile":       "Caddyfile.tmpl",
	"config/api.yaml": "api.yaml.tmpl",
}

/*
Render validates in and renders the deployment files, keyed by path relative
to Paths.Etc: "compose.yaml", "Caddyfile", "config/api.yaml" and the postgres
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
	if in.DBImage == "" {
		in.DBImage = DefaultDBImage
	}
	if in.CoreSubnet == "" {
		in.CoreSubnet = DefaultCoreSubnet
	}
	if in.Paths.Etc == "" {
		in.Paths.Etc = DefaultEtc
	}
	if in.Paths.Var == "" {
		in.Paths.Var = DefaultVar
	}

	switch {
	case !hostRe.MatchString(in.PublicHost) || len(in.PublicHost) > 253:
		return view{}, fmt.Errorf("public host %q is not a valid DNS name or IPv4 address", in.PublicHost)
	case in.HTTPSPort < 1 || in.HTTPSPort > 65535:
		return view{}, fmt.Errorf("https port %d out of range", in.HTTPSPort)
	case !tagRe.MatchString(in.ImageTag):
		return view{}, fmt.Errorf("image tag %q is invalid", in.ImageTag)
	}
	for name, repo := range map[string]string{"api": in.APIImage, "gateway": in.GatewayImage} {
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

	subnet, err := netip.ParsePrefix(in.CoreSubnet)
	if err != nil || !subnet.Addr().Is4() || subnet != subnet.Masked() {
		return view{}, fmt.Errorf("core subnet %q must be an IPv4 network address with prefix", in.CoreSubnet)
	}
	if subnet.Bits() < 16 || subnet.Bits() > 28 {
		return view{}, fmt.Errorf("core subnet %s: prefix must be /16../28", subnet)
	}
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

	authority := in.PublicHost
	if in.HTTPSPort != DefaultHTTPSPort {
		authority += ":" + strconv.Itoa(in.HTTPSPort)
	}
	return view{RenderInput: in, Authority: authority, CoreIPRange: ipRange.String(), DBName: "nms", APIListenPort: 8080}, nil
}

/* upperHalf returns the first address of the upper half of p: the first host bit set. */
func upperHalf(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	b := p.Bits()
	a[b/8] |= 0x80 >> (b % 8)
	return netip.AddrFrom4(a)
}
