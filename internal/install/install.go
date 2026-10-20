package install

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/beekamai/network-scheme/deploy"
	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/keys"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* Image repositories of the services built from this repository. */
const (
	DefaultAPIImage     = "nms/api"
	DefaultGatewayImage = "nms/gateway"
	DefaultAdminUser    = "admin"
)

/* systemdDir receives the audit anchor units. */
const systemdDir = "/etc/systemd/system"

/* anchorUnits are copied from deploy/systemd; the timer is enabled. */
var anchorUnits = []string{"nms-audit-anchor.service", "nms-audit-anchor.timer"}

/* composeUpTimeout bounds "docker compose up --wait" in seconds. */
const composeUpTimeout = "600"

// Options configure an installation.
type Options struct {
	PublicHost              string
	WebCertFile, WebKeyFile string /* empty → self-signed by the internal CA */
	InfraNTP, InfraDNS      []string
	InfraMirror             []string
	AdminUser               string /* DefaultAdminUser when empty */
	AdminPasswordFile       string
	AdminPassword           secret.Secret /* set by the caller after an interactive prompt; else read from AdminPasswordFile */
	TOTPSecretOut           string        /* CI only: file that receives the admin's TOTP secret */
	NonInteractive          bool
	ImageTag                string
	Paths                   Paths
	Root                    string    /* tests only: every host path is resolved under Root */
	Out                     io.Writer /* progress, fingerprints and the admin's QR code */
}

func (o Options) paths() Paths {
	p := o.Paths
	if p.Etc == "" {
		p.Etc = DefaultEtc
	}
	if p.Var == "" {
		p.Var = DefaultVar
	}
	return p
}

/* prepared is everything Run validated before writing anything. */
type prepared struct {
	files    map[string][]byte /* rendered, relative to Etc */
	user     string
	password secret.Secret
	web      SecretsInput
}

/*
Run installs on this host: preflight → validation of every input → secrets →
keys.json for the gateway → rendered compose project → docker compose up and
wait for healthy → first admin with TOTP (in the tools container) → hourly
audit anchor timer → marker Etc/installed → key and certificate fingerprints.
Invalid input fails before anything is written; an existing installation
fails with ErrAlreadyInstalled and nothing is touched.
*/
func Run(ctx context.Context, o Options, sys System) error {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if err := Preflight(o, sys); err != nil {
		return err
	}
	p, err := prepareInstall(o)
	if err != nil {
		return err
	}
	ps := o.paths()
	err = install(ctx, o, sys, p)
	if errors.Is(err, ErrSecretsExist) {
		return err /* someone else's secrets: never suggest deleting them */
	}
	if err != nil {
		return fmt.Errorf("%w\ninstall incomplete: remove %s, %s and the volumes (docker compose -f %s down -v) before retrying",
			err, ps.Etc, ps.Var, path.Join(ps.Etc, "compose.yaml"))
	}
	return nil
}

func prepareInstall(o Options) (prepared, error) {
	ps := o.paths()
	o.PublicHost = strings.ToLower(o.PublicHost)
	files, err := Render(RenderInput{
		PublicHost: o.PublicHost, ImageTag: o.ImageTag,
		APIImage: DefaultAPIImage, GatewayImage: DefaultGatewayImage, Paths: ps,
	})
	if err != nil {
		return prepared{}, fmt.Errorf("install: %w", err)
	}
	infra, err := infraYAML(o)
	if err != nil {
		return prepared{}, err
	}
	files["config/infra.yaml"] = infra

	p := prepared{files: files, web: SecretsInput{PublicHost: o.PublicHost}}
	if p.user, err = auth.NormalizeUsername(cmp.Or(o.AdminUser, DefaultAdminUser)); err != nil {
		return prepared{}, fmt.Errorf("install: admin user: %w", err)
	}
	p.password = o.AdminPassword
	if p.password.IsZero() {
		if o.AdminPasswordFile == "" {
			return prepared{}, errors.New("install: --admin-password-file is required")
		}
		if p.password, err = config.ReadSecretFile(o.AdminPasswordFile); err != nil {
			return prepared{}, fmt.Errorf("install: admin password: %w", err)
		}
	}
	if err := auth.ValidateNewPassword(p.password.Reveal()); err != nil {
		return prepared{}, fmt.Errorf("install: admin password: %w", err)
	}
	if err := checkTOTPOut(o.TOTPSecretOut); err != nil {
		return prepared{}, fmt.Errorf("install: %w", err)
	}
	if (o.WebCertFile == "") != (o.WebKeyFile == "") {
		return prepared{}, errors.New("install: --web-cert and --web-key must be given together")
	}
	if o.WebCertFile != "" {
		if p.web.WebCertPEM, err = os.ReadFile(o.WebCertFile); err != nil {
			return prepared{}, fmt.Errorf("install: %w", err)
		}
		if p.web.WebKeyPEM, err = os.ReadFile(o.WebKeyFile); err != nil {
			return prepared{}, fmt.Errorf("install: %w", err)
		}
	}
	return p, nil
}

/* infraYAML records the customer's internal NTP/DNS/mirror hosts (validated). */
func infraYAML(o Options) ([]byte, error) {
	doc := map[string][]string{"ntp": o.InfraNTP, "dns": o.InfraDNS, "mirror": o.InfraMirror}
	for kind, hosts := range doc {
		for _, h := range hosts {
			if _, err := netip.ParseAddr(h); err != nil && (!hostRe.MatchString(h) || len(h) > 253) {
				return nil, fmt.Errorf("install: infra %s %q is not a host name or IP address", kind, h)
			}
		}
		if hosts == nil {
			doc[kind] = []string{}
		}
	}
	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return append([]byte("# Customer infrastructure this host uses (firewall documentation). Written by nmsctl install.\n"), body...), nil
}

func install(ctx context.Context, o Options, sys System, p prepared) error {
	if err := installHostBinary(o, sys); err != nil {
		return err
	}
	ps := o.paths()
	etc, vr := o.hostPath(ps.Etc), o.hostPath(ps.Var)
	if err := os.MkdirAll(etc, 0o750); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	web := p.web
	web.Chown = sys.Chown
	secretsDir := filepath.Join(etc, "secrets")
	if err := WriteSecrets(secretsDir, web); err != nil {
		return err
	}
	fps, err := writeKeysJSON(secretsDir, filepath.Join(vr, "gateway"))
	if err != nil {
		return err
	}
	if err := writeRendered(etc, p.files); err != nil {
		return err
	}
	anchors := filepath.Join(vr, "anchors")
	if err := os.MkdirAll(anchors, 0o700); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := sys.Chown(anchors, ContainerUID, ContainerUID); err != nil {
		return fmt.Errorf("install: chown %s: %w", anchors, err)
	}

	compose := path.Join(ps.Etc, "compose.yaml")
	if _, err := fmt.Fprintln(o.Out, "Starting services…"); err != nil {
		return err
	}
	up := Cmd{Name: "docker", Args: []string{"compose", "-f", compose, "up", "-d", "--wait", "--wait-timeout", composeUpTimeout}, Stdout: o.Out, Stderr: o.Out}
	if err := sys.Run(ctx, up); err != nil {
		return fmt.Errorf("install: docker compose up: %w", err)
	}
	if err := AdminCreate(ctx, sys, ps.Etc, p.user, p.password, o.TOTPSecretOut, o.Out, o.Out); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := installAnchorTimer(ctx, o, sys); err != nil {
		return err
	}
	if err := writeExcl(o.markerPath(), nil, 0o644); err != nil {
		return err
	}
	return printFingerprints(o.Out, secretsDir, fps)
}

/*
writeRendered writes the rendered project files (0644: containers read them
through bind mounts that keep the host mode). The init script and its
directory, which is bind-mounted and listed by the postgres user, are 0755
whatever the umask.
*/
func writeRendered(etc string, files map[string][]byte) error {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		p := filepath.Join(etc, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		mode := os.FileMode(0o644)
		if n == initDBScript {
			mode = 0o755
			if err := os.Chmod(filepath.Dir(p), 0o755); err != nil { // #nosec G302 -- listed by the postgres user in its container
				return fmt.Errorf("install: %w", err)
			}
		}
		if err := writeExcl(p, files[n], mode); err != nil {
			return err
		}
	}
	return nil
}

/*
writeKeysJSON derives the public domain keys from the private key files and
writes keys.json for the gateway. It returns the fingerprints by domain.
*/
func writeKeysJSON(secretsDir, gatewayDir string) (map[string]string, error) {
	pubs := map[string][32]byte{}
	fps := map[string]string{}
	for d, file := range DomainKeyFiles {
		priv, err := config.ReadKeyFile(filepath.Join(secretsDir, file))
		if err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
		k, err := ecdh.X25519().NewPrivateKey(priv[:])
		if err != nil {
			return nil, fmt.Errorf("install: %s: %w", file, err)
		}
		var pub [32]byte
		copy(pub[:], k.PublicKey().Bytes())
		pubs[d], fps[d] = pub, keys.Fingerprint(pub)
	}
	doc, err := keys.BuildKeysJSON(pubs)
	if err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	if err := os.MkdirAll(gatewayDir, 0o750); err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}
	return fps, writeExcl(filepath.Join(gatewayDir, "keys.json"), doc, 0o644)
}

/*
installHostBinary copies the running nmsctl to HostBinary (root:root, 0755),
where the anchor timer runs it, unless it already runs from there. The copy
is written next to the target and renamed into place.
*/
func installHostBinary(o Options, sys System) (err error) {
	exe, err := sys.Executable()
	if err != nil {
		return fmt.Errorf("install: locate nmsctl: %w", err)
	}
	dst := o.hostPath(HostBinary)
	if a, err := os.Stat(exe); err == nil {
		if b, err := os.Stat(dst); err == nil && os.SameFile(a, b) {
			return nil
		}
	}
	src, err := os.Open(exe) // #nosec G304 -- our own executable
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	defer func() { _ = src.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil { // #nosec G301 -- the standard /usr/local/bin
		return fmt.Errorf("install: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".nmsctl-*")
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	_, cerr := io.Copy(tmp, src)
	if err := errors.Join(cerr, tmp.Chmod(0o755), tmp.Sync(), tmp.Close()); err != nil {
		return fmt.Errorf("install: copy nmsctl: %w", err)
	}
	if err := sys.Chown(tmp.Name(), 0, 0); err != nil {
		return fmt.Errorf("install: chown %s: %w", HostBinary, err)
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	_, err = fmt.Fprintf(o.Out, "Installed nmsctl to %s.\n", HostBinary)
	return err
}

func installAnchorTimer(ctx context.Context, o Options, sys System) error {
	dir := o.hostPath(systemdDir)
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- the standard /etc/systemd/system
		return fmt.Errorf("install: %w", err)
	}
	for _, u := range anchorUnits {
		body, err := deploy.FS.ReadFile("systemd/" + u)
		if err != nil {
			return err
		}
		if err := writeExcl(filepath.Join(dir, u), body, 0o644); err != nil {
			return err
		}
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "nms-audit-anchor.timer"}} {
		if err := sys.Run(ctx, Cmd{Name: "systemctl", Args: args, Stdout: o.Out, Stderr: o.Out}); err != nil {
			return fmt.Errorf("install: systemctl %s: %w", strings.Join(args, " "), err)
		}
	}
	return nil
}

/* printFingerprints shows what the administrator compares in the browser. */
func printFingerprints(out io.Writer, secretsDir string, domains map[string]string) error {
	var b strings.Builder
	b.WriteString("\nInstallation complete.\nDomain key fingerprints (the panel shows the same values from keys.json):\n")
	for _, d := range []string{"read", "write", "backup"} {
		fmt.Fprintf(&b, "  %-7s %s\n", d, domains[d])
	}
	for _, c := range []struct{ label, file string }{{"Web certificate", "web.crt"}, {"Internal CA", "ca.crt"}} {
		fp, err := certFingerprint(filepath.Join(secretsDir, c.file))
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s SHA-256: %s\n", c.label, fp)
	}
	_, err := io.WriteString(out, b.String())
	return err
}

/* certFingerprint returns SHA-256 of the first certificate's DER as colon-separated hex. */
func certFingerprint(file string) (string, error) {
	raw, err := os.ReadFile(file) // #nosec G304 -- installer-owned path
	if err != nil {
		return "", fmt.Errorf("install: %w", err)
	}
	blk, _ := pem.Decode(raw)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return "", fmt.Errorf("install: %s is not a PEM certificate", file)
	}
	sum := sha256.Sum256(blk.Bytes)
	parts := make([]string, len(sum))
	for i, x := range sum {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":"), nil
}
