package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

/* Preflight errors. */
var (
	ErrNotLinux         = errors.New("install: only Linux hosts are supported")
	ErrDockerTooOld     = errors.New("install: Docker Engine 24 or newer is required")
	ErrUserlandProxy    = errors.New("install: docker userland-proxy must be disabled")
	ErrDockerFirewall   = errors.New("install: docker must manage iptables (the egress rules live in DOCKER-USER)")
	ErrAlreadyInstalled = errors.New("install: already installed")
)

/* minDockerMajor is the oldest supported Docker Engine major version. */
const minDockerMajor = 24

/* daemonJSON is the Docker daemon configuration file checked by Preflight. */
const daemonJSON = "/etc/docker/daemon.json"

// Cmd is an external command with a fixed argv; it is never run through a shell.
type Cmd struct {
	Name   string /* "docker", "systemctl" or "iptables" */
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

/*
System is the part of the host that install and nmsctl touch besides plain
files under Options.Root: OS identity, Docker, ownership and external
commands. Tests substitute a fake; OSSystem is the real implementation.
*/
type System interface {
	GOOS() string
	InContainer() bool
	DockerServerVersion() (string, error)
	Chown(path string, uid, gid int) error
	Run(ctx context.Context, c Cmd) error
	/* Executable is the path of the running nmsctl binary. */
	Executable() (string, error)
}

/* hostPath maps an absolute host path into o.Root (empty Root: the path itself). */
func (o Options) hostPath(p string) string {
	if o.Root == "" {
		return p
	}
	return filepath.Join(o.Root, filepath.FromSlash(p))
}

/* markerPath is the file whose presence means a completed installation. */
func (o Options) markerPath() string {
	return o.hostPath(o.paths().Etc + "/installed")
}

/*
Preflight checks that the host can take an installation: Linux, Docker
Engine >= 24, userland-proxy disabled in /etc/docker/daemon.json (so that
published ports keep the client's source address), Docker's iptables firewall
not disabled or replaced (the egress rules live in DOCKER-USER), and no
previous install.
*/
func Preflight(o Options, sys System) error {
	if sys.GOOS() != "linux" {
		return ErrNotLinux
	}
	v, err := sys.DockerServerVersion()
	if err != nil {
		return fmt.Errorf("install: docker version: %w", err)
	}
	major, err := strconv.Atoi(strings.SplitN(strings.TrimSpace(v), ".", 2)[0])
	if err != nil || major < minDockerMajor {
		return fmt.Errorf("%w (found %q)", ErrDockerTooOld, v)
	}
	if err := checkDaemonJSON(o.hostPath(daemonJSON)); err != nil {
		return err
	}
	if _, err := os.Lstat(o.markerPath()); err == nil {
		return fmt.Errorf("%w: %s exists; secrets are never regenerated", ErrAlreadyInstalled, o.paths().Etc+"/installed")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

func checkDaemonJSON(path string) error {
	fix := fmt.Errorf(`%w: add "userland-proxy": false to %s (e.g. {"userland-proxy": false}) and restart docker`, ErrUserlandProxy, daemonJSON)
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed system path
	if errors.Is(err, os.ErrNotExist) {
		return fix
	}
	if err != nil {
		return fmt.Errorf("install: read %s: %w", daemonJSON, err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("%w; %s is not valid JSON: %v", fix, daemonJSON, err)
	}
	if v, ok := cfg["userland-proxy"].(bool); !ok || v {
		return fix
	}
	if v, ok := cfg["iptables"]; ok && v != true {
		return fmt.Errorf(`%w: remove "iptables" from %s or set "iptables": true, and restart docker`, ErrDockerFirewall, daemonJSON)
	}
	if v, ok := cfg["firewall-backend"]; ok && v != "iptables" {
		return fmt.Errorf(`%w: remove "firewall-backend" from %s or set "firewall-backend": "iptables", and restart docker`, ErrDockerFirewall, daemonJSON)
	}
	return nil
}
