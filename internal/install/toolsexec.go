package install

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/beekamai/network-scheme/internal/secret"
)

/*
TOTPSecretLinePrefix starts the line on which "nmsctl admin create" prints the
TOTP secret for manual entry; the host side reads it for --totp-secret-out.
*/
const TOTPSecretLinePrefix = "TOTP secret (manual entry): "

/* HostBinary is where the systemd anchor unit expects nmsctl on the host. */
const HostBinary = "/usr/local/bin/nmsctl"

/* allowedCommands are the only programs OSSystem.Run starts. */
var allowedCommands = map[string]bool{"docker": true, "systemctl": true}

// OSSystem is the real System: it shells out to docker and systemctl with fixed argv.
type OSSystem struct{}

// GOOS returns runtime.GOOS.
func (OSSystem) GOOS() string { return runtime.GOOS }

// InContainer reports whether the process runs in a Docker container (/.dockerenv exists).
func (OSSystem) InContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// DockerServerVersion returns the Docker Engine (server) version, e.g. "24.0.7".
func (s OSSystem) DockerServerVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := s.Run(ctx, Cmd{Name: "docker", Args: []string{"version", "--format", "{{.Server.Version}}"}, Stdout: &out, Stderr: io.Discard})
	return strings.TrimSpace(out.String()), err
}

// Chown changes the numeric owner of path.
func (OSSystem) Chown(path string, uid, gid int) error { return os.Lchown(path, uid, gid) }

// Executable returns the path of the running binary.
func (OSSystem) Executable() (string, error) { return os.Executable() }

// Run starts docker or systemctl directly (no shell) and waits for it.
func (OSSystem) Run(ctx context.Context, c Cmd) error {
	if !allowedCommands[c.Name] {
		return fmt.Errorf("install: command %q is not allowed", c.Name)
	}
	cmd := exec.CommandContext(ctx, c.Name, c.Args...) // #nosec G204 -- name from a fixed allowlist, argv without a shell
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	return cmd.Run()
}

/*
RunInTools runs "nmsctl args..." in the one-shot tools container of the
compose project in etc (docker compose --profile tools run --rm --no-deps -T
nmsctl). Database commands always go this way: only that container sees the
core network and the nms_cli secret. stdin is the container's whole input
(no TTY), so prompts happen on the host before the call.
*/
func RunInTools(ctx context.Context, sys System, etc string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	argv := append([]string{
		"compose", "-f", path.Join(etc, "compose.yaml"), "--profile", "tools",
		"run", "--rm", "--no-deps", "-T", "nmsctl",
	}, args...)
	return sys.Run(ctx, Cmd{Name: "docker", Args: argv, Stdin: stdin, Stdout: stdout, Stderr: stderr})
}

/*
AdminCreate runs "nmsctl admin create" in the tools container, handing it the
already validated password on stdin. With totpOut set (CI only), the TOTP
secret printed by the container is also written to totpOut (0600, never
overwritten) and a warning is printed.
*/
func AdminCreate(ctx context.Context, sys System, etc, user string, pw secret.Secret, totpOut string, out, errw io.Writer) error {
	if err := checkTOTPOut(totpOut); err != nil {
		return err
	}
	var captured bytes.Buffer
	w := out
	if totpOut != "" {
		w = io.MultiWriter(out, &captured)
	}
	args := []string{"admin", "create", "--user", user, "--password-file", "-"}
	if err := RunInTools(ctx, sys, etc, args, strings.NewReader(pw.Reveal()+"\n"), w, errw); err != nil {
		return fmt.Errorf("admin create: %w", err)
	}
	if totpOut == "" {
		return nil
	}
	sc := bufio.NewScanner(&captured)
	for sc.Scan() {
		if s, ok := strings.CutPrefix(sc.Text(), TOTPSecretLinePrefix); ok {
			if err := writeExcl(totpOut, []byte(strings.TrimSpace(s)+"\n"), 0o600); err != nil {
				return err
			}
			_, err := fmt.Fprintf(out, "WARNING: the TOTP secret of %s was written to %s (--totp-secret-out is for CI only); delete it after use.\n", user, totpOut)
			return err
		}
	}
	return errors.New("admin create: no TOTP secret in the output")
}

/*
checkTOTPOut fails unless totpOut is empty or a not yet existing file in an
existing directory, so a bad path is rejected before the admin is created.
*/
func checkTOTPOut(totpOut string) error {
	if totpOut == "" {
		return nil
	}
	if _, err := os.Lstat(totpOut); err == nil {
		return fmt.Errorf("--totp-secret-out %s: must not exist", totpOut)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--totp-secret-out: %w", err)
	}
	if st, err := os.Stat(filepath.Dir(totpOut)); err != nil || !st.IsDir() {
		return fmt.Errorf("--totp-secret-out %s: parent directory does not exist", totpOut)
	}
	return nil
}
