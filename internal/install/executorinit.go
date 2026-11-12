package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

/* Errors of InitExecutor. */
var (
	ErrNotInstalled        = errors.New("install: not installed (run nmsctl install)")
	ErrExecutorInitialised = errors.New("install: the executor is already initialised")
)

/* initPending is created first and removed last by InitExecutor: while it exists, init may run again to finish. */
const initPending = ".executor-init-pending"

/* backupSuffix is appended to a rendered file InitExecutor replaces; the old content stays there. */
const backupSuffix = ".pre-executor"

/* executorConfig is the rendered file whose presence (without initPending) means the executor is set up. */
const executorConfig = "config/executor.yaml"

/* roleSQL creates nms_executor and sets its password from the secret, read by psql in the postgres container (never in argv). */
const roleSQL = `\set pw ` + "`cat /run/secrets/db_executor_password`" + `
SELECT 'CREATE ROLE nms_executor' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nms_executor') \gexec
SELECT format('ALTER ROLE nms_executor LOGIN PASSWORD %L', :'pw') \gexec
GRANT CONNECT ON DATABASE ` + dbName + ` TO nms_executor;
`

/*
InitExecutor adds the executor to an installation made before it existed
(Phases 0-3): the secrets it lacks (InitSecrets), the project files rendered
again from the current templates (compose.yaml, Caddyfile, api.yaml with
ticket_key_file, executor.yaml, the default policy with enabled: false),
the nms_executor role, then the stack restarted on the new images. The
public host and the core and devices subnets are read from the installation;
o.ImageTag, o.XnetSubnet and o.EdgeSubnet are the operator's. Data is never
touched: secrets that exist are kept (only their owner is corrected), a
rendered file that changes keeps its old content as <file>.pre-executor,
the volumes stay. An interrupted run is finished by running it again; a
completed one, or an installation made with the executor, is refused with
ErrExecutorInitialised.
*/
func InitExecutor(ctx context.Context, o Options, sys System) error {
	if sys.GOOS() != "linux" {
		return ErrNotLinux
	}
	ps := o.paths()
	etc := o.hostPath(ps.Etc)
	if _, err := os.Stat(o.markerPath()); err != nil {
		return fmt.Errorf("%w: %v", ErrNotInstalled, err)
	}
	pending := filepath.Join(etc, initPending)
	_, err := os.Stat(pending)
	resume := err == nil
	if _, err := os.Stat(filepath.Join(etc, filepath.FromSlash(executorConfig))); err == nil && !resume {
		return fmt.Errorf("%w: %s exists", ErrExecutorInitialised, path.Join(ps.Etc, executorConfig))
	}
	if err := recoverInputs(etc, &o); err != nil {
		return err
	}
	in := o.renderInput()
	files, err := Render(in)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	/* The stack holds its other ports; on a resume the gateway may already hold this one. */
	if !resume {
		if o.PortFree != nil {
			if err := o.PortFree("tcp", DefaultExecutorPort); err != nil {
				return fmt.Errorf("%w: %d/tcp (%v); free it for the executor origin and run init again", ErrPortInUse, DefaultExecutorPort, err)
			}
		}
		if err := writeExcl(pending, nil, 0o600); err != nil {
			return err
		}
	}

	if err := InitSecrets(filepath.Join(etc, "secrets"), sys.Chown); err != nil {
		return err
	}
	var replaced []string
	err = writeRendered(etc, files, func(p string, data []byte, mode os.FileMode) error {
		changed, err := updateFile(p, data, mode)
		if changed {
			replaced = append(replaced, p)
		}
		return err
	})
	if err != nil {
		return err
	}

	compose := path.Join(ps.Etc, "compose.yaml")
	docker := func(stdin string, args ...string) error {
		c := Cmd{Name: "docker", Args: append([]string{"compose", "-f", compose}, args...), Stdout: o.Out, Stderr: o.Out}
		if stdin != "" {
			c.Stdin = strings.NewReader(stdin)
		}
		if err := sys.Run(ctx, c); err != nil {
			return fmt.Errorf("install: docker compose %s: %w (fix it and run nmsctl executor init again)", args[0], err)
		}
		return nil
	}
	if _, err := fmt.Fprintln(o.Out, "Restarting services with the executor…"); err != nil {
		return err
	}
	/*
	 * down first: the edge network gets a fixed subnet, which Docker cannot change on an existing network.
	 * Volumes stay. Postgres alone next, with the new secret mounted, for the role the migrations grant to.
	 */
	if err := docker("", "down"); err != nil {
		return err
	}
	if err := docker("", "up", "-d", "--wait", "--wait-timeout", composeUpTimeout, "postgres"); err != nil {
		return err
	}
	if err := docker(roleSQL, "exec", "-T", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", dbName); err != nil {
		return err
	}
	if err := docker("", "up", "-d", "--wait", "--wait-timeout", composeUpTimeout); err != nil {
		return err
	}
	if err := os.Remove(pending); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	var b strings.Builder
	b.WriteString("\nExecutor initialised; its policy keeps it disabled (nmsctl executor enable).\n")
	for _, p := range replaced {
		fmt.Fprintf(&b, "  replaced %s (previous content: %s%s)\n", p, filepath.Base(p), backupSuffix)
	}
	_, err = fmt.Fprint(o.Out, b.String())
	return err
}

/* recoverInputs reads the public host and the core and devices subnets the installation was rendered with. */
func recoverInputs(etc string, o *Options) error {
	var api struct {
		PublicOrigin string `yaml:"public_origin"`
	}
	if err := readYAML(filepath.Join(etc, "config", "api.yaml"), &api); err != nil {
		return err
	}
	u, err := url.Parse(api.PublicOrigin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || (u.Port() != "" && u.Port() != "443") {
		return fmt.Errorf("install: api.yaml: public_origin %q is not https://HOST", api.PublicOrigin)
	}
	var compose struct {
		Networks map[string]struct {
			IPAM struct {
				Config []struct {
					Subnet string `yaml:"subnet"`
				} `yaml:"config"`
			} `yaml:"ipam"`
		} `yaml:"networks"`
	}
	if err := readYAML(filepath.Join(etc, "compose.yaml"), &compose); err != nil {
		return err
	}
	subnet := func(name string) (string, error) {
		if c := compose.Networks[name].IPAM.Config; len(c) == 1 && c[0].Subnet != "" {
			return c[0].Subnet, nil
		}
		return "", fmt.Errorf("install: compose.yaml has no %s network subnet: the installation predates the poller (Phase 1b) and cannot take the executor", name)
	}
	o.PublicHost = u.Hostname()
	if o.CoreSubnet, err = subnet("core"); err != nil {
		return err
	}
	o.DevicesSubnet, err = subnet("devices")
	return err
}

func readYAML(p string, v any) error {
	raw, err := os.ReadFile(p) // #nosec G304 -- a file of the installation
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := yaml.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("install: %s: %w", p, err)
	}
	return nil
}

/*
updateFile writes a rendered file: created when missing, left as is when
equal, else its old content goes to p+backupSuffix (kept from an earlier
run) and the new one replaces it atomically. It reports a replacement.
*/
func updateFile(p string, data []byte, mode os.FileMode) (bool, error) {
	old, err := os.ReadFile(p) // #nosec G304 -- a file of the installation
	switch {
	case errors.Is(err, os.ErrNotExist):
		return false, writeExcl(p, data, mode)
	case err != nil:
		return false, fmt.Errorf("install: %w", err)
	case bytes.Equal(old, data):
		return false, nil
	}
	if err := writeExcl(p+backupSuffix, old, 0o600); err != nil && !errors.Is(err, os.ErrExist) {
		return false, err
	}
	if err := ReplaceFile(p, data); err != nil {
		return false, fmt.Errorf("install: %w", err)
	}
	return true, os.Chmod(p, mode)
}

/*
InitSecrets adds the executor's secrets (executorSecrets, issued by the CA
in dir) to the secrets directory of an installation made before the
executor: a missing secret, or a pair of which a half is missing (an
interrupted run), is written (temporary file, owner, rename); a present one
is kept and only given the owner and mode a new installation has. The
write and backup domain keys and the CA must exist: keys.json was built
from them.
*/
func InitSecrets(dir string, chown func(path string, uid, gid int) error) error {
	caCrt, err := os.ReadFile(filepath.Join(dir, "ca.crt")) // #nosec G304 -- the installation's secrets
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	caKey, err := os.ReadFile(filepath.Join(dir, "ca.key")) // #nosec G304 -- the installation's secrets
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	files, err := executorSecrets(caCrt, caKey)
	if err != nil {
		return err
	}
	/* Owned by root or 0400 before the executor existed. */
	keep := []secretFile{
		{name: DomainKeyFiles["write"], uid: ExecutorUID, gid: ExecutorUID, mode: 0o400},
		{name: DomainKeyFiles["backup"], uid: ExecutorUID, gid: ExecutorUID, mode: 0o400},
		{name: "ca.crt", mode: 0o444},
	}
	/* A pair (ticket.key/.pub, *.crt/.key) shares the stem: both halves are kept or both written. */
	complete := map[string]bool{}
	for _, f := range files {
		stem := strings.SplitN(f.name, ".", 2)[0]
		_, err := os.Lstat(filepath.Join(dir, f.name))
		prev, seen := complete[stem]
		complete[stem] = err == nil && (prev || !seen)
	}
	for _, f := range files {
		if complete[strings.SplitN(f.name, ".", 2)[0]] {
			keep = append(keep, f)
			continue
		}
		p, tmp := filepath.Join(dir, f.name), filepath.Join(dir, ".init-"+f.name)
		_ = os.Remove(tmp)
		if err := writeExcl(tmp, f.data, f.mode); err != nil {
			return err
		}
		if err := chown(tmp, f.uid, f.gid); err != nil {
			return fmt.Errorf("install: chown %s: %w", f.name, err)
		}
		if err := os.Rename(tmp, p); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}
	for _, f := range keep {
		p := filepath.Join(dir, f.name)
		if err := chown(p, f.uid, f.gid); err != nil {
			return fmt.Errorf("install: chown %s: %w", f.name, err)
		}
		if err := os.Chmod(p, f.mode); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}
	return nil
}
