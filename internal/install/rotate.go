package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

/*
Key rotation on the host (nmsctl keys rotate, nmsctl executor key rotate):
the new secret is first staged next to the live one as NAME.next (created
exclusively, owned by its consumer, synced), so a rotation interrupted at
any point is resumed from it; it then replaces the live file by rename
(PromoteSecret), which the consumer reads at its next start. The old file
is gone once the rename is durable.
*/

/* NextSuffix names a staged secret. */
const NextSuffix = ".next"

/* SecretsDir is the secrets directory of an install in etc. */
func SecretsDir(etc string) string { return filepath.Join(etc, "secrets") }

/* StageSecret writes data as the staged secret of p (p.next, mode 0400, owned by uid), durably; an existing p.next is an error. */
func StageSecret(p string, data []byte, uid int, chown func(path string, uid, gid int) error) error {
	n := p + NextSuffix
	if err := writeExcl(n, data, 0o400); err != nil {
		return err
	}
	if err := chown(n, uid, uid); err != nil {
		_ = os.Remove(n)
		return fmt.Errorf("install: chown %s: %w", n, err)
	}
	return syncDir(filepath.Dir(p))
}

/* PromoteSecret replaces p with its staged secret (rename, then a directory sync). */
func PromoteSecret(p string) error {
	if runtime.GOOS == "windows" {
		_ = os.Chmod(p, 0o600) /* development only: a read-only file cannot be renamed over there */
	}
	if err := os.Rename(p+NextSuffix, p); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return syncDir(filepath.Dir(p))
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil /* development only: a directory cannot be synced there */
	}
	d, err := os.Open(dir) // #nosec G304 -- a directory nmsctl manages
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	return errors.Join(d.Sync(), d.Close())
}

/* Compose runs docker compose on the project in etc with args (stop, up -d, restart …). */
func Compose(ctx context.Context, sys System, etc string, out io.Writer, args ...string) error {
	return sys.Run(ctx, Cmd{Name: "docker", Args: append([]string{"compose", "-f", path.Join(etc, "compose.yaml")}, args...),
		Stdout: out, Stderr: out})
}

/*
RunExecutorOnce runs "executor args…" in a one-shot container of the
executor service (docker compose run --rm --no-deps -T executor): its
image, user, secrets and state volume, the daemon stopped. Secrets go on
stdin, never in argv.
*/
func RunExecutorOnce(ctx context.Context, sys System, etc string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	argv := append([]string{"compose", "-f", path.Join(etc, "compose.yaml"), "run", "--rm", "--no-deps", "-T", "executor"}, args...)
	return sys.Run(ctx, Cmd{Name: "docker", Args: argv, Stdin: stdin, Stdout: stdout, Stderr: stderr})
}
