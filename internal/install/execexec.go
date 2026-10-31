package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
)

/* PolicyFile is the executor's policy relative to the install directory (mounted as its directory, read-only). */
const PolicyFile = "policies/executor.yaml"

/*
RunInExecutor runs "executor admin" in the running executor container of
the compose project in etc (docker compose exec -T executor /executor
admin), as the container's own user, which is what the daemon's socket
accepts (SO_PEERCRED). The one request line goes on stdin, never in argv;
the response line comes back on stdout. nmsctl links nothing of the
executor: this is its only way in (security.md 4, TB6).
*/
func RunInExecutor(ctx context.Context, sys System, etc string, request []byte, stdout, stderr io.Writer) error {
	argv := []string{"compose", "-f", path.Join(etc, "compose.yaml"), "exec", "-T", "executor", "/executor", "admin"}
	return sys.Run(ctx, Cmd{Name: "docker", Args: argv, Stdin: bytes.NewReader(request), Stdout: stdout, Stderr: stderr})
}

/*
ReplaceFile replaces the file at p with data atomically and durably: a
temporary file in the same directory (mode 0644, as installed), fsync,
rename over p, directory fsync. A reader (the executor rereading its policy
by mtime) sees the old file or the new one, never a part.
*/
func ReplaceFile(p string, data []byte) error {
	dir := filepath.Dir(p)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(p)+".")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() /* no-op after the rename */
	_, werr := tmp.Write(data)
	if err := errors.Join(werr, tmp.Chmod(0o644), tmp.Sync(), tmp.Close()); err != nil {
		return fmt.Errorf("write %s: %w", p, err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil /* development only: a directory cannot be synced there */
	}
	d, err := os.Open(dir) // #nosec G304 -- the directory of a file nmsctl manages
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
