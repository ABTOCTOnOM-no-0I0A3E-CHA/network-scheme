package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/sysbackup"
)

/*
nmsctl backup and nmsctl restore run on the host, as root (they read the
install directory, run docker and, on restore, set up the host as install
does).

Consistency with the executor: the executor is the only writer of the exec
schema and of its state volume, and each registry change is one database
transaction between two writes of the state file (pending before COMMIT,
committed after). backup stops the executor container (docker compose stop
lets it finish: the state file is final), copies its state directory
(docker cp reads a stopped container's volume), takes the pg_dump (one
snapshot) and starts the executor again. The state file and the exec schema
are then of the same point, so after a restore the executor's hwm,
state_hash and audit head match the restored schema: the registry
verifies (the restored executor is still frozen on purpose, restoredMarker). A state file still holding a pending record (the
executor died inside a change) is refused: that record names a transaction
of this database cluster, which a restored cluster does not know; the
executor settles it at its next start. Only the executor stops; the panel
keeps running, and its audit anchors are copied before the dump, so every
anchor names an event the dump holds.
*/

/* Install and data directories on the host, and install's Options.Root; tests point them elsewhere. */
var (
	etcDir, varDir = install.DefaultEtc, install.DefaultVar
	hostRoot       = ""
)

/* identityFile is the backup identity, relative to etcDir (so it travels in the keys archive). */
const identityFile = "secrets/backup_age.key" // #nosec G101 -- path of a secret file, not a secret

/* varFiles are the host files of varDir a data archive carries. */
var varFiles = []string{"anchors/anchors.log", "gateway/keys.json"}

/* executorStateDir is the executor's state volume inside its container. */
const executorStateDir = "/var/lib/executor"

var containerRe = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

/* stack runs docker commands for the compose project in etcDir. */
type stack struct {
	sys  install.System
	errw io.Writer
}

func (s stack) docker(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	return s.sys.Run(ctx, install.Cmd{Name: "docker", Args: args, Stdin: stdin, Stdout: stdout, Stderr: s.errw})
}

func (s stack) compose(ctx context.Context, stdin io.Reader, stdout io.Writer, args ...string) error {
	return s.docker(ctx, stdin, stdout, append([]string{"compose", "-f", path.Join(etcDir, "compose.yaml")}, args...)...)
}

/* pg is the sysbackup.Exec of the postgres service. */
func (s stack) pg(ctx context.Context, script string, stdin io.Reader, stdout io.Writer) error {
	return s.compose(ctx, stdin, stdout, "exec", "-T", "-u", "postgres", "postgres", "sh", "-c", script)
}

/* output runs a compose command and returns its trimmed stdout. */
func (s stack) output(ctx context.Context, args ...string) (string, error) {
	var out bytes.Buffer
	err := s.compose(ctx, nil, &out, args...)
	return strings.TrimSpace(out.String()), err
}

/* executorID is the id of the executor's container (running or not). */
func (s stack) executorID(ctx context.Context) (string, error) {
	id, err := s.output(ctx, "ps", "-aq", "executor")
	if err != nil {
		return "", err
	}
	if !containerRe.MatchString(id) {
		return "", fmt.Errorf("no single executor container (%q)", id)
	}
	return id, nil
}

/* stateLimit collects docker cp's tar of the state directory, at most sysbackup.MaxState bytes. */
type stateLimit struct{ bytes.Buffer }

func (l *stateLimit) Write(p []byte) (int, error) {
	if l.Len()+len(p) > sysbackup.MaxState {
		return 0, errors.New("executor state too large")
	}
	return l.Buffer.Write(p)
}

/* readPassphrase reads the keys archive's passphrase (file, "-": stdin, or the terminal: twice for a new one). */
func readPassphrase(file string, d deps, isNew bool) (secret.Secret, error) {
	prompts := []string{"Passphrase of the keys archive: "}
	if isNew {
		prompts = append(prompts, "Repeat the passphrase: ")
	}
	p, err := readSecret(file, "--passphrase-file", d, prompts...)
	if err == nil && isNew && len([]rune(p.Reveal())) < sysbackup.MinPassphrase {
		return secret.Secret{}, fmt.Errorf("the passphrase must have at least %d characters", sysbackup.MinPassphrase)
	}
	return p, err
}

func backupCmd(ctx context.Context, args []string, d deps) error {
	fs := newFlags("backup")
	out := fs.String("out", ".", "directory for the two archives")
	pf := fs.String("passphrase-file", "", `file with the passphrase of the keys archive ("-": stdin)`)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errors.New("usage: nmsctl backup [--out DIR] [--passphrase-file F]")
	}
	pass, err := readPassphrase(*pf, d, true)
	if err != nil {
		return err
	}
	defer pass.Wipe()
	id, err := sysbackup.Identity(filepath.Join(etcDir, identityFile))
	if err != nil {
		return fmt.Errorf("backup identity: %w", err)
	}
	stamp := d.now().UTC().Format("20060102T150405Z")
	dataPath := filepath.Join(*out, "nms-backup-"+stamp+".age")
	keysPath := filepath.Join(*out, "nms-keys-"+stamp+".age")
	if err := newArchive(keysPath, func(w io.Writer) error { return sysbackup.WriteKeys(w, pass, etcDir) }); err != nil {
		return fmt.Errorf("keys archive: %w", err)
	}
	var m sysbackup.Manifest
	err = newArchive(dataPath, func(w io.Writer) (err error) {
		m, err = snapshot(ctx, stack{d.sys, d.errw}, w, id.Recipient(), d, true)
		return err
	})
	if err != nil {
		_ = os.Remove(keysPath)
		return fmt.Errorf("data archive: %w", err)
	}
	printf(d.out, "backup %s: executor registry at counter %d\n  data: %s\n  keys: %s (under the passphrase: keep it apart from the data)\n",
		m.ID, m.ExecutorHWM, dataPath, keysPath)
	return nil
}

/* newArchive creates p (0600, never over an existing file), fills it with write, and removes it on failure. */
func newArchive(p string, write func(io.Writer) error) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path given by the operator
	if err != nil {
		return err
	}
	err = write(f)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		_ = os.Remove(p)
	}
	return err
}

/*
snapshot writes the data archive: host files, then the executor stopped while
its state and the dump are taken. With restart it starts the executor again
afterwards (backup); update passes false: its services stay stopped until
the update succeeded or was rolled back.
*/
func snapshot(ctx context.Context, s stack, w io.Writer, to age.Recipient, d deps, restart bool) (m sysbackup.Manifest, err error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return m, err
	}
	m = sysbackup.Manifest{ID: hex.EncodeToString(raw), Created: d.now().UTC(), Files: map[string][]byte{}}
	for _, name := range varFiles { /* before the dump: an anchor names an event the dump then holds */
		b, err := os.ReadFile(filepath.Join(varDir, filepath.FromSlash(name))) // #nosec G304 -- fixed files of the install
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return m, err
		}
		m.Files[name] = b
	}
	if m.Server, m.TimescaleDB, err = sysbackup.DBVersions(ctx, s.pg); err != nil {
		return m, err
	}
	cid, err := s.executorID(ctx)
	if err != nil {
		return m, err
	}
	running, err := s.output(ctx, "ps", "-q", "--status", "running", "executor")
	if err != nil {
		return m, err
	}
	if running != "" {
		printf(d.errw, "Stopping the executor for the backup…\n")
		if err := s.compose(ctx, nil, d.errw, "stop", "executor"); err != nil {
			return m, err
		}
		if restart {
			defer func() {
				if serr := s.compose(context.WithoutCancel(ctx), nil, d.errw, "start", "executor"); serr != nil {
					err = errors.Join(err, fmt.Errorf("start the executor again: %w", serr))
				}
			}()
		}
	}
	var st stateLimit
	if err := s.docker(ctx, nil, &st, "cp", cid+":"+executorStateDir, "-"); err != nil {
		return m, fmt.Errorf("copy the executor state: %w", err)
	}
	m.ExecutorState = st.Bytes()
	if m.ExecutorHWM, err = sysbackup.CheckState(m.ExecutorState); err != nil {
		return m, fmt.Errorf("%w (start the executor so it settles it, then back up again)", err)
	}
	return m, sysbackup.WriteData(ctx, w, to, m, s.pg)
}

func restoreCmd(ctx context.Context, args []string, d deps) error {
	fs := newFlags("restore")
	dataFile := fs.String("data", "", "data archive (nms-backup-*.age)")
	keysFile := fs.String("keys", "", "keys archive (nms-keys-*.age)")
	pf := fs.String("passphrase-file", "", `file with the passphrase of the keys archive ("-": stdin)`)
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *dataFile == "" || *keysFile == "" {
		return errors.New("usage: nmsctl restore --data F --keys F [--passphrase-file F]")
	}
	s := stack{d.sys, d.errw}
	if err := checkClean(ctx, s); err != nil {
		return err
	}
	pass, err := readPassphrase(*pf, d, false)
	if err != nil {
		return err
	}
	defer pass.Wipe()
	entries, id, err := readKeysFile(*keysFile, pass)
	if err != nil {
		return err
	}
	data, err := os.Open(*dataFile) // #nosec G304 -- path given by the operator
	if err != nil {
		return err
	}
	defer func() { _ = data.Close() }()
	m, err := sysbackup.VerifyData(data, id)
	if err != nil {
		return err
	}
	printf(d.out, "Archives verified: backup %s of %s, executor registry at counter %d.\n", m.ID, m.Created.Format("2006-01-02 15:04:05 UTC"), m.ExecutorHWM)
	if err := restoreAll(ctx, s, entries, m, id, data, d); err != nil {
		return fmt.Errorf("%w\nrestore incomplete: remove %s, %s and the volumes (docker compose -f %s down -v) before retrying",
			err, etcDir, varDir, path.Join(etcDir, "compose.yaml"))
	}
	return nil
}

/* checkClean refuses anything but a clean server: no install directory content, no data files, no volumes of the project. */
func checkClean(ctx context.Context, s stack) error {
	if ents, err := os.ReadDir(etcDir); err == nil && len(ents) > 0 {
		return fmt.Errorf("restore needs a clean server: %s is not empty", etcDir)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, dir := range []string{"anchors", "gateway"} {
		if _, err := os.Lstat(filepath.Join(varDir, dir)); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("restore needs a clean server: %s exists", filepath.Join(varDir, dir))
		}
	}
	var vols bytes.Buffer
	if err := s.docker(ctx, nil, &vols, "volume", "ls", "-q", "--filter", "label=com.docker.compose.project=nms"); err != nil {
		return err
	}
	if v := strings.TrimSpace(vols.String()); v != "" {
		return fmt.Errorf("restore needs a clean server: volumes exist: %s", strings.Join(strings.Fields(v), ", "))
	}
	return nil
}

/* readKeysFile decrypts the keys archive and finds the backup identity in it. */
func readKeysFile(file string, pass secret.Secret) ([]sysbackup.Entry, age.Identity, error) {
	f, err := os.Open(file) // #nosec G304 -- path given by the operator
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	entries, err := sysbackup.ReadKeys(f, pass)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if e.Name == identityFile && !e.Dir {
			id, err := age.ParseX25519Identity(strings.TrimSpace(string(e.Data)))
			return entries, id, err
		}
	}
	return nil, nil, errors.New("keys archive: no backup identity in it")
}

/*
restoreAll puts the install back once both archives verified: the install
directory and host files, install's host steps (egress rules before any
container), the database into a fresh postgres, the executor's state
volume into its created container, the stack, the audit record of the
restore with a new anchor, and finally the executor's registry verify. The
executor starts frozen (restoredMarker).
*/
func restoreAll(ctx context.Context, s stack, entries []sysbackup.Entry, m sysbackup.Manifest, id age.Identity, data io.ReadSeeker, d deps) error {
	var files []sysbackup.Entry /* without the installed marker: it is written last */
	for _, e := range entries {
		if e.Name != "installed" {
			files = append(files, e)
		}
	}
	if err := sysbackup.WriteEntries(etcDir, files, d.sys.Chown); err != nil {
		return err
	}
	if err := writeVarFiles(m, d.sys); err != nil {
		return err
	}
	if err := install.PrepareRestoredHost(ctx, d.sys, hostRoot, d.out); err != nil {
		return err
	}
	printf(d.out, "Restoring the database…\n")
	if err := s.compose(ctx, nil, d.out, "up", "-d", "--wait", "postgres"); err != nil {
		return fmt.Errorf("start postgres: %w", err)
	}
	if _, err := data.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := sysbackup.RestoreDB(ctx, data, id, s.pg); err != nil {
		return err
	}
	if err := s.compose(ctx, nil, d.out, "up", "--no-start", "executor"); err != nil {
		return err
	}
	cid, err := s.executorID(ctx)
	if err != nil {
		return err
	}
	if err := s.docker(ctx, bytes.NewReader(m.ExecutorState), d.out, "cp", "-a", "-", cid+":"+path.Dir(executorStateDir)); err != nil {
		return fmt.Errorf("restore the executor state: %w", err)
	}
	marker, err := restoredMarker()
	if err != nil {
		return err
	}
	if err := s.docker(ctx, bytes.NewReader(marker), d.out, "cp", "-a", "-", cid+":"+executorStateDir); err != nil {
		return fmt.Errorf("mark the executor state as restored: %w", err)
	}
	printf(d.out, "Starting services…\n")
	if err := s.compose(ctx, nil, d.out, "up", "-d", "--wait", "--wait-timeout", "600"); err != nil {
		return err
	}
	summary, err := json.Marshal(m.Summary())
	if err != nil {
		return err
	}
	if err := install.RunInTools(ctx, d.sys, etcDir, []string{"restore", "record"}, bytes.NewReader(summary), d.out, d.errw); err != nil {
		return fmt.Errorf("record the restore: %w", err)
	}
	if err := install.RunInTools(ctx, d.sys, etcDir, []string{"audit", "anchor"}, nil, d.out, d.errw); err != nil {
		return fmt.Errorf("anchor the audit: %w", err)
	}
	if err := install.FinishRestoredHost(ctx, d.sys, hostRoot, d.out); err != nil {
		return err
	}
	if err := show(ctx, d, execadmin.Request{Cmd: execadmin.CmdRegistryVerify}); err != nil {
		return err
	}
	printf(d.out, "The executor starts frozen (%s): review its grants, devices and host keys, then lift it with nmsctl executor freeze off.\n",
		execadmin.RestoredReason)
	return nil
}

/*
restoredMarker is docker cp's tar of execadmin.RestoredMarker for the state
directory: the restored executor starts frozen (a backup may be of any age)
until the host lifts the freeze.
*/
func restoredMarker() ([]byte, error) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	err := tw.WriteHeader(&tar.Header{Name: execadmin.RestoredMarker, Typeflag: tar.TypeReg, Mode: 0o600,
		Uid: install.ExecutorUID, Gid: install.ExecutorUID})
	return b.Bytes(), errors.Join(err, tw.Close())
}

/* writeVarFiles puts back the host files of varDir with install's owners and modes. */
func writeVarFiles(m sysbackup.Manifest, sys install.System) error {
	anchors, gateway := filepath.Join(varDir, "anchors"), filepath.Join(varDir, "gateway")
	if err := errors.Join(os.MkdirAll(anchors, 0o700), os.MkdirAll(gateway, 0o750)); err != nil {
		return err
	}
	if err := sys.Chown(anchors, install.ContainerUID, install.ContainerUID); err != nil {
		return err
	}
	for name, b := range m.Files {
		p := filepath.Join(varDir, filepath.FromSlash(name))
		mode, uid := os.FileMode(0o644), 0
		switch name {
		case "anchors/anchors.log":
			mode, uid = 0o600, install.ContainerUID
		case "gateway/keys.json":
		default:
			return fmt.Errorf("data archive: unexpected file %q", name)
		}
		if err := writeNewFile(p, b); err != nil {
			return err
		}
		if err := errors.Join(os.Chmod(p, mode), sys.Chown(p, uid, uid)); err != nil {
			return err
		}
	}
	return nil
}

/* restoreRecord (tools container) appends the restore handed on stdin to the panel audit. */
func restoreRecord(ctx context.Context, pool *pgxpool.Pool, args []string, d deps) error {
	if len(args) > 0 {
		return errors.New("usage: nmsctl restore record (summary on stdin; run by nmsctl restore)")
	}
	var s sysbackup.RestoreSummary
	dec := json.NewDecoder(io.LimitReader(d.in, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil || s.ID == "" {
		return errors.New("restore record: bad summary on stdin")
	}
	if err := sysbackup.RecordRestore(ctx, pool, s); err != nil {
		return err
	}
	printf(d.out, "restore of backup %s recorded in the audit\n", s.ID)
	return nil
}
