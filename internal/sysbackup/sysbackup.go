/*
Package sysbackup is the archive format and the database half of nmsctl
backup and restore. A backup is two age files:

  - the data archive, encrypted to the install's backup identity (an age
    X25519 key in Etc/secrets): one JSON line (Manifest: versions, the
    executor's state volume as the tar docker cp gives, the small host
    files of Var) followed by the pg_dump custom-format stream to its end;
  - the keys archive, encrypted under a passphrase (age scrypt): a tar of
    the install directory Etc (secrets, the backup identity, configuration,
    compose project), owners and modes kept.

age authenticates every chunk and the end of a file, so restore reads both
archives to their end before it changes anything (a wrong passphrase, a
foreign key or a tampered or truncated archive fails there), and then reads
the data archive a second time straight into pg_restore: no plaintext dump
is ever written to disk.
*/
package sysbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/beekamai/network-scheme/internal/secret"
)

/* Version is the format version of the manifest; any other value is refused. */
const Version = 1

/* Bounds of what restore reads into memory. */
const (
	MaxManifest = 64 << 20
	MaxKeys     = 64 << 20
	MaxState    = 16 << 20
)

/* MinPassphrase is the shortest passphrase of a keys archive. */
const MinPassphrase = 12

/* StateDir is the name of the executor's state directory in its tar (docker cp of /var/lib/executor). */
const StateDir = "executor"

/* dumpMagic starts every pg_dump custom-format archive. */
var dumpMagic = []byte("PGDMP")

/* Manifest is the first line of a data archive. */
type Manifest struct {
	V             int               `json:"v"`
	ID            string            `json:"id"`
	Created       time.Time         `json:"created"`
	Server        string            `json:"server_version_num"`
	TimescaleDB   string            `json:"timescaledb"`
	ExecutorState []byte            `json:"executor_state"` /* tar of the state directory (StateDir/...) */
	ExecutorHWM   int64             `json:"executor_hwm"`
	Files         map[string][]byte `json:"files"` /* host files relative to Var */
}

/*
Exec runs a fixed shell script as the postgres user in the database
container, with POSTGRES_DB set (docker compose exec -T -u postgres
postgres sh -c script). The scripts are constants of this package.
*/
type Exec func(ctx context.Context, script string, stdin io.Reader, stdout io.Writer) error

const (
	versionsScript = `exec psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -c "SELECT current_setting('server_version_num') || ' ' || extversion FROM pg_extension WHERE extname = 'timescaledb'"`
	dumpScript     = `exec pg_dump -U postgres -d "$POSTGRES_DB" -Fc`
	/*
		Onto the database a fresh postgres container made (its init script: roles,
		the timescaledb extension, empty core and audit schemas, which the dump
		brings back; DROP SCHEMA without CASCADE fails on anything not fresh), the
		TimescaleDB restore procedure: pre_restore, pg_restore, post_restore.
	*/
	restoreScript = `set -eu
psql -X -q -1 -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -c 'DROP SCHEMA core' -c 'DROP SCHEMA audit' -c 'SELECT timescaledb_pre_restore()' >/dev/null
pg_restore -U postgres -d "$POSTGRES_DB" --exit-on-error
psql -X -q -v ON_ERROR_STOP=1 -U postgres -d "$POSTGRES_DB" -c 'SELECT timescaledb_post_restore()' -c 'ANALYZE' >/dev/null`
)

/* DBVersions returns server_version_num and the timescaledb extension's version. */
func DBVersions(ctx context.Context, run Exec) (string, string, error) {
	var out bytes.Buffer
	if err := run(ctx, versionsScript, strings.NewReader(""), &out); err != nil {
		return "", "", fmt.Errorf("database versions: %w", err)
	}
	server, ts, ok := strings.Cut(strings.TrimSpace(out.String()), " ")
	if !ok || server == "" || ts == "" {
		return "", "", fmt.Errorf("database versions: unexpected %q", out.String())
	}
	return server, ts, nil
}

/* WriteData writes the data archive: m, then the pg_dump stream, encrypted to to. */
func WriteData(ctx context.Context, w io.Writer, to age.Recipient, m Manifest, run Exec) error {
	m.V = Version
	line, err := json.Marshal(m)
	if err != nil {
		return err
	}
	enc, err := age.Encrypt(w, to)
	if err != nil {
		return err
	}
	if _, err := enc.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := run(ctx, dumpScript, strings.NewReader(""), enc); err != nil {
		return fmt.Errorf("pg_dump: %w", err)
	}
	return enc.Close()
}

/* openData decrypts a data archive and reads its manifest; the rest of the reader is the dump. */
func openData(r io.Reader, id age.Identity) (Manifest, io.Reader, error) {
	dec, err := age.Decrypt(r, id)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("data archive: %w", err)
	}
	br := bufio.NewReader(dec)
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxManifest {
			return Manifest{}, nil, errors.New("data archive: manifest too large")
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return Manifest{}, nil, fmt.Errorf("data archive: %w", err)
		}
	}
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return Manifest{}, nil, fmt.Errorf("data archive: manifest: %w", err)
	}
	if m.V != Version || m.ID == "" || m.Server == "" || m.TimescaleDB == "" {
		return Manifest{}, nil, fmt.Errorf("data archive: manifest of version %d or incomplete", m.V)
	}
	for name := range m.Files {
		if !fs.ValidPath(name) || name == "." {
			return Manifest{}, nil, fmt.Errorf("data archive: bad file name %q", name)
		}
	}
	if _, err := CheckState(m.ExecutorState); err != nil {
		return Manifest{}, nil, err
	}
	return m, br, nil
}

/* VerifyData reads a data archive to its authenticated end and returns its manifest. */
func VerifyData(r io.Reader, id age.Identity) (Manifest, error) {
	m, rest, err := openData(r, id)
	if err != nil {
		return m, err
	}
	head := make([]byte, len(dumpMagic))
	if _, err := io.ReadFull(rest, head); err != nil || !bytes.Equal(head, dumpMagic) {
		return m, errors.New("data archive: no pg_dump archive after the manifest")
	}
	if _, err := io.Copy(io.Discard, rest); err != nil {
		return m, fmt.Errorf("data archive: %w", err)
	}
	return m, nil
}

/*
RestoreDB restores the dump of a data archive VerifyData accepted into the
fresh database: the server and TimescaleDB versions must be the backup's.
*/
func RestoreDB(ctx context.Context, r io.Reader, id age.Identity, run Exec) error {
	m, rest, err := openData(r, id)
	if err != nil {
		return err
	}
	server, ts, err := DBVersions(ctx, run)
	if err != nil {
		return err
	}
	if server != m.Server || ts != m.TimescaleDB {
		return fmt.Errorf("the backup is of PostgreSQL %s with TimescaleDB %s, this database is %s with %s: restore with the same images",
			m.Server, m.TimescaleDB, server, ts)
	}
	if err := run(ctx, restoreScript, rest, io.Discard); err != nil {
		return fmt.Errorf("pg_restore: %w", err)
	}
	return nil
}

/* stateBody is what CheckState reads of the state file (the executor alone can check its MAC). */
type stateBody struct {
	Committed struct {
		HWM int64 `json:"hwm"`
	} `json:"committed"`
	Pending *json.RawMessage `json:"pending"`
}

/*
CheckState validates the tar of the executor's state directory: entries
only under StateDir, regular files and directories, and a state file
without a registry change in flight (its pending record names a database
transaction, which a restored database does not have). It returns the
committed high-water mark.
*/
func CheckState(tarball []byte) (int64, error) {
	if len(tarball) > MaxState {
		return 0, errors.New("executor state: too large")
	}
	var body []byte
	tr := tar.NewReader(bytes.NewReader(tarball))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("executor state: %w", err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !fs.ValidPath(name) || (name != StateDir && !strings.HasPrefix(name, StateDir+"/")) ||
			(h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) {
			return 0, fmt.Errorf("executor state: unexpected entry %q", h.Name)
		}
		if name == StateDir+"/state" {
			if body, err = io.ReadAll(tr); err != nil {
				return 0, fmt.Errorf("executor state: %w", err)
			}
		}
	}
	_, js, ok := bytes.Cut(body, []byte("\n"))
	var s stateBody
	if !ok || json.Unmarshal(js, &s) != nil || s.Committed.HWM <= 0 {
		return 0, errors.New("executor state: no valid state file")
	}
	if s.Pending != nil && string(*s.Pending) != "null" {
		return 0, errors.New("executor state: a registry change is in flight")
	}
	return s.Committed.HWM, nil
}

/* Entry is one file or directory of a keys archive, relative to its root. */
type Entry struct {
	Name     string
	Dir      bool
	Mode     fs.FileMode
	UID, GID int
	Data     []byte
}

/* WriteKeys writes dir (regular files and directories, owners and modes kept) as a tar encrypted under pass. */
func WriteKeys(w io.Writer, pass secret.Secret, dir string) error {
	rcpt, err := age.NewScryptRecipient(pass.Reveal())
	if err != nil {
		return err
	}
	enc, err := age.Encrypt(w, rcpt)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir) /* reads stay inside dir, whatever is renamed meanwhile */
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tw := tar.NewWriter(enc)
	err = filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil || p == dir {
			return err
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return fmt.Errorf("%s: not a regular file or directory", p)
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		h.Name, h.Uname, h.Gname = filepath.ToSlash(rel), "", ""
		if err := tw.WriteHeader(h); err != nil || fi.IsDir() {
			return err
		}
		data, err := root.ReadFile(rel)
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		clear(data)
		return err
	})
	if err != nil {
		return err
	}
	return errors.Join(tw.Close(), enc.Close())
}

/* ReadKeys decrypts a keys archive whole (at most MaxKeys bytes) and returns its validated entries. */
func ReadKeys(r io.Reader, pass secret.Secret) ([]Entry, error) {
	id, err := age.NewScryptIdentity(pass.Reveal())
	if err != nil {
		return nil, err
	}
	dec, err := age.Decrypt(r, id)
	if err != nil {
		return nil, fmt.Errorf("keys archive: %w (wrong passphrase?)", err)
	}
	raw, err := io.ReadAll(io.LimitReader(dec, MaxKeys+1))
	if err != nil {
		return nil, fmt.Errorf("keys archive: %w", err)
	}
	if len(raw) > MaxKeys {
		return nil, errors.New("keys archive: too large")
	}
	var es []Entry
	seen := map[string]bool{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return es, nil
		}
		if err != nil {
			return nil, fmt.Errorf("keys archive: %w", err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !fs.ValidPath(name) || name == "." || seen[name] || (h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir) {
			return nil, fmt.Errorf("keys archive: unexpected entry %q", h.Name)
		}
		if dir := path.Dir(name); dir != "." && !seen[dir] {
			return nil, fmt.Errorf("keys archive: %q before its directory", h.Name)
		}
		seen[name] = true
		e := Entry{Name: name, Dir: h.Typeflag == tar.TypeDir, Mode: fs.FileMode(h.Mode & 0o777), UID: h.Uid, GID: h.Gid}
		if !e.Dir {
			if e.Data, err = io.ReadAll(tr); err != nil {
				return nil, fmt.Errorf("keys archive: %w", err)
			}
		}
		es = append(es, e)
	}
}

/*
WriteEntries creates the entries under root (created 0750 if missing; no
entry may exist yet) with their modes, then hands each to chown with its
owner. Directories come before what they hold (ReadKeys checks it).
*/
func WriteEntries(root string, es []Entry, chown func(path string, uid, gid int) error) error {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return err
	}
	for _, e := range es {
		p := filepath.Join(root, filepath.FromSlash(e.Name))
		var err error
		if e.Dir {
			err = os.Mkdir(p, 0o700)
		} else {
			err = writeExcl(p, e.Data)
		}
		if err != nil {
			return err
		}
		if err := errors.Join(os.Chmod(p, e.Mode), chown(p, e.UID, e.GID)); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

func writeExcl(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a path under the install directory
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	return errors.Join(werr, f.Sync(), f.Close())
}

/*
Identity returns the install's backup identity from file, creating it
(0400) on first use: the data archives are encrypted to it, and it travels
in the keys archive.
*/
func Identity(file string) (*age.X25519Identity, error) {
	raw, err := os.ReadFile(file) // #nosec G304 -- the install's secrets directory
	if errors.Is(err, os.ErrNotExist) {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return nil, err
		}
		if err := writeExcl(file, []byte(id.String()+"\n")); err != nil {
			return nil, err
		}
		return id, os.Chmod(file, 0o400)
	}
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return age.ParseX25519Identity(strings.TrimSpace(string(raw)))
}
