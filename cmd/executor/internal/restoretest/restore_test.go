/*
Package restoretest checks nmsctl backup and restore against the executor
(nmsctl links nothing of the executor, so the check lives here): a server
with registry changes, audit rows on both chains and TimescaleDB data is
backed up as nmsctl does it (the state directory of the stopped executor,
then pg_dump), restored onto a clean server with nmsctl's restore marker,
and the executor there starts frozen (sticky, "restored from backup"), with
its registry and its audit chain verified; the host's freeze off lifts it.
*/
package restoretest

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"

	execaudit "github.com/beekamai/network-scheme/cmd/executor/internal/audit"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/internal/audit"
	"github.com/beekamai/network-scheme/internal/execadmin"
	"github.com/beekamai/network-scheme/internal/sysbackup"
	"github.com/beekamai/network-scheme/internal/testdb"
)

/* pgExec is sysbackup.Exec on a test container, as nmsctl's docker compose exec -T -u postgres postgres sh -c. */
func pgExec(c testcontainers.Container) sysbackup.Exec {
	return func(ctx context.Context, script string, stdin io.Reader, stdout io.Writer) error {
		var stderr bytes.Buffer
		cmd := exec.CommandContext(ctx, "docker", "exec", "-i", "-u", "postgres", c.GetContainerID(), "sh", "-c", script) // #nosec G204 -- test
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, &stderr
		if err := cmd.Run(); err != nil {
			return errors.Join(err, errors.New(stderr.String()))
		}
		return nil
	}
}

/* tarDir is docker cp's tar of a state directory: entries under sysbackup.StateDir. */
func tarDir(t *testing.T, dir string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		h.Name = filepath.ToSlash(filepath.Join(sysbackup.StateDir, rel))
		if err := tw.WriteHeader(h); err != nil || e.IsDir() {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- test
		if err != nil {
			return err
		}
		_, err = tw.Write(data)
		return err
	})
	if err != nil || tw.Close() != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

/* untar is docker cp -a - into the parent of a new state directory. */
func untar(t *testing.T, tarball []byte, dir string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(tarball))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(h.Name, sysbackup.StateDir), "/")
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func grant(user int64) func(context.Context, *registry.Snapshot, *registry.Tx) error {
	return func(_ context.Context, _ *registry.Snapshot, tx *registry.Tx) error {
		tx.Audit(execaudit.Append(execaudit.Event{TS: time.Now(), UA: "test", Action: "grant", Object: "user", Result: execaudit.OK}))
		return tx.Put("write_grant", map[string]any{"user_id": user, "kind": "write", "write_group": "core", "username_snapshot": "u"})
	}
}

/* verifyExecutor starts a registry over the state directory as the executor does and checks it and its audit chain. */
func verifyExecutor(t *testing.T, env *testdb.Env, keys *seal.Keys, dir string) registry.Report {
	t.Helper()
	ctx := context.Background()
	reg := registry.New(env.Pool("nms_executor"), keys, filepath.Join(dir, "state"))
	if err := reg.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	rep, err := reg.Verify(ctx)
	if err != nil {
		t.Fatalf("registry verify: %v", err)
	}
	f, err := state.Load(filepath.Join(dir, "state"), keys.State())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := env.Pool("nms_executor").BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	res, err := execaudit.Verify(ctx, tx, f.Chain())
	if err != nil || res.Break != nil {
		t.Fatalf("executor audit: %+v %v", res.Break, err)
	}
	return rep
}

func TestBackupRestoreKeepsTheExecutorConsistent(t *testing.T) {
	ctx := context.Background()
	passwords := map[string]string{}
	src, srcC := testdb.Fresh(t, passwords, true)
	keys, err := seal.Derive(&[32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	srcDir := t.TempDir()
	reg := registry.New(src.Pool("nms_executor"), keys, filepath.Join(srcDir, "state"))
	if err := reg.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for u := int64(1); u <= 3; u++ {
		if err := reg.Write(ctx, grant(u)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sysbackup.RecordRestore(ctx, src.Pool("nms_cli"), sysbackup.RestoreSummary{ID: "earlier"}); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Pool("postgres").Exec(ctx, `INSERT INTO metrics.availability (device_id, ts, icmp_ok, snmp_ok, state)
		SELECT 1, now() - make_interval(days => d), true, true, 'up' FROM generate_series(0, 3) d`); err != nil {
		t.Fatal(err)
	}
	before := verifyExecutor(t, src, keys, srcDir)

	/* Backup: the executor is stopped (no Registry in use), its state directory, then the dump. */
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	m := sysbackup.Manifest{ID: "b1", Created: time.Now().UTC(), ExecutorState: tarDir(t, srcDir)}
	if m.ExecutorHWM, err = sysbackup.CheckState(m.ExecutorState); err != nil || m.ExecutorHWM != before.Seq {
		t.Fatalf("state hwm %d (registry %d): %v", m.ExecutorHWM, before.Seq, err)
	}
	if m.Server, m.TimescaleDB, err = sysbackup.DBVersions(ctx, pgExec(srcC)); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := sysbackup.WriteData(ctx, &archive, id.Recipient(), m, pgExec(srcC)); err != nil {
		t.Fatal(err)
	}

	/* A clean server with the restored secrets (role passwords), and a fresh state volume. */
	dst, dstC := testdb.Fresh(t, passwords, false)
	dstDir := t.TempDir()

	other, _ := age.GenerateX25519Identity()
	if _, err := sysbackup.VerifyData(bytes.NewReader(archive.Bytes()), other); err == nil {
		t.Fatal("a foreign identity opened the archive")
	}
	tampered := bytes.Clone(archive.Bytes())
	tampered[len(tampered)/2] ^= 1
	if _, err := sysbackup.VerifyData(bytes.NewReader(tampered), id); err == nil {
		t.Fatal("a tampered archive verified")
	}
	if _, err := sysbackup.VerifyData(bytes.NewReader(archive.Bytes()[:archive.Len()-1]), id); err == nil {
		t.Fatal("a truncated archive verified")
	}

	got, err := sysbackup.VerifyData(bytes.NewReader(archive.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := sysbackup.RestoreDB(ctx, bytes.NewReader(archive.Bytes()), id, pgExec(dstC)); err != nil {
		t.Fatal(err)
	}
	untar(t, got.ExecutorState, dstDir)

	after := verifyExecutor(t, dst, keys, dstDir)
	if after.Seq != before.Seq || after.Frozen {
		t.Fatalf("restored registry %+v, backed up %+v", after, before)
	}

	/* nmsctl restore's marker: the executor starts frozen, sticky across a restart, until the host's freeze off. */
	marker := filepath.Join(dstDir, execadmin.RestoredMarker)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	startGuard := func() *freeze.Guard {
		g := freeze.New(registry.New(dst.Pool("nms_executor"), keys, filepath.Join(dstDir, "state")), dst.Pool("nms_executor"),
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err := g.Start(ctx); err != nil {
			t.Fatal(err)
		}
		if err := g.FreezeRestored(ctx, marker); err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := startGuard()
	if frozen, reason := g.Frozen(); !frozen || reason != execadmin.RestoredReason {
		t.Fatalf("restored executor frozen %v (%q)", frozen, reason)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("marker left: %v", err)
	}
	if rep := verifyExecutor(t, dst, keys, dstDir); !rep.Frozen || rep.Reason != execadmin.RestoredReason {
		t.Fatalf("not sticky: %+v", rep)
	}
	var audited int
	if err := dst.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM exec.audit_event WHERE action = 'admin.freeze-on' AND convert_from(payload, 'UTF8') LIKE '%restored from backup%'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("restore's freeze audited %d times: %v", audited, err)
	}
	g = startGuard()
	if frozen, _ := g.Frozen(); !frozen {
		t.Fatal("a restart lifted the restore's freeze")
	}
	if err := g.FreezeOff(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}
	if frozen, _ := g.Frozen(); frozen {
		t.Fatal("freeze off did not lift the restore's freeze")
	}
	unfrozen := verifyExecutor(t, dst, keys, dstDir)
	if unfrozen.Frozen {
		t.Fatalf("after freeze off %+v", unfrozen)
	}
	var rows int
	if err := dst.Pool("postgres").QueryRow(ctx, `SELECT count(*) FROM metrics.availability`).Scan(&rows); err != nil || rows != 4 {
		t.Fatalf("hypertable rows %d: %v", rows, err)
	}

	/* The restore is recorded in the panel audit, whose chain verifies; the executor keeps writing. */
	if err := sysbackup.RecordRestore(ctx, dst.Pool("nms_cli"), got.Summary()); err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, dst.Pool("nms_cli"))
	if err != nil || res.Break != nil || res.Count != 2 {
		t.Fatalf("panel audit %+v: %v", res, err)
	}
	reg2 := registry.New(dst.Pool("nms_executor"), keys, filepath.Join(dstDir, "state"))
	if err := reg2.Write(ctx, grant(4)); err != nil {
		t.Fatal(err)
	}
	if rep := verifyExecutor(t, dst, keys, dstDir); rep.Seq != unfrozen.Seq+1 || rep.Frozen {
		t.Fatalf("after a write %+v", rep)
	}
}
