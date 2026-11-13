package rotate_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/beekamai/network-scheme/cmd/executor/internal/attacktest"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/rotate"
	"github.com/beekamai/network-scheme/cmd/executor/internal/session"
	"github.com/beekamai/network-scheme/internal/backup"
	"github.com/beekamai/network-scheme/internal/backup/open"
	"github.com/beekamai/network-scheme/internal/keys"
)

/*
The backup-domain rotation re-seals the DEK of every config version and
pre-session backup to the next key (bodies unchanged, MACs rewritten), in
one transaction with one executor audit row: they open under the next key
only. A version the poller planted under another key is counted and left;
run again nothing changes; a pre-session row failing its MAC stops it with
nothing written.
*/
func TestBackupDomainRotation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	old, next, other := &[32]byte{5: 1}, &[32]byte{5: 2}, &[32]byte{5: 3}
	pubOf := func(k *[32]byte) *[32]byte {
		p, err := keys.PublicOf(k)
		if err != nil {
			t.Fatal(err)
		}
		return &p
	}
	exe, root := f.env.Pool("nms_executor"), f.env.Pool("postgres")
	insert := func(role, source string, to *[32]byte, text string) {
		t.Helper()
		sum := sha256.Sum256([]byte(text))
		ct, dek, err := backup.Seal(to, []byte(text), backup.AAD(3, hex.EncodeToString(sum[:])))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.env.Pool(role).Exec(ctx, `INSERT INTO backups.config_version (device_id, source, sha256, size, masked, full_ct, full_dek_ct)
			VALUES (3, $1, $2, $3, '', $4, $5)`, source, sum[:], len(text), ct, dek); err != nil {
			t.Fatal(err)
		}
	}
	insert("nms_executor", "executor", pubOf(old), "hostname a")
	insert("nms_poller", "schedule", pubOf(old), "hostname b")
	insert("nms_poller", "schedule", pubOf(other), "planted")

	m := session.New(session.Config{MAC: f.old.MAC()})
	sid := [16]byte{0: 9}
	attacktest.Tamper(t, f.env, `INSERT INTO exec.session (id, user_id, opened_at, policy_snapshot, mac) VALUES ($1, 1, now(), '{}', $2)`, sid, make([]byte, 32))
	pre := sha256.Sum256([]byte("pre"))
	pct, pdek, err := backup.Seal(pubOf(old), []byte("pre"), backup.AAD(3, hex.EncodeToString(pre[:])))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exe.Exec(ctx, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac) VALUES ($1, 3, $2, $3, $4, $5)`,
		sid, pre[:], pct, pdek, m.DeviceMAC(sid, 3, pre, pct, pdek)); err != nil {
		t.Fatal(err)
	}

	reg := registry.New(exe, f.old, filepath.Join(f.dir, "state"))
	rep, err := rotate.BackupDomain(ctx, reg, f.old.MAC(), old, next, "root")
	if err != nil || rep != (rotate.BackupReport{Backups: 2, Unreadable: 1, Sessions: 1}) {
		t.Fatalf("rotation: %+v %v", rep, err)
	}
	/* opensUnder lists, per config version in id order, whether it opens under the next and the retired key. */
	opensUnder := func() (out [][2]bool) {
		t.Helper()
		rows, err := root.Query(ctx, `SELECT sha256, full_ct, full_dek_ct FROM backups.config_version ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var sum, ct, dek []byte
			if err := rows.Scan(&sum, &ct, &dek); err != nil {
				t.Fatal(err)
			}
			aad := backup.AAD(3, hex.EncodeToString(sum))
			_, errNext := open.Open(next, pubOf(next), ct, dek, aad)
			_, errOld := open.Open(old, pubOf(old), ct, dek, aad)
			out = append(out, [2]bool{errNext == nil, errOld == nil})
		}
		return out
	}
	if got := opensUnder(); len(got) != 3 || got[0] != [2]bool{true, false} || got[1] != [2]bool{true, false} || got[2] != [2]bool{} {
		t.Fatalf("config versions (next, retired): %v", got)
	}
	var pct2, pdek2, mac []byte
	if err := root.QueryRow(ctx, `SELECT pre_ct, pre_dek_ct, mac FROM exec.session_device WHERE session_id = $1`, sid).Scan(&pct2, &pdek2, &mac); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pct2, pct) || !bytes.Equal(mac, m.DeviceMAC(sid, 3, pre, pct2, pdek2)) {
		t.Fatal("the pre-session row: body changed or MAC not rewritten")
	}
	if _, err := open.Open(next, pubOf(next), pct2, pdek2, backup.AAD(3, hex.EncodeToString(pre[:]))); err != nil {
		t.Fatalf("the pre-session backup under the next key: %v", err)
	}
	if again, err := rotate.BackupDomain(ctx, reg, f.old.MAC(), old, next, "root"); err != nil || again != (rotate.BackupReport{Unreadable: 1}) {
		t.Fatalf("second run: %+v %v", again, err)
	}

	attacktest.Tamper(t, f.env, `INSERT INTO exec.session_device (session_id, device_id, pre_sha256, pre_ct, pre_dek_ct, mac) VALUES ($1, 4, $2, $3, $4, $2)`,
		sid, make([]byte, 32), pct, pdek)
	insert("nms_executor", "executor", pubOf(next), "hostname c")
	if _, err := rotate.BackupDomain(ctx, reg, f.old.MAC(), next, old, "root"); !errors.Is(err, registry.ErrTampered) {
		t.Fatalf("a planted pre-session row: %v", err)
	}
	if got := opensUnder(); len(got) != 4 || got[0] != [2]bool{true, false} || got[3] != [2]bool{true, false} {
		t.Fatalf("the refused rotation re-sealed config versions: %v", got)
	}
	var audits int
	if err := root.QueryRow(ctx, `SELECT count(*) FROM exec.audit_event WHERE action = 'admin.key-rotate' AND object = 'backup-domain'`).
		Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("audit rows %d %v", audits, err)
	}
}
