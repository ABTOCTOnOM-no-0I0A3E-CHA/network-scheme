package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/internal/audit"
	nmsconfig "github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/keys"
)

/* Paths of the published keys.json, api.yaml and the poller's backup public key on the host; tests point them elsewhere. */
var (
	keysJSONPath  = filepath.Join(install.DefaultVar, "gateway", "keys.json")
	apiYAMLPath   = filepath.Join(install.DefaultEtc, "config", "api.yaml")
	backupPubPath = filepath.Join(install.DefaultEtc, "config", "domain_backup.pub")
)

var readVersionRe = regexp.MustCompile(`(?m)^read_key_version: [0-9]+$`)

/* newDomainPriv is a fresh X25519 private key, base64 (as install writes the domain key files). */
func newDomainPriv() ([]byte, error) {
	k, err := keys.NewDomainKey()
	defer clear(k.Private[:])
	return []byte(base64.StdEncoding.EncodeToString(k.Private[:])), err
}

/*
publish puts pub in keys.json as domain's next key version (unless it is
there already: a resumed rotation) and returns that version. For the read
domain api.yaml takes the version first: the api refuses credentials sealed
under any other (security.md 9).
*/
func publish(domain string, pub [32]byte) (int, error) {
	doc, err := os.ReadFile(keysJSONPath) // #nosec G304 -- the install's keys.json
	if err != nil {
		return 0, err
	}
	v := keys.Published(doc, domain, pub)
	var next []byte
	if v == 0 {
		if next, v, err = keys.Rotate(doc, domain, pub); err != nil {
			return 0, err
		}
	}
	if domain == "read" {
		y, err := os.ReadFile(apiYAMLPath) // #nosec G304 -- the install's api.yaml
		if err != nil {
			return 0, err
		}
		if len(readVersionRe.FindAll(y, -1)) != 1 {
			return 0, fmt.Errorf("%s: want exactly one read_key_version line", apiYAMLPath)
		}
		if err := install.ReplaceFile(apiYAMLPath, readVersionRe.ReplaceAll(y, fmt.Appendf(nil, "read_key_version: %d", v))); err != nil {
			return 0, err
		}
	}
	if next != nil {
		if err := install.ReplaceFile(keysJSONPath, next); err != nil {
			return 0, err
		}
	}
	return v, nil
}

/*
domainRotate is "nmsctl keys rotate read|write": a new key pair for the
domain, staged first. read: api.yaml and keys.json take the next version
and the api restarts (from then on it accepts only credentials sealed to
the next key); the tools container re-seals every read credential from the
retired key to the next one and records the version per row (one
transaction, audited); then the key file is replaced and the poller and
eventd restart. write: the executor is stopped, the one-shot executor
re-seals every write credential of its registry, keys.json takes the next
version, the key file is replaced and the executor starts. backup: the
poller's public key and keys.json take the next key and the poller
restarts (new backups are sealed to it), the executor is stopped and the
one-shot executor re-seals every backup DEK from the retired key to the
next one (rotate.BackupDomain: config versions, pre-session backups,
recordings), then the key file is replaced and the executor starts. The
retired private key is gone afterwards: a ciphertext still sealed to it
never opens again. Interrupted, the command run again resumes from the
staged key.
*/
func domainRotate(ctx context.Context, d deps, domain string) error {
	uid := install.ContainerUID
	if domain != "read" {
		uid = install.ExecutorUID
	}
	p := filepath.Join(secretsDir, install.DomainKeyFiles[domain])
	nextB64, err := staged(p, uid, d, newDomainPriv)
	if err != nil {
		return err
	}
	defer clear(nextB64)
	next, err := nmsconfig.ParseKey(nextB64)
	if err != nil {
		return fmt.Errorf("staged %s%s: %w", p, install.NextSuffix, err)
	}
	defer clear(next[:])
	pub, err := keys.PublicOf(next)
	if err != nil {
		return err
	}
	var v int
	switch domain {
	case "read":
		if v, err = publish(domain, pub); err != nil {
			return err
		}
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "restart", "api"); err != nil {
			return fmt.Errorf("restart the api: %w", err)
		}
		old, err := os.ReadFile(p) // #nosec G304 -- a file of the secrets directory
		if err != nil {
			return err
		}
		defer clear(old)
		stdin := append(append(append([]byte{}, bytes.TrimSpace(old)...), '\n'), nextB64...)
		defer clear(stdin)
		if err := install.RunInTools(ctx, d.sys, install.DefaultEtc, []string{"keys", "reencrypt", "read", "--version", strconv.Itoa(v)},
			bytes.NewReader(append(stdin, '\n')), d.out, d.errw); err != nil {
			return fmt.Errorf("re-seal the read credentials (run the command again to resume): %w", err)
		}
		if err := install.PromoteSecret(p); err != nil {
			return err
		}
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "restart", "poller", "eventd"); err != nil {
			return fmt.Errorf("restart poller and eventd: %w", err)
		}
	case "write":
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "stop", "executor"); err != nil {
			return fmt.Errorf("stop the executor: %w", err)
		}
		stdin := append(append(append([]byte{}, nextB64...), '\n'), hostOperator()+"\n"...)
		defer clear(stdin)
		if err := install.RunExecutorOnce(ctx, d.sys, install.DefaultEtc, []string{"reseal-write"}, bytes.NewReader(stdin), d.out, d.errw); err != nil {
			return fmt.Errorf("re-seal the write credentials (the executor stays stopped; run the command again to resume): %w", err)
		}
		if v, err = publish(domain, pub); err != nil {
			return err
		}
		if err := install.PromoteSecret(p); err != nil {
			return err
		}
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "up", "-d", "executor"); err != nil {
			return fmt.Errorf("start the executor: %w", err)
		}
	case "backup":
		if v, err = publish(domain, pub); err != nil {
			return err
		}
		if err := install.ReplaceFile(backupPubPath, []byte(base64.StdEncoding.EncodeToString(pub[:])+"\n")); err != nil {
			return err
		}
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "restart", "poller"); err != nil {
			return fmt.Errorf("restart the poller: %w", err)
		}
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "stop", "executor"); err != nil {
			return fmt.Errorf("stop the executor: %w", err)
		}
		stdin := append(append(append([]byte{}, nextB64...), '\n'), hostOperator()+"\n"...)
		defer clear(stdin)
		var out limited
		if err := install.RunExecutorOnce(ctx, d.sys, install.DefaultEtc, []string{"reseal-backup"}, bytes.NewReader(stdin), &out, d.errw); err != nil {
			return fmt.Errorf("re-seal the backups (the executor stays stopped; run the command again to resume): %w", err)
		}
		var res struct {
			Backups    int `json:"backups"`
			Unreadable int `json:"unreadable"`
			Sessions   int `json:"sessions"`
			Chunks     int `json:"chunks"`
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			return fmt.Errorf("executor reseal-backup: malformed result (the executor stays stopped; run the command again to resume): %v", err)
		}
		if err := install.PromoteSecret(p); err != nil {
			return err
		}
		if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "up", "-d", "executor"); err != nil {
			return fmt.Errorf("start the executor: %w", err)
		}
		printf(d.out, "re-sealed %d config versions, %d pre-session backups, %d recording chunks; opening under neither key (left as they are): %d\n",
			res.Backups, res.Sessions, res.Chunks, res.Unreadable)
	default:
		return errors.New(keysUsage)
	}
	printf(d.out, "%s domain key rotated to version %d, fingerprint %s; the previous key is gone\n", domain, v, keys.Fingerprint(pub))
	return nil
}

/*
reencryptRead is "nmsctl keys reencrypt read --version V" in the tools
container (stdin: the retired and the next read private key, one line
each): in one transaction every read credential not yet at V is re-sealed
from the retired key to the next one at V; one that does not open under
the retired key is marked invalid and keeps its version (refused: the
operator enters it again). The plaintext never leaves this process.
*/
func reencryptRead(ctx context.Context, pool *pgxpool.Pool, args []string, d deps) error {
	fs := flag.NewFlagSet("keys reencrypt read", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	version := fs.Int("version", 0, "the next key version")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *version < 2 {
		return errors.New("usage: nmsctl keys reencrypt read --version V (keys on stdin; run by nmsctl keys rotate read)")
	}
	raw, err := io.ReadAll(io.LimitReader(d.in, 4096))
	if err != nil {
		return err
	}
	defer clear(raw)
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if len(lines) != 2 {
		return errors.New("keys reencrypt: stdin must hold the retired and the next key, one line each")
	}
	old, err := nmsconfig.ParseKey(lines[0])
	if err != nil {
		return err
	}
	defer clear(old[:])
	next, err := nmsconfig.ParseKey(lines[1])
	if err != nil {
		return err
	}
	defer clear(next[:])
	pub, err := keys.PublicOf(next)
	if err != nil {
		return err
	}
	type cred struct {
		ownerKind, kind string
		ownerID         int64
		ct              []byte
	}
	var done, bad int
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT owner_kind, owner_id, kind, ciphertext FROM core.access_profile WHERE key_version <> $1 FOR UPDATE`, *version)
		if err != nil {
			return err
		}
		all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cred, error) {
			var c cred
			return c, r.Scan(&c.ownerKind, &c.ownerID, &c.kind, &c.ct)
		})
		if err != nil {
			return err
		}
		for _, c := range all {
			nct, err := keys.Reseal(c.ct, old, &pub)
			if errors.Is(err, keys.ErrNotSealedToKey) {
				bad++
				if _, err := tx.Exec(ctx, `UPDATE core.access_profile SET status = 'invalid' WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3`,
					c.ownerKind, c.ownerID, c.kind); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE core.access_profile SET ciphertext = $4, key_version = $5 WHERE owner_kind = $1 AND owner_id = $2 AND kind = $3`,
				c.ownerKind, c.ownerID, c.kind, nct, *version); err != nil {
				return err
			}
			done++
		}
		_, err = audit.Append(ctx, tx, audit.Event{UserAgent: "nmsctl", Action: "cli.keys_rotate", ObjectType: "key", ObjectID: "read",
			Result: "success", Details: map[string]any{"key_version": *version, "resealed": done, "invalid": bad, "fingerprint": keys.Fingerprint(pub)}})
		return err
	})
	if err != nil {
		return err
	}
	printf(d.out, "read credentials re-sealed to key version %d: %d; not opening under the retired key (marked invalid): %d\n", *version, done, bad)
	return nil
}
