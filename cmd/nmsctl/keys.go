package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/beekamai/network-scheme/internal/install"
	"github.com/beekamai/network-scheme/internal/keys"
)

/* secretsDir is the install's secrets directory on the host; tests point it elsewhere. */
var secretsDir = install.SecretsDir(install.DefaultEtc)

/*
staged returns the staged secret of p: the one an interrupted rotation left
(resumed), or a new one from gen, staged first (install.StageSecret).
*/
func staged(p string, uid int, d deps, gen func() ([]byte, error)) ([]byte, error) {
	b, err := os.ReadFile(p + install.NextSuffix) // #nosec G304 -- a file of the secrets directory
	if err == nil {
		printf(d.errw, "resuming the rotation staged in %s%s\n", p, install.NextSuffix)
		return bytes.TrimSpace(b), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if b, err = gen(); err != nil {
		return nil, err
	}
	return b, install.StageSecret(p, b, uid, d.sys.Chown)
}

func newSymmetric() ([]byte, error) {
	k, err := keys.NewSymmetricKey()
	defer clear(k[:])
	return []byte(base64.StdEncoding.EncodeToString(k[:])), err
}

/*
sealingRotate is "nmsctl executor key rotate": a new sealing key for the
executor. The daemon is stopped; a one-shot executor container (rotate-key)
re-MACs and re-seals everything under the next key, which it reads on stdin
(security.md 9); only then does the next key replace the key file, and the
executor starts again. Interrupted anywhere, the command run again resumes
from the staged key; until then the executor stays stopped (or, started by
hand, frozen).
*/
func sealingRotate(ctx context.Context, d deps, args []string) error {
	fs := newFlags("executor key rotate")
	yes := fs.Bool("yes", false, "do not ask")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return errors.New("usage: nmsctl executor key rotate [--yes]")
	}
	if !*yes {
		if err := confirm(d, "The executor stops during the rotation (open change sessions end as interrupted). Rotate its sealing key?"); err != nil {
			return err
		}
	}
	p := filepath.Join(secretsDir, "executor_sealing_key")
	next, err := staged(p, install.ExecutorUID, d, newSymmetric)
	if err != nil {
		return err
	}
	defer clear(next)
	if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "stop", "executor"); err != nil {
		return fmt.Errorf("stop the executor: %w", err)
	}
	stdin := append(append(append([]byte{}, next...), '\n'), hostOperator()+"\n"...)
	defer clear(stdin)
	var out limited
	if err := install.RunExecutorOnce(ctx, d.sys, install.DefaultEtc, []string{"rotate-key"}, bytes.NewReader(stdin), &out, d.errw); err != nil {
		return fmt.Errorf("the rotation did not finish (the executor stays stopped; run the command again to resume): %w", err)
	}
	var res struct {
		Version int32 `json:"version"`
		Rows    int   `json:"rows"`
		TOTPs   int   `json:"totps"`
		Resumed bool  `json:"resumed"`
		Already bool  `json:"already"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Version < 2 {
		return fmt.Errorf("executor rotate-key: malformed result (the executor stays stopped; run the command again to resume): %v", err)
	}
	if err := install.PromoteSecret(p); err != nil {
		return err
	}
	if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "up", "-d", "executor"); err != nil {
		return fmt.Errorf("start the executor: %w", err)
	}
	printf(d.out, "sealing key rotated to version %d (%d registry rows, %d change TOTP secrets); the previous key is gone\n",
		res.Version, res.Rows, res.TOTPs)
	return nil
}

const keysUsage = "usage: nmsctl keys rotate ticket|read|write|backup"

/* keysCmd is "nmsctl keys rotate ticket|read|write|backup" (on the host). */
func keysCmd(ctx context.Context, d deps, args []string) error {
	if len(args) != 1 {
		return errors.New(keysUsage)
	}
	switch args[0] {
	case "ticket":
		return ticketRotate(ctx, d)
	case "read", "write", "backup":
		return domainRotate(ctx, d, args[0])
	}
	return errors.New(keysUsage)
}

/*
ticketRotate is "nmsctl keys rotate ticket": a new Ed25519 pair for the session
tickets. ticket.pub (executor) is replaced before ticket.key (api), both by
rename from staged files, then both services restart: a ticket signed with
the old key no longer verifies, and the executor refuses tickets issued
before its start anyway (no overlap: a ticket lives 60 s, the panel asks
for a new one). Interrupted, the command run again resumes from the staged
key.
*/
func ticketRotate(ctx context.Context, d deps) error {
	keyP, pubP := filepath.Join(secretsDir, "ticket.key"), filepath.Join(secretsDir, "ticket.pub")
	seedB64, err := staged(keyP, install.ContainerUID, d, func() ([]byte, error) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		defer clear(priv)
		return []byte(base64.StdEncoding.EncodeToString(priv.Seed())), nil
	})
	if err != nil {
		return err
	}
	defer clear(seedB64)
	seed, err := base64.StdEncoding.DecodeString(string(seedB64))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("staged %s%s is malformed: remove it and run again", keyP, install.NextSuffix)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	pub := []byte(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	clear(priv)
	cur, err := os.ReadFile(pubP) // #nosec G304 -- a file of the secrets directory
	if err != nil {
		return err
	}
	if !bytes.Equal(bytes.TrimSpace(cur), pub) {
		/* A staged ticket.pub of another key (staged before a crash) is replaced: the staged ticket.key decides. */
		if err := os.Remove(pubP + install.NextSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := install.StageSecret(pubP, pub, install.ExecutorUID, d.sys.Chown); err != nil {
			return err
		}
		if err := install.PromoteSecret(pubP); err != nil {
			return err
		}
	}
	if err := install.PromoteSecret(keyP); err != nil {
		return err
	}
	if err := install.Compose(ctx, d.sys, install.DefaultEtc, d.errw, "restart", "api", "executor"); err != nil {
		return fmt.Errorf("restart api and executor: %w", err)
	}
	printf(d.out, "session ticket key rotated; tickets signed with the previous key are refused\n")
	return nil
}
