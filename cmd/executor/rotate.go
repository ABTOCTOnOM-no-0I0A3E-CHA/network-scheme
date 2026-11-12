package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"

	"github.com/beekamai/network-scheme/cmd/executor/internal/config"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/rotate"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
	"github.com/beekamai/network-scheme/cmd/executor/internal/wcreds"
	nmsconfig "github.com/beekamai/network-scheme/internal/config"
)

var rotateOperatorRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{0,64}$`)

/* rotateResult is the one JSON line rotate-key prints for nmsctl. */
type rotateResult struct {
	Version int32 `json:"version"`
	Rows    int   `json:"rows"`
	TOTPs   int   `json:"totps"`
	Resumed bool  `json:"resumed"`
	Already bool  `json:"already"`
}

/*
rotateKey is "executor rotate-key": the sealing key rotation (package
rotate), run by nmsctl in a one-shot container of the executor image while
the daemon is stopped. stdin holds the next key (base64, one line) and the
host operator (one line): never argv or the environment.
*/
func rotateKey(ctx context.Context, cfg config.Config, in io.Reader, out io.Writer) error {
	nk, operator, err := nextKey(in)
	if err != nil {
		return err
	}
	next, err := seal.Derive(nk)
	clear(nk[:])
	if err != nil {
		return err
	}
	defer next.Wipe()
	old, err := seal.Load(cfg.SealingKeyFile)
	if err != nil {
		return err
	}
	defer old.Wipe()
	pool, err := openPool(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	reg := registry.New(pool, old, filepath.Join(cfg.StateDir, "state"))
	rep, err := rotate.Sealing(ctx, rotate.Config{Reg: reg, Old: old, Next: next, StateDir: cfg.StateDir, Operator: operator})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(rotateResult{rep.Version, rep.Rows, rep.TOTPs, rep.Resumed, rep.Already})
}

/* nextKey reads a rotation's stdin: the next key (base64) and the host operator, one line each; the caller wipes the key. */
func nextKey(in io.Reader) (*[32]byte, string, error) {
	raw, err := io.ReadAll(io.LimitReader(in, 4096))
	if err != nil {
		return nil, "", err
	}
	defer clear(raw)
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if len(lines) != 2 || !rotateOperatorRe.Match(lines[1]) {
		return nil, "", errors.New("stdin must hold the next key (base64) and the operator, one line each")
	}
	k, err := nmsconfig.ParseKey(lines[0])
	if err != nil {
		return nil, "", errors.New("the next key: " + err.Error())
	}
	return k, string(lines[1]), nil
}

/*
resealWrite is "executor reseal-write": the write-domain key rotation
(rotate.WriteDomain), run by nmsctl in a one-shot container while the
daemon is stopped; stdin as rotate-key's, with the next write-domain key.
*/
func resealWrite(ctx context.Context, cfg config.Config, in io.Reader, out io.Writer) error {
	next, operator, err := nextKey(in)
	if err != nil {
		return err
	}
	defer clear(next[:])
	old, _, err := wcreds.LoadKey(cfg.WriteKeyFile)
	if err != nil {
		return err
	}
	defer clear(old[:])
	sk, err := seal.Load(cfg.SealingKeyFile)
	if err != nil {
		return err
	}
	defer sk.Wipe()
	keyVersion(sk, cfg.StateDir)
	pool, err := openPool(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	n, err := rotate.WriteDomain(ctx, registry.New(pool, sk, filepath.Join(cfg.StateDir, "state")), old, next, operator)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "write credentials re-sealed: %d\n", n)
	return err
}

/* keyVersion sets the sealing key's version from the state file (a fresh install, or an unreadable file that freezes anyway: the first). */
func keyVersion(keys *seal.Keys, stateDir string) {
	if f, err := state.Load(filepath.Join(stateDir, "state"), keys.State()); err == nil {
		keys.SetVersion(f.SealVersion())
	}
}
