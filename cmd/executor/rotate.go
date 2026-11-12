package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"

	"github.com/beekamai/network-scheme/cmd/executor/internal/config"
	"github.com/beekamai/network-scheme/cmd/executor/internal/rotate"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/state"
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
	raw, err := io.ReadAll(io.LimitReader(in, 4096))
	if err != nil {
		return err
	}
	defer clear(raw)
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if len(lines) != 2 || !rotateOperatorRe.Match(lines[1]) {
		return errors.New("rotate-key: stdin must hold the next key (base64) and the operator, one line each")
	}
	nk, err := nmsconfig.ParseKey(lines[0])
	if err != nil {
		return errors.New("rotate-key: the next key: " + err.Error())
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
	rep, err := rotate.Sealing(ctx, rotate.Config{Pool: pool, Old: old, Next: next, StateDir: cfg.StateDir, Operator: string(lines[1])})
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(rotateResult{rep.Version, rep.Rows, rep.TOTPs, rep.Resumed, rep.Already})
}

/* keyVersion sets the sealing key's version from the state file (a fresh install, or an unreadable file that freezes anyway: the first). */
func keyVersion(keys *seal.Keys, stateDir string) {
	if f, err := state.Load(filepath.Join(stateDir, "state"), keys.State()); err == nil {
		keys.SetVersion(f.SealVersion())
	}
}
