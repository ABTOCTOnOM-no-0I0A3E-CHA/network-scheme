/*
Command executor is the only service that may change devices: run (the
daemon), healthcheck (container health check) and admin (host-only
administration, reached through docker compose exec).
*/
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/beekamai/network-scheme/cmd/executor/internal/config"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	nmsconfig "github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/store"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: executor run|healthcheck [--config executor.yaml] | admin")
	}
	if args[0] == "admin" {
		/* The administration socket and its commands come with nmsctl executor. */
		return errors.New("admin: not implemented")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nms/executor.yaml", "path to executor.yaml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "run":
		return serve(ctx, cfg)
	case "healthcheck":
		return healthcheck(ctx, cfg)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

/*
serve checks that every file the executor needs is present and well-formed,
opens the database, verifies the registry (bootstrapping a fresh install,
freezing on tampering) and keeps verifying it every 30 s until
SIGTERM/SIGINT. It listens nowhere yet and touches no device.
*/
func serve(ctx context.Context, cfg config.Config) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := checkFiles(cfg); err != nil {
		return err
	}
	pw, err := nmsconfig.ReadSecretFile(cfg.DB.PasswordFile)
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.DB, pw, registry.PinSession)
	pw.Wipe()
	if err != nil {
		return err
	}
	defer pool.Close()
	keys, err := seal.Load(cfg.SealingKeyFile)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	guard := freeze.New(registry.New(pool, keys, filepath.Join(cfg.StateDir, "state")), pool, log)
	if err := guard.Start(ctx); err != nil {
		return err
	}
	frozen, _ := guard.Frozen()
	log.Info("executor started", slog.String("xnet", cfg.ListenXnet.String()), slog.Bool("frozen", frozen))
	guard.Run(ctx)
	log.Info("shutting down")
	return nil
}

/*
checkFiles fails on a missing, unreadable or malformed key, certificate,
state directory or host file, so a wrong owner or mode of a secret stops the
container at once. The keys are read and wiped again.
*/
func checkFiles(cfg config.Config) error {
	for _, f := range []string{cfg.SealingKeyFile, cfg.WriteKeyFile, cfg.BackupKeyFile, cfg.TicketPubKeyFile} {
		k, err := nmsconfig.ReadKeyFile(f)
		if err != nil {
			return err
		}
		clear(k[:])
	}
	if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
		return fmt.Errorf("tls certificate: %w", err)
	}
	ca, err := os.ReadFile(cfg.ClientCAFile) // #nosec G304 -- path from the executor configuration
	if err != nil {
		return fmt.Errorf("client ca: %w", err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(ca) {
		return fmt.Errorf("client ca %s: no PEM certificate", cfg.ClientCAFile)
	}
	for _, f := range []string{cfg.PolicyFile, cfg.EgressFile} {
		if _, err := os.ReadFile(f); err != nil { // #nosec G304 -- path from the executor configuration
			return err
		}
	}
	/* The state file is written here (temporary file and rename): the directory must be writable. */
	probe, err := os.CreateTemp(cfg.StateDir, ".probe-")
	if err != nil {
		return fmt.Errorf("state_dir: %w", err)
	}
	return errors.Join(probe.Close(), os.Remove(probe.Name()))
}

/* healthcheck exits 0 when the executor's database role can connect. */
func healthcheck(ctx context.Context, cfg config.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pw, err := nmsconfig.ReadSecretFile(cfg.DB.PasswordFile)
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.DB, pw)
	pw.Wipe()
	if err != nil {
		return err
	}
	pool.Close()
	return nil
}
