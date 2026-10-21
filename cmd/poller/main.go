// Command poller collects availability, metrics and inventory from devices (read-only).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/beekamai/network-scheme/internal/drivers/all" /* links every read driver */

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/poller"
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
		return errors.New("usage: poller run|healthcheck [--config poller.yaml]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nms/poller.yaml", "path to poller.yaml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := poller.LoadConfig(*cfgPath)
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

/* serve polls until SIGTERM/SIGINT. Secrets come only from the files named in the config. */
func serve(ctx context.Context, cfg poller.Config) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	priv, pub, err := cfg.ReadKeys()
	if err != nil {
		return err
	}
	pw, err := config.ReadSecretFile(cfg.DB.PasswordFile)
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.DB, pw)
	if err != nil {
		return err
	}
	defer pool.Close()
	return poller.New(cfg, poller.Deps{Pool: pool, Priv: priv, Pub: pub, Logger: log}).Run(ctx)
}

/* healthcheck exits 0 when this poller wrote a heartbeat within the last 45 s. */
func healthcheck(ctx context.Context, cfg poller.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pw, err := config.ReadSecretFile(cfg.DB.PasswordFile)
	if err != nil {
		return err
	}
	pool, err := store.Open(ctx, cfg.DB, pw)
	if err != nil {
		return err
	}
	defer pool.Close()
	return poller.Healthy(ctx, pool, cfg.PollerID)
}
