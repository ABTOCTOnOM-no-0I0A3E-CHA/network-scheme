// Command eventd receives syslog and SNMP traps from known devices and stores them (it never writes to devices).
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

	_ "github.com/beekamai/network-scheme/internal/drivers/all" /* links every read driver (trap naming) */

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/eventd"
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
		return errors.New("usage: eventd run|healthcheck [--config eventd.yaml]")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nms/eventd.yaml", "path to eventd.yaml")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.LoadEventD(*cfgPath)
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

/* serve runs until SIGTERM/SIGINT. Secrets come only from the files named in the config. */
func serve(ctx context.Context, cfg config.EventD) error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	priv, pub, err := eventd.ReadKeys(cfg)
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
	return eventd.Run(ctx, cfg, eventd.Deps{Pool: pool, Priv: priv, Pub: pub, Logger: log})
}

/* healthcheck exits 0 when this instance wrote its stats within the last 30 s. */
func healthcheck(ctx context.Context, cfg config.EventD) error {
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
	return eventd.Healthy(ctx, pool, eventd.Instance(cfg))
}
