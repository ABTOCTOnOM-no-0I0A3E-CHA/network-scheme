// Command api is the panel backend. Phase 0: only "migrate" is functional.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/store"
)

/* migratorUser is the only role allowed to change the schema. */
const migratorUser = "nms_migrator"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: api migrate|serve|healthcheck")
	}
	switch args[0] {
	case "migrate":
		return migrate(ctx, args[1:])
	case "serve", "healthcheck":
		return fmt.Errorf("%s: not implemented yet", args[0])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func migrate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nms/api.yaml", "path to api.yaml")
	pwFile := fs.String("password-file", "/run/secrets/db_migrator_password", "file with the nms_migrator password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadAPI(*cfgPath)
	if err != nil {
		return err
	}
	pw, err := config.ReadSecretFile(*pwFile)
	if err != nil {
		return err
	}
	db := cfg.DB
	db.User = migratorUser
	return store.Migrate(ctx, db, pw)
}
