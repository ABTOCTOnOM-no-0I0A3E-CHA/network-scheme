// Command api is the panel backend: migrate, serve and healthcheck.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beekamai/network-scheme/internal/auth"
	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/devices"
	"github.com/beekamai/network-scheme/internal/httpapi"
	"github.com/beekamai/network-scheme/internal/inventory"
	"github.com/beekamai/network-scheme/internal/jobs"
	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/rbac"
	"github.com/beekamai/network-scheme/internal/store"
)

/* migratorUser is the only role allowed to change the schema. */
const migratorUser = "nms_migrator"

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
		return errors.New("usage: api migrate|serve|healthcheck")
	}
	switch args[0] {
	case "migrate":
		return migrate(ctx, args[1:])
	case "serve":
		return serve(ctx, args[1:])
	case "healthcheck":
		return healthcheck(ctx, args[1:])
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

func configFlag(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nms/api.yaml", "path to api.yaml")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *cfgPath, nil
}

/* HTTP server limits; TLS is terminated by the gateway. */
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 60 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 64 << 10
	shutdownTimeout   = 20 * time.Second
)

/*
serve runs the API until SIGTERM/SIGINT, then drains in-flight requests.
Secrets come only from the files named in the config.
*/
func serve(ctx context.Context, args []string) error {
	cfgPath, err := configFlag("serve", args)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadAPI(cfgPath)
	if err != nil {
		return err
	}
	if cfg.ListenAddr == "" || cfg.DataKeyFile == "" || cfg.PublicOrigin == "" || cfg.ReadKeyVersion == 0 {
		return errors.New("config: listen_addr, public_origin, data_key_file and read_key_version are required")
	}
	key, err := config.ReadKeyFile(cfg.DataKeyFile)
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
	enq, err := jobs.NewEnqueuer(pool)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr: cfg.ListenAddr,
		Handler: httpapi.NewRouter(httpapi.Deps{
			Auth: auth.NewService(pool, key, nil), Users: auth.NewUserStore(pool), RBAC: rbac.NewStore(pool), Pool: pool,
			Devices: devices.NewStore(pool), Inventory: inventory.NewStore(pool), Metrics: metrics.NewStore(pool), Jobs: enq, Cfg: cfg, Clock: time.Now, Logger: log,
		}),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("api listening", slog.String("addr", cfg.ListenAddr))

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

/* healthcheck probes the local API for the container health check: exit 0 or 1. */
func healthcheck(ctx context.Context, args []string) error {
	cfgPath, err := configFlag("healthcheck", args)
	if err != nil {
		return err
	}
	cfg, err := config.LoadAPI(cfgPath)
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen_addr: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/api/health", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck: status %d", resp.StatusCode)
	}
	return nil
}
