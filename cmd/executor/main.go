/*
Command executor is the only service that may change devices: run (the
daemon), healthcheck (container health check) and admin (host-only
administration, reached through docker compose exec).
*/
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/beekamai/network-scheme/cmd/executor/internal/admin"
	"github.com/beekamai/network-scheme/cmd/executor/internal/authz"
	"github.com/beekamai/network-scheme/cmd/executor/internal/config"
	"github.com/beekamai/network-scheme/cmd/executor/internal/confirm"
	"github.com/beekamai/network-scheme/cmd/executor/internal/freeze"
	"github.com/beekamai/network-scheme/cmd/executor/internal/policy"
	"github.com/beekamai/network-scheme/cmd/executor/internal/registry"
	"github.com/beekamai/network-scheme/cmd/executor/internal/seal"
	"github.com/beekamai/network-scheme/cmd/executor/internal/web"
	nmsconfig "github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/execadmin"
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
		if len(args) > 1 {
			return errors.New("usage: executor admin (one JSON request on stdin; run by nmsctl executor)")
		}
		return relay(ctx, os.Stdin, os.Stdout)
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
freezing on tampering), loads the policy, serves the host-only
administration socket and /x (web: TLS with the gateway's client
certificate, bound only to the executor's address in xnet), and keeps
verifying the registry every 30 s and rereading the policy until
SIGTERM/SIGINT. The authorizer of session tickets and change TOTP (authz)
and the confirm(H) store are built here; authz follows the host's unlocks.
It touches no device yet. It returns (and wipes the keys) only after every
administration command, every /x request and the policy loop ended.
*/
func serve(ctx context.Context, cfg config.Config) error {
	started := time.Now() /* tickets issued before (minus authz's skew) are refused: none survives a restart */
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := checkFiles(cfg); err != nil {
		return err
	}
	pool, err := openPool(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	keys, err := seal.Load(cfg.SealingKeyFile)
	if err != nil {
		return err
	}
	defer keys.Wipe()
	reg := registry.New(pool, keys, filepath.Join(cfg.StateDir, "state"))
	guard := freeze.New(reg, pool, log)
	if err := guard.Start(ctx); err != nil {
		return err
	}
	pol := policy.New(cfg.PolicyFile)
	pub, err := nmsconfig.ReadKeyFile(cfg.TicketPubKeyFile)
	if err != nil {
		return err
	}
	az, err := authz.New(authz.Config{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log,
		TicketKey: ed25519.PublicKey(pub[:]), Started: started, GuardsFile: filepath.Join(cfg.StateDir, "guards")})
	if err != nil {
		return err
	}
	adm := &admin.Admin{Guard: guard, Reg: reg, Keys: keys, Policy: pol, Log: log, Lockouts: az}
	pin, _ := hex.DecodeString(cfg.GatewaySPKI) /* validated by config: 64 hex digits or empty */
	if len(pin) == 0 {
		pin = nil
	}
	x, err := web.New(web.Config{CertFile: cfg.TLSCertFile, KeyFile: cfg.TLSKeyFile, ClientCAFile: cfg.ClientCAFile, GatewaySPKI: pin,
		ExecutorOrigin: cfg.ExecutorOrigin, PanelOrigin: cfg.PanelOrigin, Auth: az, Confirm: confirm.New(az, nil), Log: log,
		State: func() (bool, bool) {
			frozen, _ := guard.Frozen()
			return pol.Current().Enabled(), frozen
		}})
	if err != nil {
		return err
	}
	/* Only the executor's own address in xnet: nothing listens in core. */
	ln, err := listen("tcp", cfg.ListenXnet.String())
	if err != nil {
		return fmt.Errorf("listen_xnet: %w", err)
	}
	old, cur, _ := pol.Reload(true)
	adm.PolicyChanged(ctx, "start", old, cur)
	frozen, _ := guard.Frozen()
	log.Info("executor started", slog.String("xnet", cfg.ListenXnet.String()), slog.Bool("frozen", frozen),
		slog.Bool("enabled", cur.Enabled()))

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := &admin.Server{Path: adminSocket, UID: admin.ExecutorUID, Handle: adm.Handle, Log: log,
		Refused: func(reason string, uid int) { adm.Refused(ctx, reason, uid) }}
	served := make(chan error, 1)
	go func() {
		served <- srv.Serve(ctx)
		cancel() /* no administration socket: stop, the container restarts */
	}()
	webbed := make(chan error, 1)
	go func() {
		webbed <- x.Serve(ctx, ln)
		cancel() /* no /x: stop, the container restarts */
	}()
	reloads := make(chan struct{})
	go func() {
		defer close(reloads)
		pol.Run(ctx, policyEvery, func(old, cur policy.State) { adm.PolicyChanged(ctx, "reload", old, cur) })
	}()
	guard.Run(ctx)
	log.Info("shutting down")
	err = errors.Join(<-served, <-webbed)
	<-reloads
	return err
}

/* adminSocket, policyEvery and listen are variables for the tests. */
var (
	adminSocket = admin.SocketPath
	policyEvery = 2 * time.Second
	listen      = net.Listen
)

/*
relay is "executor admin", run by nmsctl on the host through docker compose
exec -T executor: it forwards the one request line on stdin to the
daemon's socket (as the container's uid, which the daemon checks) and
copies the response line to stdout. It decides nothing.
*/
func relay(ctx context.Context, in io.Reader, out io.Writer) error {
	line, err := bufio.NewReaderSize(io.LimitReader(in, execadmin.MaxRequest+1), execadmin.MaxRequest+1).ReadSlice('\n')
	if err != nil {
		return errors.New("admin: one JSON request line expected on stdin")
	}
	resp, err := admin.Call(ctx, adminSocket, line)
	if err != nil {
		return err
	}
	_, err = out.Write(resp)
	return err
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

/*
openPool connects as the executor's database role, every connection pinned
to pg_catalog and bounded to registry.MaxMessage (the daemon and the
healthcheck alike: a planted oversized message never reaches memory).
*/
func openPool(ctx context.Context, cfg config.Config) (*pgxpool.Pool, error) {
	pw, err := nmsconfig.ReadSecretFile(cfg.DB.PasswordFile)
	if err != nil {
		return nil, err
	}
	defer pw.Wipe()
	return store.Open(ctx, cfg.DB, pw, registry.PinSession, registry.BoundMessages)
}

/* healthcheck exits 0 when the executor's database role can connect. */
func healthcheck(ctx context.Context, cfg config.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	pool, err := openPool(ctx, cfg)
	if err != nil {
		return err
	}
	pool.Close()
	return nil
}
