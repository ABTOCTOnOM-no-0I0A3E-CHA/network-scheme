// Package testdb provides one shared TimescaleDB container per test package.
package testdb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/beekamai/network-scheme/internal/config"
	"github.com/beekamai/network-scheme/internal/secret"
	"github.com/beekamai/network-scheme/internal/store"
)

/*
Image is the database image used by tests and, by reference, by deployment
templates: TimescaleDB 2.30.2 on PostgreSQL 17, pinned by digest.
*/
const Image = "timescale/timescaledb:2.30.2-pg17@sha256:b346edcdb51a1fd6020e3965e0bd1c9f3406fa6d5fbce1e28f4852587ef934e2"

const dbName = "nms"

var roles = []string{"nms_migrator", "nms_api", "nms_cli", "nms_poller", "nms_eventd", "postgres"}

// Env is a running, migrated test database.
type Env struct {
	pools     map[string]*pgxpool.Pool
	cfg       func(user string) config.DB
	passwords map[string]string
}

// Pool returns a pool connected as role: nms_migrator, nms_api, nms_cli, nms_poller, nms_eventd or postgres.
func (e *Env) Pool(role string) *pgxpool.Pool {
	p, ok := e.pools[role]
	if !ok {
		panic("testdb: unknown role " + role)
	}
	return p
}

// Config returns the connection settings and password of role, to open a pool with other settings.
func (e *Env) Config(role string) (config.DB, secret.Secret) {
	if _, ok := e.passwords[role]; !ok {
		panic("testdb: unknown role " + role)
	}
	return e.cfg(role), secret.New(e.passwords[role])
}

// Connect opens one connection as role to database db and closes it (to check CONNECT privileges).
func (e *Env) Connect(ctx context.Context, role, db string) error {
	c := e.cfg(role)
	c.Name = db
	p, err := store.Open(ctx, c, secret.New(e.passwords[role]))
	if err != nil {
		return err
	}
	p.Close()
	return nil
}

var (
	once      sync.Once
	shared    *Env
	startErr  error
	container testcontainers.Container
)

/*
New returns the package-wide Env, starting the container on first use. The
test is skipped under -short or when Docker is unavailable.
*/
func New(t *testing.T) *Env {
	t.Helper()
	if testing.Short() {
		t.Skip("testdb: skipped in -short mode (needs Docker)")
	}
	once.Do(func() { shared, startErr = start() })
	if startErr != nil {
		if errors.Is(startErr, errNoDocker) {
			t.Skipf("testdb: Docker is unavailable: %v", startErr)
		}
		t.Fatalf("testdb: %v", startErr)
	}
	return shared
}

/*
Main runs the package tests and then tears the container down. Call it from
TestMain; without it the Ryuk reaper still removes the container.
*/
func Main(m *testing.M) {
	code := m.Run()
	if container != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		_ = container.Terminate(ctx)
		cancel()
	}
	os.Exit(code)
}

var errNoDocker = errors.New("docker daemon not reachable")

func checkDocker(ctx context.Context) error {
	p, err := testcontainers.NewDockerProvider()
	if err != nil {
		return fmt.Errorf("%w: %v", errNoDocker, err)
	}
	defer func() { _ = p.Close() }()
	if err := p.Health(ctx); err != nil {
		return fmt.Errorf("%w: %v", errNoDocker, err)
	}
	return nil
}

func repoRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("cannot locate testdb source")
	}
	return filepath.Join(filepath.Dir(file), "..", ".."), nil
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func start() (*Env, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	if err := checkDocker(ctx); err != nil {
		return nil, err
	}
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}
	passwords := map[string]string{}
	var files []testcontainers.ContainerFile
	/* Mirror production: every password is a file under /run/secrets. */
	for role, secretName := range map[string]string{
		"postgres":     "postgres_password",
		"nms_migrator": "db_migrator_password",
		"nms_api":      "db_api_password",
		"nms_cli":      "db_cli_password",
		"nms_poller":   "db_poller_password",
		"nms_eventd":   "db_eventd_password",
	} {
		pw, err := randomPassword()
		if err != nil {
			return nil, err
		}
		passwords[role] = pw
		files = append(files, testcontainers.ContainerFile{
			Reader:            bytes.NewReader([]byte(pw)),
			ContainerFilePath: "/run/secrets/" + secretName,
			FileMode:          0o444,
		})
	}

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        Image,
			ExposedPorts: []string{"5432/tcp"},
			/* As in the deployment: no TimescaleDB telemetry. */
			Cmd: []string{"postgres", "-c", "timescaledb.telemetry_level=off"},
			Env: map[string]string{ // #nosec G101 -- path of a secret file, not a secret
				"POSTGRES_DB":            dbName,
				"POSTGRES_PASSWORD_FILE": "/run/secrets/postgres_password",
			},
			Files: files,
			/*
				Mirror production: compose bind-mounts deploy/postgres/initdb over the
				directory, so the image's own init scripts never run.
			*/
			HostConfigModifier: func(hc *dockercontainer.HostConfig) {
				hc.Mounts = append(hc.Mounts, mount.Mount{
					Type: mount.TypeBind, Source: filepath.Join(root, "deploy", "postgres", "initdb"),
					Target: "/docker-entrypoint-initdb.d", ReadOnly: true,
				})
			},
			/* The entrypoint restarts the server after init scripts: wait for the second start. */
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		return nil, fmt.Errorf("start container: %w", err)
	}
	container = c

	host, err := c.Host(ctx)
	if err != nil {
		return nil, err
	}
	if host == "localhost" {
		host = "127.0.0.1" /* avoid the IPv6 loopback, which Docker Desktop on Windows may not publish */
	}
	port, err := c.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, err
	}
	dbCfg := func(user string) config.DB {
		return config.DB{Host: host, Port: int(port.Num()), Name: dbName, User: user}
	}

	if err := store.Migrate(ctx, dbCfg("nms_migrator"), secret.New(passwords["nms_migrator"])); err != nil {
		return nil, err
	}
	env := &Env{pools: map[string]*pgxpool.Pool{}, cfg: dbCfg, passwords: passwords}
	for _, role := range roles {
		p, err := store.Open(ctx, dbCfg(role), secret.New(passwords[role]))
		if err != nil {
			return nil, fmt.Errorf("open pool %s: %w", role, err)
		}
		env.pools[role] = p
	}
	return env, nil
}
