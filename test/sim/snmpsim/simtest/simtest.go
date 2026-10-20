/*
Package simtest starts an snmpsim container for tests. Every .snmprec file
passed to Start becomes an agent: SNMPv1/v2c community and SNMPv3 context name
are the file name without extension. The SNMPv3 user is V3User with
SHA-256 authentication and AES privacy.
*/
package simtest

import (
	"bufio"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/beekamai/network-scheme/internal/creds"
	"github.com/beekamai/network-scheme/internal/secret"
)

/* Fixed SNMPv3 test credentials of the simulator; synthetic, not secrets. */
const (
	V3User    = "simuser"
	V3AuthKey = "sim-auth-key-0123456789" // #nosec G101 -- simulator test value
	V3PrivKey = "sim-priv-key-0123456789" // #nosec G101 -- simulator test value
)

/* Fixture returns the absolute path of a file in test/fixtures/snmp. */
func Fixture(name string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures", "snmp", name)
}

/*
FixtureSys returns the sysObjectID and sysDescr values of a fixture file in
test/fixtures/snmp without starting the simulator (for driver Match tests).
*/
func FixtureSys(t testing.TB, name string) (sysObjectID, sysDescr string) {
	t.Helper()
	f, err := os.Open(Fixture(name))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f) /* ScanLines also drops a trailing CR */
	for sc.Scan() {
		p := strings.SplitN(sc.Text(), "|", 3)
		switch {
		case len(p) == 3 && p[0] == "1.3.6.1.2.1.1.2.0":
			sysObjectID = p[2]
		case len(p) == 3 && p[0] == "1.3.6.1.2.1.1.1.0":
			sysDescr = p[2]
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if sysObjectID == "" {
		t.Fatalf("%s has no sysObjectID", name)
	}
	return sysObjectID, sysDescr
}

/* V2Cred is an snmp2c credential for the given community (a fixture name). */
func V2Cred(community string) creds.Credential {
	return creds.Credential{Kind: "snmp2c", Community: secret.New(community)}
}

/* V3Cred is the simulator's snmp3 authPriv credential. */
func V3Cred() creds.Credential {
	return creds.Credential{
		Kind: "snmp3", User: V3User,
		AuthProto: "SHA256", AuthKey: secret.New(V3AuthKey),
		PrivProto: "AES", PrivKey: secret.New(V3PrivKey),
	}
}

/*
Start builds (cached) and runs the simulator with the given .snmprec files and
returns its UDP address on 127.0.0.1. The test is skipped with -short or when
Docker is unavailable. The container is removed when the test ends.
*/
func Start(t testing.TB, files ...string) netip.AddrPort {
	t.Helper()
	if testing.Short() {
		t.Skip("snmpsim container skipped with -short")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if p, err := testcontainers.NewDockerProvider(); err != nil {
		t.Skipf("docker unavailable: %v", err)
	} else {
		err = p.Health(ctx)
		_ = p.Close()
		if err != nil {
			t.Skipf("docker unavailable: %v", err)
		}
	}

	_, self, _, _ := runtime.Caller(0)
	cf := make([]testcontainers.ContainerFile, 0, len(files))
	for _, f := range files {
		cf = append(cf, testcontainers.ContainerFile{
			HostFilePath:      f,
			ContainerFilePath: "/data/" + filepath.Base(f),
			FileMode:          0o444,
		})
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    filepath.Join(filepath.Dir(self), ".."),
				Dockerfile: "Dockerfile",
				Repo:       "nms-snmpsim",
				Tag:        "1.2.2",
				KeepImage:  true,
			},
			ExposedPorts: []string{"161/udp"},
			Files:        cf,
			Cmd: []string{
				"sh", "-c",
				"mkdir -p /tmp/idx && chmod 777 /tmp/idx && exec snmpsim-command-responder" +
					" --process-user=nobody --process-group=nogroup --cache-dir=/tmp/idx" +
					" --data-dir=/data --agent-udpv4-endpoint=0.0.0.0:161" +
					" --v3-user=" + V3User + " --v3-auth-proto=SHA256 --v3-auth-key=" + V3AuthKey +
					" --v3-priv-proto=AES --v3-priv-key=" + V3PrivKey,
			},
			WaitingFor: wait.ForLog("Listening at UDP/IPv4 endpoint").WithStartupTimeout(2 * time.Minute),
		},
		Started: true,
	})
	if c != nil {
		t.Cleanup(func() {
			tctx, tcancel := context.WithTimeout(context.Background(), time.Minute)
			defer tcancel()
			_ = c.Terminate(tctx, testcontainers.StopTimeout(time.Second)) /* the simulator ignores SIGTERM as PID 1 */
		})
	}
	if err != nil {
		t.Fatalf("start snmpsim: %v", err)
	}

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if host == "localhost" {
		host = "127.0.0.1" /* avoid the IPv6 loopback, which Docker Desktop on Windows may not publish */
	}
	port, err := c.MappedPort(ctx, "161/udp")
	if err != nil {
		t.Fatal(err)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		t.Fatalf("docker host %q is not an IP: %v", host, err)
	}
	return netip.AddrPortFrom(ip, uint16(port.Num())) //nolint:gosec // port range is checked by Docker
}
