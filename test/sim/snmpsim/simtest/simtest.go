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
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cf := make([]testcontainers.ContainerFile, 0, len(files))
	for _, f := range files {
		cf = append(cf, testcontainers.ContainerFile{
			HostFilePath:      f,
			ContainerFilePath: "/data/" + filepath.Base(f),
			FileMode:          0o444,
		})
	}
	c := run(ctx, t, testcontainers.ContainerRequest{
		ExposedPorts: []string{"161/udp"},
		Files:        cf,
		Cmd:          []string{"sh", "-c", "mkdir -p /tmp/idx && chmod 777 /tmp/idx && exec " + responder("/tmp/idx") + " --agent-udpv4-endpoint=0.0.0.0:161"},
		WaitingFor:   wait.ForLog("Listening at UDP/IPv4 endpoint").WithStartupTimeout(2 * time.Minute),
	})
	host := hostIP(ctx, t, c)
	port, err := c.MappedPort(ctx, "161/udp")
	if err != nil {
		t.Fatal(err)
	}
	return netip.AddrPortFrom(host, uint16(port.Num())) //nolint:gosec // port range is checked by Docker
}

/*
StartMany runs one simulator listening on the n UDP ports first..first+n-1,
with every .snmprec file of dir (a directory named "data") as data, and
returns the address of each port in order. Every portsPerProcess ports get
their own snmpsim process: one Python process answers a few hundred requests
a second, far fewer than a thousand devices ask of it. On Linux the ports are reached on
the container's own address; elsewhere (Docker Desktop) they are published on
127.0.0.1 under the same numbers, which takes Docker a minute or two for a
thousand ports.
*/
func StartMany(t testing.TB, dir string, first, n int) []netip.AddrPort {
	t.Helper()
	if filepath.Base(dir) != "data" {
		t.Fatalf("simtest: %s: the data directory must be named data", dir)
	}
	last := first + n - 1
	if first < 1 || n < 1 || last > 65535 {
		t.Fatalf("simtest: ports %d..%d out of range", first, last)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	req := testcontainers.ContainerRequest{
		/* A directory is copied under the parent of ContainerFilePath; 0o555 keeps it listable. */
		Files: []testcontainers.ContainerFile{{HostFilePath: dir, ContainerFilePath: "/data", FileMode: 0o555}},
		/* The endpoints are built in the container: a thousand flags overflow a Windows command line. */
		Cmd: []string{"sh", "-c", fmt.Sprintf(`for lo in $(seq %[1]d %[2]d %[3]d); do
				hi=$((lo + %[2]d - 1)); [ "$hi" -gt %[3]d ] && hi=%[3]d
				mkdir -p /tmp/idx$lo && chmod 777 /tmp/idx$lo
				set --; for p in $(seq "$lo" "$hi"); do set -- "$@" --agent-udpv4-endpoint=0.0.0.0:$p; done
				%[4]s "$@" &
			done; wait`, first, portsPerProcess, last, responder("/tmp/idx$lo"))},
		WaitingFor: wait.ForLog("Listening at UDP/IPv4 endpoint").WithOccurrence(n).WithStartupTimeout(10 * time.Minute),
	}
	direct := runtime.GOOS == "linux"
	if !direct {
		bind := network.PortMap{}
		for p := first; p <= last; p++ {
			spec := fmt.Sprintf("%d/udp", p)
			req.ExposedPorts = append(req.ExposedPorts, spec)
			bind[network.MustParsePort(spec)] = []network.PortBinding{{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: strconv.Itoa(p)}}
		}
		req.HostConfigModifier = func(hc *dockercontainer.HostConfig) { hc.PortBindings = bind }
	}
	c := run(ctx, t, req)
	host := netip.MustParseAddr("127.0.0.1")
	if direct {
		ip, err := c.ContainerIP(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if host, err = netip.ParseAddr(ip); err != nil {
			t.Fatalf("container address %q: %v", ip, err)
		}
	}
	addrs := make([]netip.AddrPort, n)
	for i := range addrs {
		addrs[i] = netip.AddrPortFrom(host, uint16(first+i)) //nolint:gosec // range checked above
	}
	return addrs
}

/* portsPerProcess is how many endpoints one snmpsim process of StartMany serves. */
const portsPerProcess = 50

/* responder is the snmpsim command with the simulator's v3 user and its index in cacheDir; endpoints are appended. */
func responder(cacheDir string) string {
	return "snmpsim-command-responder --process-user=nobody --process-group=nogroup --cache-dir=" + cacheDir +
		" --data-dir=/data" +
		" --v3-user=" + V3User + " --v3-auth-proto=SHA256 --v3-auth-key=" + V3AuthKey +
		" --v3-priv-proto=AES --v3-priv-key=" + V3PrivKey
}

/* run builds (cached) and starts the simulator image with req; skipped with -short or without Docker. */
func run(ctx context.Context, t testing.TB, req testcontainers.ContainerRequest) testcontainers.Container {
	t.Helper()
	if testing.Short() {
		t.Skip("snmpsim container skipped with -short")
	}
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
	req.FromDockerfile = testcontainers.FromDockerfile{
		Context:    filepath.Join(filepath.Dir(self), ".."),
		Dockerfile: "Dockerfile",
		Repo:       "nms-snmpsim",
		Tag:        "1.2.2",
		KeepImage:  true,
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
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
	return c
}

/* hostIP is the address under which the container's published ports are reached. */
func hostIP(ctx context.Context, t testing.TB, c testcontainers.Container) netip.Addr {
	t.Helper()
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if host == "localhost" {
		host = "127.0.0.1" /* avoid the IPv6 loopback, which Docker Desktop on Windows may not publish */
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		t.Fatalf("docker host %q is not an IP: %v", host, err)
	}
	return ip
}
