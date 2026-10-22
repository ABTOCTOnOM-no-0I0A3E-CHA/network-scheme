//go:build load

/*
Package load is the load test of the poller: 1 000 simulated devices, each an
in-process SNMPv2c agent of test/sim/snmpgo (build tag load, so go test ./... skips it).
*/
package load

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/beekamai/network-scheme/test/sim/snmpsim/simtest"
)

/* fixtures are cycled over the devices so that every read driver takes part. */
var fixtures = []string{"generic-switch.snmprec", "generic-router.snmprec", "eltex-mes.snmprec", "eltex-esr.snmprec"}

const oidSysName = "1.3.6.1.2.1.1.5.0"

/* community is the SNMPv2c community of device i (16+ characters, or the poller rejects it as weak) and the name of its data file. */
func community(i int) string { return fmt.Sprintf("load-device-%04d-ro", i) }

/*
generate writes n .snmprec files into dir: device i answers with fixture
i mod len(fixtures) and its own sysName, under community(i).
*/
func generate(dir string, n int) error {
	src := make([][]string, len(fixtures))
	for k, name := range fixtures {
		raw, err := os.ReadFile(simtest.Fixture(name))
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(bytes.NewReader(raw)) /* ScanLines also drops a trailing CR */
		for sc.Scan() {
			src[k] = append(src[k], sc.Text())
		}
		if err := sc.Err(); err != nil {
			return err
		}
	}
	for i := range n {
		var b strings.Builder
		named := false
		for _, line := range src[i%len(src)] {
			if strings.HasPrefix(line, oidSysName+"|") {
				line = oidSysName + "|4|" + community(i)
				named = true
			}
			b.WriteString(line + "\n")
		}
		if !named {
			return fmt.Errorf("%s has no sysName", fixtures[i%len(fixtures)])
		}
		if err := os.WriteFile(filepath.Join(dir, community(i)+".snmprec"), []byte(b.String()), 0o600); err != nil {
			return err
		}
	}
	return nil
}
