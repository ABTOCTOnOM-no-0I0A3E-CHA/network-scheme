package httpapi_test

import (
	"os/exec"
	"strings"
	"testing"
)

func goList(t *testing.T, args ...string) []string {
	t.Helper()
	out, err := exec.Command("go", append([]string{"list"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("go list %v: %v\n%s", args, err, out)
	}
	return strings.Fields(string(out))
}

/*
The api validates show requests with the showspec leaf package only: the
handlers import neither SSH nor driver code, and the api binary links no
concrete read driver (they are registered by internal/drivers/all, which the
poller imports). internal/ssh itself is still reachable through the driver
interface types the inventory and metrics stores use.
*/
func TestAPILinksNoDriverImplementationsOrSSH(t *testing.T) {
	const mod = "github.com/beekamai/network-scheme/"
	for _, imp := range goList(t, "-f", `{{join .Imports "\n"}}`, mod+"internal/httpapi") {
		if imp == mod+"internal/ssh" || imp == mod+"internal/drivers" || (strings.HasPrefix(imp, mod+"internal/drivers/") && imp != mod+"internal/drivers/showspec") {
			t.Errorf("internal/httpapi imports %s", imp)
		}
	}
	deps := goList(t, "-deps", mod+"cmd/api")
	for _, bad := range []string{"internal/drivers/all", "internal/drivers/eltexmes", "internal/drivers/eltexesr", "internal/drivers/generic", "internal/backup/open", "cmd/executor"} {
		for _, d := range deps {
			if strings.HasPrefix(d, mod+bad) {
				t.Errorf("cmd/api depends on %s", d)
			}
		}
	}
	found := false
	for _, d := range deps {
		found = found || d == mod+"internal/drivers/showspec"
	}
	if !found {
		t.Error("cmd/api does not link showspec")
	}
}
