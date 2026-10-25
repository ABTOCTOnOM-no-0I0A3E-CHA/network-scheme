package deploy_test

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func dockerfile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("docker/" + name) // #nosec G304 -- fixed file in the repository
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

/* builds lists the packages a Dockerfile compiles ("go build ... ./cmd/x"). */
var builds = regexp.MustCompile(`go build [^\n]*?(\./cmd/[a-z]+)`)

/* pinned is a FROM line with a digest. */
var pinned = regexp.MustCompile(`^FROM \S+@sha256:[a-f0-9]{64}( AS \w+)?\s*$`)

/* Every base image is pinned by digest. */
func TestBaseImagesPinned(t *testing.T) {
	for _, name := range []string{"api.Dockerfile", "gateway.Dockerfile", "executor.Dockerfile"} {
		for _, l := range strings.Split(dockerfile(t, name), "\n") {
			if strings.HasPrefix(l, "FROM ") && !pinned.MatchString(l) {
				t.Errorf("%s: %q is not pinned by digest", name, l)
			}
		}
	}
}

/* The api image (api, nmsctl, poller, eventd) carries no executor; the executor image carries only the executor, as uid 65533. */
func TestExecutorOnlyInItsOwnImage(t *testing.T) {
	api := dockerfile(t, "api.Dockerfile")
	if strings.Contains(api, "cmd/executor") || strings.Contains(api, "/executor") {
		t.Error("api.Dockerfile builds or copies the executor")
	}
	var got []string
	for _, m := range builds.FindAllStringSubmatch(api, -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, " ") != "./cmd/api ./cmd/nmsctl ./cmd/poller ./cmd/eventd" {
		t.Errorf("api.Dockerfile builds %v", got)
	}
	if builds.MatchString(dockerfile(t, "gateway.Dockerfile")) {
		t.Error("gateway.Dockerfile builds a Go binary")
	}

	ex := dockerfile(t, "executor.Dockerfile")
	got = nil
	for _, m := range builds.FindAllStringSubmatch(ex, -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, " ") != "./cmd/executor" {
		t.Errorf("executor.Dockerfile builds %v, want only ./cmd/executor", got)
	}
	for _, want := range []string{"\nUSER 65533:65533\n", "\nENTRYPOINT [\"/executor\"]\n", "--chown=65533:65533 --chmod=0700 /out/state /var/lib/executor"} {
		if !strings.Contains(ex, want) {
			t.Errorf("executor.Dockerfile lacks %q", strings.TrimSpace(want))
		}
	}
	if n := strings.Count(ex, "\nCOPY --from=build "); n != 2 {
		t.Errorf("executor.Dockerfile copies %d things from the build stage, want the binary and the state directory", n)
	}
}
