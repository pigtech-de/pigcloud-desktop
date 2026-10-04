package e2ee

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

var mobileGraph = []string{
	"pigcloud/internal/crypto",
	"pigcloud/internal/config",
	"pigcloud/internal/api",
	"pigcloud/internal/e2ee",
	"pigcloud/internal/output",
	"pigcloud/mobile",
}

var hostOnly = []string{
	"os/exec",
	"golang.org/x/term",
	"github.com/zalando/go-keyring",
	"pigcloud/internal/agent",
}

var cliOnly = []string{
	"pigcloud/cmd",
	"pigcloud/internal/agent",
	"pigcloud/internal/agentkeys",
	"pigcloud/internal/cmdutil",
	"pigcloud/internal/completion",
	"pigcloud/internal/keyringstore",
	"pigcloud/internal/progress",
	"pigcloud/internal/mount",
}

var goosMatrix = []string{"linux", "darwin", "android", "ios", "windows"}

func listDeps(t *testing.T, goos string, pkgs ...string) map[string]bool {
	t.Helper()
	cmd := exec.Command("go", append([]string{"list", "-deps"}, pkgs...)...)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		var stderr string
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			stderr = string(exit.Stderr)
		}
		t.Fatalf("go list failed for GOOS=%s: %v\n%s\nA skip here would retire the whole guard silently", goos, err, stderr)
	}
	deps := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			deps[trimmed] = true
		}
	}
	return deps
}

func TestMobileGraphReachesNoHostOnlyPackage(t *testing.T) {
	for _, goos := range goosMatrix {
		t.Run(goos, func(t *testing.T) {
			deps := listDeps(t, goos, mobileGraph...)
			if !deps["pigcloud/internal/crypto"] {
				t.Fatal("go list returned a graph without internal/crypto; the assertions below would prove nothing")
			}
			for _, banned := range hostOnly {
				if deps[banned] {
					t.Errorf("%s is reachable from the mobile graph on %s; the facade cannot link it", banned, goos)
				}
			}
		})
	}
}

func TestTheFacadeLinksNoTerminalPackage(t *testing.T) {
	for _, goos := range goosMatrix {
		t.Run(goos, func(t *testing.T) {
			deps := listDeps(t, goos, "pigcloud/mobile")
			if !deps["pigcloud/mobile"] {
				t.Fatal("go list did not return the facade itself; the assertions below would prove nothing")
			}
			for dep := range deps {
				if !strings.HasPrefix(dep, "pigcloud/") {
					continue
				}
				for _, banned := range cliOnly {
					if dep == banned || strings.HasPrefix(dep, banned+"/") {
						t.Errorf("cli/mobile links %s on %s. That package is the terminal's, not the binding's; "+
							"internal/mount/transfer is the live example, it reaches os/exec on android and must not be bound as is. "+
							"Move what the facade needs into a package the mobile graph may link, and add it to mobileGraph", dep, goos)
					}
				}
			}
		})
	}
}
