package spawn

import (
	"pigcloud/internal/mount"
	"strings"
	"testing"
)

func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

func TestMountServeArgsCarryTheLogLevel(t *testing.T) {
	args := mountServeArgs("/Photos", "P:", 1<<30, 30, mount.ModeSync, false, "debug")

	got, ok := argValue(args, "--log-level")
	if !ok {
		t.Fatalf("--log-level missing from child argv: %v", args)
	}
	if got != "debug" {
		t.Errorf("--log-level = %q, want debug", got)
	}
}

func TestMountServeArgsOmitLogLevelWhenUnset(t *testing.T) {
	args := mountServeArgs("/Photos", "P:", 1<<30, 30, mount.ModeSync, false, "")

	if _, ok := argValue(args, "--log-level"); ok {
		t.Errorf("an unset level must not be passed, so the child keeps its own default: %v", args)
	}
}

func TestMountServeArgsKeepTheExistingContract(t *testing.T) {
	args := mountServeArgs("/Photos", "P:", 4096, 15, mount.ModeVirtual, true, "warn")

	if args[0] != "__mount-serve" {
		t.Fatalf("argv[0] = %q, want __mount-serve", args[0])
	}
	for flag, want := range map[string]string{
		"--remote": "/Photos", "--mountpoint": "P:",
		"--cache-size": "4096", "--poll": "15", "--mode": mount.ModeVirtual,
	} {
		got, ok := argValue(args, flag)
		if !ok || got != want {
			t.Errorf("%s = %q,%v; want %q", flag, got, ok, want)
		}
	}
	if !strings.Contains(strings.Join(args, " "), "--read-only") {
		t.Error("--read-only dropped")
	}
}
