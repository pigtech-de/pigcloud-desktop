//go:build !windows

package fuse

import "os"

func IsAvailable() bool {
	if _, err := os.Stat("/dev/fuse"); err == nil {
		return true
	}
	for _, p := range []string{
		"/Library/Filesystems/macfuse.fs",
		"/Library/Filesystems/fuse-t.fs",
		"/usr/local/lib/libfuse.dylib",
	} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func InstallHint() string {
	return `FUSE is required for mount.

  Linux:   sudo apt install fuse3   (or your distro's equivalent)
  macOS:   brew install macfuse      (or install FUSE-T from https://www.fuse-t.org)

  Then run 'pc mn' again.`
}
