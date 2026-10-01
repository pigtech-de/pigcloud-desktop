//go:build windows

package winfsp

import (
	"os"
	"path/filepath"
)

func IsInstalled() bool {
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WinFsp", "bin", "winfsp-x64.dll"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "WinFsp", "bin", "winfsp-x64.dll"),
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}

	if dir := os.Getenv("WINFSP_INSTALL_DIR"); dir != "" {
		if _, err := os.Stat(filepath.Join(dir, "bin", "winfsp-x64.dll")); err == nil {
			return true
		}
	}

	return false
}

func InstallHint() string {
	return `WinFsp is required for mount on Windows.

  Install with:  winget install WinFsp.WinFsp
  Or:            choco install winfsp
  Or download:   https://winfsp.dev/rel/

  Then restart your terminal and run 'pc mn' again.`
}
