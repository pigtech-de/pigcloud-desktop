//go:build !windows

package mount

import (
	"pigcloud/internal/mount/fuse"
	"pigcloud/internal/mount/winfsp"
)

func NewBackend() MountBackend {
	return fuse.New()
}

func IsWinFspInstalled() bool { return winfsp.IsInstalled() }

func WinFspInstallHint() string { return winfsp.InstallHint() }

func IsFuseAvailable() bool { return fuse.IsAvailable() }

func FuseInstallHint() string { return fuse.InstallHint() }
