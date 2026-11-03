package mount

import (
	"pigcloud/internal/mount/fuse"
	"pigcloud/internal/mount/vfs"
	"pigcloud/internal/mount/winfsp"
)

type MountBackend interface {
	Mount(mountpoint string, v *vfs.VFS) error
	Unmount() error
}

func IsWinFspInstalled() bool { return winfsp.IsInstalled() }

func WinFspInstallHint() string { return winfsp.InstallHint() }

func IsFuseAvailable() bool { return fuse.IsAvailable() }

func FuseInstallHint() string { return fuse.InstallHint() }
