package mount

import "pigcloud/internal/mount/vfs"

type MountBackend interface {
	Mount(mountpoint string, v *vfs.VFS) error
	Unmount() error
}
