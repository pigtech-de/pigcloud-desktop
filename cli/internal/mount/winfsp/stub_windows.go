//go:build windows && !cgo

package winfsp

import (
	"fmt"

	"pigcloud/internal/mount/vfs"
)

type Backend struct{}

func New() *Backend {
	return &Backend{}
}

func (b *Backend) Mount(mountpoint string, v *vfs.VFS) error {
	return fmt.Errorf("mount is not available in this build (requires CGo + WinFsp). " +
		"Install WinFsp from https://winfsp.dev and rebuild with CGO_ENABLED=1")
}

func (b *Backend) Unmount() error {
	return nil
}
