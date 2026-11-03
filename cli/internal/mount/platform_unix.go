//go:build !windows

package mount

import "pigcloud/internal/mount/fuse"

func NewBackend() MountBackend {
	return fuse.New()
}
