//go:build windows

package mount

import "pigcloud/internal/mount/winfsp"

func NewBackend() MountBackend {
	return winfsp.New()
}
