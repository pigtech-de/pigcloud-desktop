//go:build !windows

package drivemap

import (
	"fmt"
	"os"
)

type UnixMapper struct{}

func New() Mapper {
	return &UnixMapper{}
}

func (m *UnixMapper) Map(localDir, mountPoint string) error {
	if info, err := os.Lstat(mountPoint); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			target, _ := os.Readlink(mountPoint)
			if target == localDir {
				return nil
			}
			return fmt.Errorf("%s already exists (symlink to %s)", mountPoint, target)
		}
		return fmt.Errorf("%s already exists and is not a symlink", mountPoint)
	}

	if err := os.Symlink(localDir, mountPoint); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", mountPoint, localDir, err)
	}
	return nil
}

func (m *UnixMapper) Unmap(mountPoint string) error {
	info, err := os.Lstat(mountPoint)
	if err != nil {
		return nil
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s is not a symlink — refusing to remove", mountPoint)
	}
	return os.Remove(mountPoint)
}

func (m *UnixMapper) IsMapped(mountPoint string) bool {
	info, err := os.Lstat(mountPoint)
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeSymlink != 0
}
