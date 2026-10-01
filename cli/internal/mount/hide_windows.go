//go:build windows

package mount

import (
	"path/filepath"
	"syscall"
)

func HideDir(path string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return
	}
	syscall.SetFileAttributes(p, attrs|syscall.FILE_ATTRIBUTE_HIDDEN)
}

func HideMetaDir(syncDir string) {
	HideDir(filepath.Join(syncDir, ".pigcloud"))
}
