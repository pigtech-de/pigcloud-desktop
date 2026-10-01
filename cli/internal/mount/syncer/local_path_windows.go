//go:build windows

package syncer

import (
	"os"
	"syscall"
)

func isLocalLink(info os.FileInfo) bool {
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return info.Mode()&os.ModeSymlink != 0 || (ok && attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0)
}
