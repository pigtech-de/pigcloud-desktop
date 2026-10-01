//go:build !windows

package syncer

import "os"

func isLocalLink(info os.FileInfo) bool { return info.Mode()&os.ModeSymlink != 0 }
