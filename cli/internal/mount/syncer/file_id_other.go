//go:build !linux && !darwin && !windows

package syncer

import "os"

func localFileID(os.FileInfo) string { return "" }
