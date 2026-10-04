//go:build !windows

package fsutil

func isSafeNamePlatform(string) bool { return true }
