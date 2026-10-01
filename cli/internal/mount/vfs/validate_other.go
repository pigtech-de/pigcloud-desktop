//go:build !windows

package vfs

func isSafeNamePlatform(string) bool { return true }
