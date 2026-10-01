//go:build windows

package fuse

func IsAvailable() bool {
	return true
}

func InstallHint() string {
	return ""
}
