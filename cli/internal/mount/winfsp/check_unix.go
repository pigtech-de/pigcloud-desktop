//go:build !windows

package winfsp

func IsInstalled() bool {
	return true
}

func InstallHint() string {
	return ""
}
