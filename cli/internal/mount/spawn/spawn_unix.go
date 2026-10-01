//go:build !windows

package spawn

import "syscall"

func mountDetachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
