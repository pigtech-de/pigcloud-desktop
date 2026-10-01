//go:build !windows

package agent

import "syscall"

func windowsDetachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
