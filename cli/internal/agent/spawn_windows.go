//go:build windows

package agent

import "syscall"

func windowsDetachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008,
	}
}
