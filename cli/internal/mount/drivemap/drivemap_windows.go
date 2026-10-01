//go:build windows

package drivemap

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type WindowsMapper struct{}

func New() Mapper {
	return &WindowsMapper{}
}

func (m *WindowsMapper) Map(localDir, mountPoint string) error {
	drive := normalizeDrive(mountPoint)

	if m.IsMapped(mountPoint) {
		return fmt.Errorf("drive %s is already mapped", drive)
	}

	cmd := exec.Command("subst", drive, localDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("subst %s %s: %s (%w)", drive, localDir, strings.TrimSpace(string(out)), err)
	}

	return nil
}

func (m *WindowsMapper) Unmap(mountPoint string) error {
	drive := normalizeDrive(mountPoint)

	cmd := exec.Command("subst", "/d", drive)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("subst /d %s: %s (%w)", drive, strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (m *WindowsMapper) IsMapped(mountPoint string) bool {
	drive := normalizeDrive(mountPoint)
	_, err := os.Stat(drive + `\`)
	return err == nil
}

func normalizeDrive(mountPoint string) string {
	mp := strings.TrimSuffix(strings.TrimSuffix(mountPoint, `\`), "/")
	if len(mp) == 1 {
		return strings.ToUpper(mp) + ":"
	}
	return strings.ToUpper(mp)
}
