package drivemap

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type directMapper struct{}

func sameDirectoryPath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func ForDirectory(localDir, mountPoint string) Mapper {
	local, localErr := os.Stat(localDir)
	point, pointErr := os.Lstat(mountPoint)
	if localErr == nil && pointErr == nil && usesDirectDirectory(localDir, mountPoint, local, point) {
		return directMapper{}
	}
	return New()
}

func usesDirectDirectory(localDir, mountPoint string, local, point os.FileInfo) bool {
	return sameDirectoryPath(localDir, mountPoint) && point.IsDir() && os.SameFile(local, point)
}

func (directMapper) Map(localDir, mountPoint string) error {
	local, localErr := os.Stat(localDir)
	point, pointErr := os.Stat(mountPoint)
	if !sameDirectoryPath(localDir, mountPoint) || localErr != nil || pointErr != nil || !local.IsDir() || !os.SameFile(local, point) {
		return fmt.Errorf("direct sync folder changed before startup")
	}
	return nil
}

func (directMapper) Unmap(string) error { return nil }

func (directMapper) IsMapped(mountPoint string) bool {
	info, err := os.Stat(mountPoint)
	return err == nil && info.IsDir()
}
