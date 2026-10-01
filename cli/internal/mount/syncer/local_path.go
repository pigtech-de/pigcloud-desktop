package syncer

import (
	"os"
	"path/filepath"
	"strings"
)

func safeSyncPath(root, localPath string) bool {
	rel, err := filepath.Rel(root, localPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	current := root
	parts := append([]string{""}, strings.Split(rel, string(filepath.Separator))...)
	for _, part := range parts {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return true
		}
		if err != nil || isLocalLink(info) {
			return false
		}
	}
	return true
}
