package vfs

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"pigcloud/internal/filetypes"
)

const (
	MaxUploadSize = 5 * 1024 * 1024 * 1024
)

var validNameRegex = regexp.MustCompile(`^[\p{L}\p{M}0-9_ &!\p{So}\x{200D}\x{FE0F}\x{1F3FB}-\x{1F3FF}.-]+$`)

var ExcludedDirs = map[string]bool{
	".Trash":        true,
	".Favorites":    true,
	".Recents":      true,
	".SharedByMe":   true,
	".SharedWithMe": true,
	".Gallery":      true,
}

func ValidateFile(name string, size int64) (bool, string) {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	if ext != "" {
		fileType := filetypes.TypeOf(ext)
		if fileType == "other" {
			return false, fmt.Sprintf("file type .%s is not supported", ext)
		}
	} else if name != "" && !strings.Contains(name, ".") {
	}

	if size > MaxUploadSize {
		return false, fmt.Sprintf("file exceeds %d GB upload limit", MaxUploadSize/(1024*1024*1024))
	}

	if !validNameRegex.MatchString(name) {
		return false, "file name contains unsupported characters"
	}

	return true, ""
}

var validFolderRegex = regexp.MustCompile(`^[\p{L}\p{M}0-9_ &!\p{So}\x{200D}\x{FE0F}\x{1F3FB}-\x{1F3FF}-]+$`)

func ValidateDirName(name string) (bool, string) {
	if !validFolderRegex.MatchString(name) {
		return false, "folder name contains unsupported characters"
	}
	return true, ""
}

func IsExcludedDir(name string) bool {
	return ExcludedDirs[name]
}
