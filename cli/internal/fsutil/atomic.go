package fsutil

import (
	"os"
	"path/filepath"
	"strings"
)

const TempPattern = ".pigcloud-tmp-*.tmp"

const legacyTempPrefix = ".tmp-"

func IsTempName(name string) bool {
	prefix, _, _ := strings.Cut(TempPattern, "*")
	return strings.HasPrefix(name, prefix) || strings.HasPrefix(name, legacyTempPrefix)
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return WriteFileAtomicGuarded(path, data, perm, nil)
}

func WriteFileAtomicGuarded(path string, data []byte, perm os.FileMode, beforeRename func() error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, TempPattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	return nil
}
