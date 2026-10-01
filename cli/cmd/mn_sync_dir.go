package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pigcloud/internal/mount"
	"pigcloud/internal/output"
)

var errSyncFolderMoveRequired = errors.New("this remote already has a sync folder; use 'pc mn mv' to move it before changing the folder")

func reportDirectSyncError(err error) {
	if jsonOutput && errors.Is(err, errSyncFolderMoveRequired) {
		if encodeErr := json.NewEncoder(os.Stdout).Encode(map[string]any{"success": false, "code": "sync_folder_move_required"}); encodeErr == nil {
			return
		}
	}
	output.PrintError(err.Error())
}

func validateDirectSyncDir(syncDir, mountPoint string) error {
	if !filepath.IsAbs(syncDir) || !filepath.IsAbs(mountPoint) {
		return fmt.Errorf("--sync-dir and its mount point must be absolute paths")
	}
	info, err := os.Lstat(syncDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("--sync-dir must name an existing directory")
	}
	point, err := os.Lstat(mountPoint)
	if err != nil || !point.IsDir() || !os.SameFile(info, point) {
		return fmt.Errorf("--sync-dir must name the mount point directory")
	}
	return nil
}

func configureDirectSyncDir(paths mount.SyncPaths, owner, remote, syncDir, mountPoint string) error {
	if err := validateDirectSyncDir(syncDir, mountPoint); err != nil {
		return err
	}
	if owner == "" {
		return fmt.Errorf("--sync-dir requires an account identity")
	}
	target, err := filepath.EvalSymlinks(syncDir)
	if err != nil {
		return err
	}
	existing := paths.GetSyncDir(owner, remote)
	if existingInfo, statErr := os.Stat(existing); statErr == nil {
		targetInfo, targetErr := os.Stat(target)
		if targetErr != nil || !os.SameFile(existingInfo, targetInfo) {
			return errSyncFolderMoveRequired
		}
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("cannot inspect the existing sync folder: %w", statErr)
	}
	for key, local := range paths {
		parts := strings.SplitN(key, "\n", 2)
		mappedRemote := parts[len(parts)-1]
		if mappedRemote == mount.NormalizeRemotePath(remote) {
			continue
		}
		left, leftErr := os.Stat(local)
		right, rightErr := os.Stat(target)
		if leftErr == nil && rightErr == nil && os.SameFile(left, right) {
			return fmt.Errorf("this local folder already syncs another remote path")
		}
	}
	if err := mount.ClaimSyncDir(target, owner); err != nil {
		return err
	}
	paths.SetSyncDir(owner, remote, target)
	return paths.Save()
}
