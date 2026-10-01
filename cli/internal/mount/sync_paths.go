package mount

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"pigcloud/internal/fsutil"
)

const syncPathsFile = "sync-paths.json"

type SyncPaths map[string]string

func syncPathKey(owner, remotePath string) string {
	return owner + "\n" + NormalizeRemotePath(remotePath)
}

func LoadSyncPaths() SyncPaths {
	data, err := os.ReadFile(filepath.Join(ConfigDir(), syncPathsFile))
	if err != nil {
		return make(SyncPaths)
	}
	var paths SyncPaths
	if json.Unmarshal(data, &paths) != nil {
		return make(SyncPaths)
	}
	return paths
}

func (sp SyncPaths) Save() error {
	data, err := json.MarshalIndent(sp, "", "  ")
	if err != nil {
		return err
	}
	dir := ConfigDir()
	os.MkdirAll(dir, 0700)
	return fsutil.WriteFileAtomic(filepath.Join(dir, syncPathsFile), data, 0600)
}

func (sp SyncPaths) GetSyncDir(owner, remotePath string) string {
	key := NormalizeRemotePath(remotePath)
	if custom, ok := sp[syncPathKey(owner, key)]; ok && custom != "" {
		return custom
	}
	if custom, ok := sp[key]; ok && custom != "" {
		if o := SyncDirOwner(custom); o == "" || o == owner {
			return custom
		}
	}
	return DefaultSyncDir(owner, key)
}

func (sp SyncPaths) SetSyncDir(owner, remotePath, syncDir string) {
	sp[syncPathKey(owner, remotePath)] = syncDir
}

func DefaultSyncDir(owner, remotePath string) string {
	key := NormalizeRemotePath(remotePath)
	legacyHash := sha256.Sum256([]byte(key))
	legacyID := hex.EncodeToString(legacyHash[:8])
	for _, base := range []string{ConfigDir(), DataDir()} {
		dir := filepath.Join(base, "sync-data", legacyID)
		if _, err := os.Stat(dir); err == nil {
			if o := SyncDirOwner(dir); o == "" || o == owner {
				return dir
			}
		}
	}
	pathHash := sha256.Sum256([]byte(owner + "\n" + key))
	return filepath.Join(DataDir(), "sync-data", hex.EncodeToString(pathHash[:8]))
}

func NormalizeRemotePath(remotePath string) string {
	if remotePath == "/" {
		return ""
	}
	if len(remotePath) > 0 && remotePath[0] == '/' {
		return remotePath[1:]
	}
	return remotePath
}

func (sp SyncPaths) HasCustomSyncDir(owner, remotePath string) bool {
	if custom, ok := sp[syncPathKey(owner, remotePath)]; ok && custom != "" {
		return true
	}
	custom, ok := sp[NormalizeRemotePath(remotePath)]
	if !ok || custom == "" {
		return false
	}
	o := SyncDirOwner(custom)
	return o == "" || o == owner
}

func (sp SyncPaths) SyncDirExists(owner, remotePath string) bool {
	dir := sp.GetSyncDir(owner, remotePath)
	_, err := os.Stat(dir)
	return err == nil
}
