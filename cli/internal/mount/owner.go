package mount

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"pigcloud/internal/fsutil"
)

const ownerFileName = "owner.json"

type syncDirOwner struct {
	Owner string `json:"owner"`
}

func ownerFilePath(syncDir string) string {
	return filepath.Join(syncDir, ".pigcloud", ownerFileName)
}

func SyncDirOwner(syncDir string) string {
	raw, err := os.ReadFile(ownerFilePath(syncDir))
	if err != nil {
		return ""
	}
	var o syncDirOwner
	if json.Unmarshal(raw, &o) != nil {
		return ""
	}
	return o.Owner
}

func ClaimSyncDir(syncDir, ownerID string) error {
	if ownerID == "" {
		return nil
	}
	existing := SyncDirOwner(syncDir)
	if existing == ownerID {
		return nil
	}
	if existing != "" {
		return fmt.Errorf("sync folder %s belongs to a different account", syncDir)
	}
	metaDir := filepath.Join(syncDir, ".pigcloud")
	if err := os.MkdirAll(metaDir, 0700); err != nil {
		return err
	}
	data, err := json.Marshal(syncDirOwner{Owner: ownerID})
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(ownerFilePath(syncDir), data, 0600)
}
