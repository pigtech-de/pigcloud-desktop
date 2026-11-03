package syncer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pigcloud/internal/mount/cache"
)

const racyWindow = 2 * time.Second

const (
	massDeleteFiles = 500
	massDeleteMin   = 20
)

func recordedSignature(fi os.FileInfo, at time.Time) string {
	sig := localFileID(fi)
	if sig == "" {
		return ""
	}
	return sig + "@" + strconv.FormatInt(at.UnixNano(), 10)
}

func splitSignature(stored string) (string, int64) {
	sig, at, found := strings.Cut(stored, "@")
	if !found {
		return stored, 0
	}
	n, _ := strconv.ParseInt(at, 10, 64)
	return sig, n
}

func signatureFields(stored string) []string {
	sig, _ := splitSignature(stored)
	parts := strings.Split(sig, ":")
	if len(parts) != 3 {
		return nil
	}
	return parts
}

func fileIdentity(stored string) string {
	if parts := signatureFields(stored); parts != nil {
		return parts[0] + ":" + parts[1]
	}
	return ""
}

func signatureDevice(stored string) string {
	if parts := signatureFields(stored); parts != nil {
		return parts[0]
	}
	return ""
}

func statUnchanged(inode *cache.Inode, info os.FileInfo) bool {
	if inode.LocalMtime == 0 || info.Size() != inode.Size || info.ModTime().Unix() != inode.LocalMtime {
		return false
	}
	current := localFileID(info)
	if current == "" {
		return true
	}
	sig, at := splitSignature(inode.LocalFileID)
	if sig != current {
		return false
	}
	ctime, err := strconv.ParseInt(signatureFields(sig)[2], 10, 64)
	return err == nil && at-ctime > int64(racyWindow)
}

func onOtherDevice(inode *cache.Inode, localPath string) bool {
	recorded := signatureDevice(inode.LocalFileID)
	if recorded == "" {
		return false
	}
	for dir := filepath.Dir(localPath); ; dir = filepath.Dir(dir) {
		if fi, err := os.Stat(dir); err == nil {
			current := signatureDevice(localFileID(fi) + "@0")
			return current != "" && current != recorded
		}
		if filepath.Dir(dir) == dir {
			return false
		}
	}
}

func massDelete(db *cache.DB, n int) bool {
	if n > massDeleteFiles {
		return true
	}
	if n < massDeleteMin {
		return false
	}
	total, err := db.CountLocalFiles()
	return err == nil && n*2 > total
}

func requeueTree(db *cache.DB, root string, localOf func(string) (string, bool)) {
	rows, err := db.InodesUnder(root)
	if err != nil {
		return
	}
	for _, in := range rows {
		lp, ok := localOf(in.RemotePath)
		if !ok {
			continue
		}
		if _, err := os.Lstat(lp); err != nil {
			continue
		}
		db.ClearNodeIDs(in.ID, false)
		if in.IsDir {
			db.SetSyncStatus(in.ID, cache.StatusPending, "")
			db.EnqueueWriteback(in.ID, "mkdir", in.RemotePath, "")
			continue
		}
		if in.SyncStatus == cache.StatusRejected {
			continue
		}
		db.InvalidateCache(in.ID)
		db.MarkDirty(in.ID)
		db.SetSyncStatus(in.ID, cache.StatusPending, "")
		db.EnqueueWriteback(in.ID, "upload", in.RemotePath, "")
	}
}
