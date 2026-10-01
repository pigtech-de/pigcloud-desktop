package syncer

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"
)

const reconcileInterval = 3 * time.Minute

type Reconciler struct {
	syncDir    string
	remotePath string
	cacheDB    *cache.DB
	store      *cache.Store
	interval   time.Duration

	cancel context.CancelFunc
	done   chan struct{}
}

func (r *Reconciler) SetStore(s *cache.Store) { r.store = s }

func NewReconciler(syncDir, remotePath string, cacheDB *cache.DB, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = reconcileInterval
	}
	return &Reconciler{syncDir: syncDir, remotePath: remotePath, cacheDB: cacheDB, interval: interval}
}

func (r *Reconciler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	go func() {
		defer close(r.done)
		r.loop(ctx)
	}()
}

func (r *Reconciler) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	awaitLoopExit(r.done, "reconciler")
}

func (r *Reconciler) loop(ctx context.Context) {
	defer mlog.RecoverPanic("reconciler")

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.Reconcile(ctx)
		}
	}
}

func (r *Reconciler) Reconcile(ctx context.Context) int {
	healed := 0
	filepath.WalkDir(r.syncDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !safeSyncPath(r.syncDir, path) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if shouldIgnore(name) || name == ".pigcloud" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		remotePath := r.toRemote(path)
		if remotePath == "" || remotePath == r.remotePath {
			return nil
		}
		if r.healEntry(path, remotePath, entry) {
			healed++
		}
		return nil
	})
	if healed > 0 {
		mlog.Infof("reconciler: re-queued %d drifted item(s)", healed)
	}
	return healed
}

func (r *Reconciler) healEntry(localPath, remotePath string, entry os.DirEntry) bool {
	if !safeSyncPath(r.syncDir, localPath) {
		return false
	}
	inode, _ := r.cacheDB.GetInodeByPath(remotePath)

	if entry.IsDir() {
		if inode != nil {
			return false
		}
		id, err := r.cacheDB.UpsertInode(&cache.Inode{
			RemotePath:  remotePath,
			DisplayName: entry.Name(),
			IsDir:       true,
			Mtime:       time.Now().Unix(),
			SyncStatus:  cache.StatusPending,
		})
		if err != nil {
			return false
		}
		r.cacheDB.EnqueueWriteback(id, "mkdir", remotePath, "")
		return true
	}

	info, err := entry.Info()
	if err != nil {
		return false
	}

	if inode == nil {
		return r.queueNewFile(remotePath, entry.Name(), info)
	}

	switch inode.SyncStatus {
	case cache.StatusRejected, cache.StatusConflict:
		return false
	case cache.StatusFailed:
		if f, _ := r.cacheDB.GetSyncFailure(inode.ID, cache.FailureUpload); f != nil {
			if f.Permanent {
				return false
			}
			if time.Now().Unix() < f.NextRetryAt {
				return false
			}
		}
		if !inode.Dirty {
			if f, _ := r.cacheDB.GetSyncFailure(inode.ID, cache.FailureDownload); f != nil {
				return false
			}
		}
		return r.requeueUpload(inode, info)
	case cache.StatusSynced:
		current, baseline, version, err := r.cacheDB.LocalContentState(inode.ID)
		if err != nil {
			return false
		}
		if baseline == "" {
			r.cacheDB.MarkLocalConflict(inode.ID, "local file has no synchronized content baseline")
			return false
		}
		remoteUnchanged := current != "" && inode.Etag != "" && version == inode.Etag
		sum, err := hashLocalFile(localPath)
		if err != nil {
			return false
		}
		if sum == baseline {
			if current != "" {
				r.cacheDB.SetLocalContentForVersion(inode.ID, current, info.ModTime().Unix(), version)
			}
			return false
		}
		if !remoteUnchanged {
			r.cacheDB.MarkLocalConflict(inode.ID, "local and remote content both differ from the synchronized baseline")
			return false
		}
		return r.requeueUpload(inode, info)
	case cache.StatusPending:
		if r.uploadInFlight(inode.ID) {
			return false
		}
		r.cacheDB.EnqueueWriteback(inode.ID, "upload", remotePath, "")
	}
	return false
}

func (r *Reconciler) uploadInFlight(inodeID int64) bool {
	active, err := r.cacheDB.HasActiveWriteback(inodeID, "upload")
	return err != nil || active
}

func (r *Reconciler) queueNewFile(remotePath, name string, info os.FileInfo) bool {
	ok, reason := vfs.ValidateFile(name, info.Size())
	status := cache.StatusPending
	if !ok {
		status = cache.StatusRejected
	}
	id, err := r.cacheDB.UpsertInode(&cache.Inode{
		RemotePath:   remotePath,
		DisplayName:  name,
		Size:         info.Size(),
		Mtime:        info.ModTime().Unix(),
		Dirty:        true,
		SyncStatus:   status,
		StatusReason: reason,
	})
	if err != nil || !ok {
		return false
	}
	r.cacheDB.EnqueueWriteback(id, "upload", remotePath, "")
	return true
}

func (r *Reconciler) requeueUpload(inode *cache.Inode, info os.FileInfo) bool {
	ok, reason := vfs.ValidateFile(inode.DisplayName, info.Size())
	if !ok {
		r.cacheDB.SetSyncStatus(inode.ID, cache.StatusRejected, reason)
		return false
	}
	if r.uploadInFlight(inode.ID) {
		return false
	}
	r.cacheDB.DeleteFailedUploadWritebacks(inode.ID)

	supersededHash := inode.ContentHash

	inode.Size = info.Size()
	inode.Mtime = info.ModTime().Unix()
	inode.Cached = false
	inode.ContentHash = ""
	inode.Dirty = true
	inode.SyncStatus = cache.StatusPending
	inode.StatusReason = ""
	id, err := r.cacheDB.UpsertInode(inode)
	if err != nil {
		return false
	}
	r.cacheDB.SetLocalContent(id, "", 0)
	cache.ReleaseBlob(r.cacheDB, r.store, supersededHash, id)
	r.cacheDB.EnqueueWriteback(id, "upload", inode.RemotePath, "")
	return true
}

func (r *Reconciler) toRemote(localPath string) string {
	rel, err := filepath.Rel(r.syncDir, localPath)
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return r.remotePath
	}
	if r.remotePath == "" || r.remotePath == "/" {
		return rel
	}
	return r.remotePath + "/" + rel
}
