package syncer

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/transfer"
	"pigcloud/internal/mount/vfs"
)

type Downloader struct {
	syncDir    string
	remotePath string
	vfs        *vfs.VFS
	client     *api.Client
	cacheDB    *cache.DB
	store      *cache.Store
	suppress   *sync.Map
	activity   ActivityFunc
	fetchFile  func(context.Context, string) ([]byte, *api.DownloadResult, error)

	dlSem chan struct{}

	missingMu sync.Mutex
	missing   []*cache.Inode

	cancel context.CancelFunc
	done   chan struct{}
}

func (d *Downloader) SetActivityCallback(fn ActivityFunc) {
	d.activity = fn
}

func (d *Downloader) SetStore(s *cache.Store) { d.store = s }

func NewDownloader(syncDir, remotePath string, v *vfs.VFS, client *api.Client,
	cacheDB *cache.DB, suppress *sync.Map) *Downloader {
	return &Downloader{
		syncDir:    syncDir,
		remotePath: remotePath,
		vfs:        v,
		client:     client,
		cacheDB:    cacheDB,
		suppress:   suppress,
		dlSem:      make(chan struct{}, 4),
	}
}

func (d *Downloader) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.done = make(chan struct{})
	go func() {
		defer close(d.done)
		d.loop(ctx)
	}()
}

func (d *Downloader) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	awaitLoopExit(d.done, "downloader")
}

func (d *Downloader) InitialSync(ctx context.Context) error {
	mlog.Infof("downloader: starting initial sync")

	os.RemoveAll(d.stagingDir())
	cleaned := d.cleanupStaleEntries()
	if cleaned > 0 {
		mlog.Infof("downloader: cleaned %d stale entries", cleaned)
	}

	if err := d.populateRemoteTree(ctx, d.vfs.Root); err != nil {
		return fmt.Errorf("initial sync: populate remote tree: %w", err)
	}

	var downloaded, skipped int64
	var wg sync.WaitGroup
	walkErr := d.walkAndSync(ctx, d.vfs.Root, &downloaded, &skipped, &wg)
	wg.Wait()
	if walkErr != nil {
		d.missingMu.Lock()
		d.missing = nil
		d.missingMu.Unlock()
		return walkErr
	}
	d.flushMissing()

	uploaded := d.scanLocalNewFiles()

	mlog.Infof("downloader: initial sync complete: %d downloaded, %d skipped, %d queued for upload",
		downloaded, skipped, uploaded)
	return nil
}

func (d *Downloader) cleanupStaleEntries() int {
	cleaned := 0

	if renames, err := d.cacheDB.FailedRenames(); err == nil {
		for _, e := range renames {
			d.cacheDB.DeleteWriteback(e.ID)
			if in, _ := d.cacheDB.GetInode(e.InodeID); in != nil {
				requeueTree(d.cacheDB, in.RemotePath, d.localPathWithin)
			}
		}
	}
	failedWBCount := d.cacheDB.DeleteFailedWritebacks()
	if failedWBCount > 0 {
		mlog.Infof("downloader: purged %d failed writeback entries", failedWBCount)
	}

	issues, err := d.cacheDB.ListIssues()
	if err != nil {
		return cleaned
	}

	for _, inode := range issues {
		if inode.RemotePath == "" {
			d.cacheDB.DeleteWritebackByInode(inode.ID)
			d.cacheDB.DeleteSyncFailures(inode.ID)
			d.cacheDB.DeleteInode(inode.RemotePath)
			cleaned++
			continue
		}

		localPath := d.toLocalPath(inode.RemotePath)
		_, statErr := os.Stat(localPath)
		localExists := statErr == nil

		shouldClean := false
		switch inode.SyncStatus {
		case cache.StatusFailed:
			if !localExists {
				shouldClean = true
			}
		case cache.StatusRejected:
			if !localExists {
				shouldClean = true
			}
		}

		if shouldClean {
			d.cacheDB.DeleteWritebackByInode(inode.ID)
			d.cacheDB.DeleteSyncFailures(inode.ID)
			d.cacheDB.DeleteInode(inode.RemotePath)
			cleaned++
		}
	}
	return cleaned
}

func (d *Downloader) loop(ctx context.Context) {
	defer mlog.RecoverPanic("downloader")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.downloadPending(ctx)
		}
	}
}

func (d *Downloader) downloadPending(ctx context.Context) {
	var wg sync.WaitGroup
	d.walkForDownloads(ctx, d.vfs.Root, &wg)
	wg.Wait()
	if ctx.Err() != nil {
		d.missingMu.Lock()
		d.missing = nil
		d.missingMu.Unlock()
		return
	}
	d.flushMissing()
}

func (d *Downloader) dispatchDownload(ctx context.Context, node *vfs.Node, wg *sync.WaitGroup, onDone func(*vfs.Node, error)) {
	select {
	case d.dlSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	wg.Go(func() {
		defer func() { <-d.dlSem }()
		err := d.downloadFile(ctx, node)
		if onDone != nil {
			onDone(node, err)
		}
	})
}

func (d *Downloader) walkForDownloads(ctx context.Context, node *vfs.Node, wg *sync.WaitGroup) {
	if ctx.Err() != nil {
		return
	}

	if !node.IsDir {
		node.Mu.RLock()
		needsDownload := !node.Cached && !node.Dirty
		remotePath := node.RemotePath
		nodeID := node.ID
		node.Mu.RUnlock()

		if needsDownload && (d.inodeDirty(nodeID) || d.deleteQueued(nodeID) || d.queueMissingAsDelete(node, d.toLocalPath(remotePath))) {
			needsDownload = false
		}

		if needsDownload {
			localPath := d.toLocalPath(remotePath)
			if info, err := os.Stat(localPath); err == nil {
				node.Mu.RLock()
				remoteSize, remoteEtag := node.Size, node.Etag
				node.Mu.RUnlock()
				switch {
				case d.localCopyMatches(nodeID, localPath, info, remoteSize, remoteEtag):
					node.Mu.Lock()
					node.Cached = true
					node.Mu.Unlock()
					d.cacheDB.ClearSyncFailure(nodeID, cache.FailureDownload)
					d.cacheDB.SetSyncStatus(nodeID, cache.StatusSynced, "")
					return
				case d.protectLocalCollision(node, localPath, info):
					return
				}
			}
		}

		if needsDownload && !d.downloadDue(nodeID) {
			needsDownload = false
		}

		if needsDownload {
			d.dispatchDownload(ctx, node, wg, func(n *vfs.Node, err error) {
				if err != nil {
					d.recordDownloadFailure(n, err)
					return
				}
				d.cacheDB.ClearSyncFailure(n.ID, cache.FailureDownload)
			})
		}
		return
	}

	if !node.Loaded {
		return
	}

	for _, child := range node.ListChildren() {
		d.walkForDownloads(ctx, child, wg)
	}
}

func (d *Downloader) downloadFile(ctx context.Context, node *vfs.Node) (retErr error) {
	node.Mu.RLock()
	remotePath := node.RemotePath
	size := node.Size
	remoteEtag := node.Etag
	mtime := node.Mtime
	node.Mu.RUnlock()
	localPath, ok := d.localPathWithin(remotePath)
	if !ok {
		return fmt.Errorf("refusing unsafe local path for %s", remotePath)
	}
	before, err := readLocalDownloadState(localPath)
	if err != nil || d.inodeDirty(node.ID) {
		return d.markLocalConflict(node, "local file cannot be replaced while local changes are pending")
	}
	if before.info != nil && (d.localBaseline(node.ID) == "" || before.hash != d.localBaseline(node.ID)) {
		return d.markLocalConflict(node, "local content differs from the synchronized baseline")
	}

	var gotBytes int64
	defer func() {
		if d.activity != nil {
			d.activity(remotePath, "download", gotBytes, retErr)
		}
	}()

	if size > transfer.MaxDownloadSize {
		return permanent(fmt.Errorf("download %s: %d bytes exceeds the %d GB limit", remotePath, size, transfer.MaxDownloadSize>>30))
	}

	mlog.Debugf("downloader: downloading inode %d (%d bytes)", node.ID, size)

	staged, err := d.stage(ctx, remotePath, size)
	if err != nil {
		return err
	}
	defer os.Remove(staged.Path)
	dlResult := staged.Result
	gotBytes = staged.Size
	if checked, safe := d.localPathWithin(remotePath); !safe || checked != localPath {
		return d.markLocalConflict(node, "local folder changed while remote content was downloading")
	}

	d.suppress.Store(localPath, true)
	defer func() {
		time.AfterFunc(3*time.Second, func() {
			d.suppress.Delete(localPath)
		})
	}()

	if err := os.MkdirAll(filepath.Dir(localPath), 0700); err != nil {
		return fmt.Errorf("create parent dir: %w", err)
	}

	if err := publishStaged(staged.Path, localPath, func() error {
		return d.validateDownloadPublication(node, localPath, before, remoteEtag)
	}); err != nil {
		return fmt.Errorf("commit %s: %w", localPath, err)
	}

	os.Chtimes(localPath, mtime, mtime)

	node.Mu.Lock()
	remoteChanged := node.Etag != remoteEtag
	node.Cached = !remoteChanged
	if dlResult != nil {
		node.SealedKey = dlResult.SealedKey
		node.EncMeta = dlResult.EncryptionMeta
	}
	node.Size = staged.Size
	node.Mu.Unlock()

	var localMtime int64
	if fi, err := os.Stat(localPath); err == nil {
		localMtime = fi.ModTime().Unix()
		d.cacheDB.SetLocalFileID(node.ID, recordedSignature(fi, time.Now()))
	}
	d.commitDownload(node.ID, staged.Size, staged.Hash, localMtime, remoteEtag)
	if remoteChanged {
		d.cacheDB.InvalidateCache(node.ID)
		return errDownloadRemoteChanged
	}

	mlog.Debugf("downloader: saved inode %d (%d bytes)", node.ID, staged.Size)
	return nil
}

func (d *Downloader) stagingDir() string {
	return filepath.Join(d.syncDir, ".pigcloud", "staging")
}

func (d *Downloader) stage(ctx context.Context, remotePath string, size int64) (*transfer.Staged, error) {
	if d.fetchFile == nil {
		fetcher := transfer.Fetcher{
			Client: d.client,
			Keys: transfer.Keys{
				NameKey:    d.vfs.NameKey,
				PrivateKey: d.vfs.PrivateKey,
				SigningKey: d.vfs.SigningPrivateKey,
			},
			Tag: "downloader",
		}
		return fetcher.FetchToFile(ctx, remotePath, d.stagingDir(), size)
	}
	plaintext, dlResult, err := d.fetchFile(ctx, remotePath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(d.stagingDir(), 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(d.stagingDir(), "dl-*.part")
	if err != nil {
		return nil, err
	}
	_, werr := f.Write(plaintext)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(f.Name())
		return nil, werr
	}
	return &transfer.Staged{Path: f.Name(), Hash: fmt.Sprintf("%x", sha256.Sum256(plaintext)), Size: int64(len(plaintext)), Result: dlResult}, nil
}

func publishStaged(staged, localPath string, guard func() error) error {
	if err := guard(); err != nil {
		return err
	}
	if err := os.Rename(staged, localPath); err == nil {
		return nil
	}
	src, err := os.Open(staged)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(localPath), ".pig-dl-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	_, err = io.Copy(tmp, src)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	return os.Rename(tmpPath, localPath)
}

func (d *Downloader) commitDownload(nodeID int64, size int64, plaintextHash string, localMtime int64, remoteEtag ...string) {
	var superseded string
	if in, err := d.cacheDB.GetInode(nodeID); err == nil && in != nil {
		superseded = in.ContentHash
	}
	d.cacheDB.MarkCached(nodeID, "")
	d.cacheDB.SetInodeSize(nodeID, size)
	if len(remoteEtag) > 0 {
		d.cacheDB.SetLocalContentForVersion(nodeID, plaintextHash, localMtime, remoteEtag[0])
	} else {
		d.cacheDB.SetLocalContent(nodeID, plaintextHash, localMtime)
	}
	d.cacheDB.SetSyncStatus(nodeID, cache.StatusSynced, "")
	cache.ReleaseBlob(d.cacheDB, d.store, superseded, nodeID)
}

func (d *Downloader) populateRemoteTree(ctx context.Context, parent *vfs.Node) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if _, err := d.vfs.Readdir(parent); err != nil {
		return err
	}

	for _, child := range parent.ListChildren() {
		if child.IsDir {
			if err := d.populateRemoteTree(ctx, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Downloader) walkAndSync(ctx context.Context, node *vfs.Node, downloaded, skipped *int64, wg *sync.WaitGroup) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if node.IsDir {
		if node != d.vfs.Root {
			localDir, ok := d.localPathWithin(node.RemotePath)
			if !ok {
				mlog.Warnf("downloader: skipping unsafe remote folder inode %d", node.ID)
				return nil
			}
			d.suppress.Store(localDir, true)
			os.MkdirAll(localDir, 0700)
			time.AfterFunc(3*time.Second, func() { d.suppress.Delete(localDir) })
		}

		for _, child := range node.ListChildren() {
			if err := d.walkAndSync(ctx, child, downloaded, skipped, wg); err != nil {
				return err
			}
		}
		return nil
	}

	localPath := d.toLocalPath(node.RemotePath)
	if d.deleteQueued(node.ID) || d.queueMissingAsDelete(node, localPath) {
		atomic.AddInt64(skipped, 1)
		return nil
	}
	if info, err := os.Stat(localPath); err == nil {
		node.Mu.RLock()
		remoteSize := node.Size
		remoteEtag := node.Etag
		node.Mu.RUnlock()

		if d.inodeDirty(node.ID) {
			if d.localBaseline(node.ID) == "" {
				d.markLocalConflict(node, "local and remote files share a name without a synchronized content baseline")
			}
			atomic.AddInt64(skipped, 1)
			return nil
		}
		if d.localCopyMatches(node.ID, localPath, info, remoteSize, remoteEtag) {
			node.Mu.Lock()
			node.Cached = true
			node.Mu.Unlock()
			d.cacheDB.SetSyncStatus(node.ID, cache.StatusSynced, "")
			d.cacheDB.ClearSyncFailure(node.ID, cache.FailureDownload)
			atomic.AddInt64(skipped, 1)
			return nil
		}

		if d.protectLocalCollision(node, localPath, info) {
			atomic.AddInt64(skipped, 1)
			return nil
		}
	}

	d.dispatchDownload(ctx, node, wg, func(n *vfs.Node, err error) {
		if err != nil {
			d.recordDownloadFailure(n, err)
			return
		}
		d.cacheDB.ClearSyncFailure(n.ID, cache.FailureDownload)
		atomic.AddInt64(downloaded, 1)
	})
	return nil
}

func (d *Downloader) localCopyMatches(nodeID int64, localPath string, info os.FileInfo, remoteSize int64, remoteEtag string) bool {
	if info.Size() != remoteSize {
		return false
	}
	if nodeID == 0 || d.cacheDB == nil || remoteEtag == "" {
		return false
	}
	inode, err := d.cacheDB.GetInode(nodeID)
	if err != nil || inode == nil || inode.LocalHash == "" {
		return false
	}
	_, _, synchronizedEtag, err := d.cacheDB.LocalContentState(nodeID)
	if err != nil || synchronizedEtag != remoteEtag {
		return false
	}
	sum, err := hashLocalFile(localPath)
	if err != nil {
		return false
	}
	return sum == inode.LocalHash
}

func hashLocalFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (d *Downloader) queueWriteback(inodeID int64, action, remotePath string) bool {
	return d.cacheDB.EnqueueWriteback(inodeID, action, remotePath, "") == nil
}

func (d *Downloader) enqueueLocalUpload(node *vfs.Node, localPath string, info os.FileInfo) {
	ok, reason := vfs.ValidateFile(filepath.Base(localPath), info.Size())
	status := cache.StatusPending
	if !ok {
		status = cache.StatusRejected
	}

	var parentID int64
	if node.Parent != nil {
		parentID = node.Parent.ID
	}

	node.Mu.Lock()
	node.Dirty = true
	node.Cached = false
	node.Size = info.Size()
	node.Mu.Unlock()

	inode := &cache.Inode{
		RemotePath:   node.RemotePath,
		DisplayName:  node.Name,
		IsDir:        false,
		Size:         info.Size(),
		Mtime:        info.ModTime().Unix(),
		Dirty:        true,
		SyncStatus:   status,
		StatusReason: reason,
		ParentID:     parentID,
	}
	id, err := d.cacheDB.UpsertInode(inode)
	if err != nil {
		mlog.Warnf("downloader: track local edit of inode %d failed (%s)", node.ID, mlog.Cause(err))
		return
	}
	node.ID = id
	d.cacheDB.SetLocalContent(id, "", 0)
	if !ok {
		return
	}
	if !d.queueWriteback(id, "upload", node.RemotePath) {
		mlog.Warnf("downloader: read-only mount, local edit of inode %d stays unsynced", id)
		return
	}
	mlog.Debugf("downloader: keeping local edit of inode %d (queued upload)", id)
}

func (d *Downloader) RemoveLocal(remotePath string) {
	localPath, ok := d.localPathWithin(remotePath)
	if !ok {
		return
	}
	fi, err := os.Lstat(localPath)
	if err != nil {
		return
	}
	var kept map[string]bool
	if fi.IsDir() {
		kept = d.unsyncedUnder(localPath)
	}
	if len(kept) == 0 {
		d.TrashLocal(remotePath)
		return
	}
	chain := map[string]bool{}
	for p := range kept {
		for dir := filepath.Dir(p); dir == localPath || strings.HasPrefix(dir, localPath+string(filepath.Separator)); dir = filepath.Dir(dir) {
			chain[dir] = true
		}
	}
	filepath.WalkDir(localPath, func(path string, entry os.DirEntry, err error) error {
		if err != nil || path == localPath {
			return nil
		}
		if !safeSyncPath(d.syncDir, path) || shouldIgnore(entry.Name()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if chain[path] {
				return nil
			}
			d.TrashLocal(d.pathToRemote(path))
			return filepath.SkipDir
		}
		if !kept[path] {
			d.TrashLocal(d.pathToRemote(path))
		}
		return nil
	})
	d.requeueKept(chain, kept)
}

func (d *Downloader) unsyncedUnder(root string) map[string]bool {
	kept := map[string]bool{}
	filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !safeSyncPath(d.syncDir, path) || (path != root && shouldIgnore(entry.Name())) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type().IsRegular() && d.localUnsynced(d.pathToRemote(path), path) {
			kept[path] = true
		}
		return nil
	})
	return kept
}

func (d *Downloader) localUnsynced(remotePath, localPath string) bool {
	inode, _ := d.cacheDB.GetInodeByPath(remotePath)
	if inode == nil || inode.Dirty {
		return true
	}
	baseline := d.localBaseline(inode.ID)
	if baseline == "" {
		return false
	}
	sum, err := hashLocalFile(localPath)
	return err == nil && sum != baseline
}

func (d *Downloader) requeueKept(chain, kept map[string]bool) {
	dirs := slices.Sorted(maps.Keys(chain))
	for _, dir := range dirs {
		remotePath := d.pathToRemote(dir)
		inode, _ := d.cacheDB.GetInodeByPath(remotePath)
		if inode == nil {
			d.trackNewLocalDir(remotePath, filepath.Base(dir))
			continue
		}
		d.cacheDB.ClearNodeIDs(inode.ID, false)
		d.cacheDB.SetSyncStatus(inode.ID, cache.StatusPending, "")
		d.queueWriteback(inode.ID, "mkdir", remotePath)
	}
	requeued := 0
	for _, file := range slices.Sorted(maps.Keys(kept)) {
		remotePath := d.pathToRemote(file)
		inode, _ := d.cacheDB.GetInodeByPath(remotePath)
		if inode == nil {
			if info, err := os.Stat(file); err == nil {
				d.trackNewLocalFile(remotePath, filepath.Base(file), info)
				requeued++
			}
			continue
		}
		d.cacheDB.ClearNodeIDs(inode.ID, false)
		d.cacheDB.InvalidateCache(inode.ID)
		cache.ReleaseBlob(d.cacheDB, d.store, inode.ContentHash, inode.ID)
		if inode.SyncStatus == cache.StatusRejected {
			continue
		}
		d.cacheDB.MarkDirty(inode.ID)
		d.cacheDB.SetSyncStatus(inode.ID, cache.StatusPending, "")
		d.queueWriteback(inode.ID, "upload", remotePath)
		requeued++
	}
	mlog.Warnf("downloader: remote folder delete kept %d unsynced item(s) and %d folder(s) for re-upload", requeued, len(dirs))
}

func (d *Downloader) TrashLocal(remotePath string) error {
	localPath, ok := d.localPathWithin(remotePath)
	if !ok {
		return fmt.Errorf("unsafe local path")
	}
	fi, err := os.Lstat(localPath)
	if err != nil {
		return nil
	}
	var delBytes int64
	if !fi.IsDir() {
		delBytes = fi.Size()
	}

	rel := remotePath
	if d.remotePath != "" && d.remotePath != "/" {
		rel = strings.TrimPrefix(remotePath, d.remotePath+"/")
	}
	trashPath := filepath.Join(d.syncDir, ".pigcloud", "trash", filepath.FromSlash(rel))

	d.suppress.Store(localPath, true)
	time.AfterFunc(3*time.Second, func() { d.suppress.Delete(localPath) })

	if err := os.MkdirAll(filepath.Dir(trashPath), 0700); err != nil {
		mlog.Warnf("downloader: trash folder unavailable (%s)", mlog.Cause(err))
		return err
	}
	dst := trashPath
	for i := 1; ; i++ {
		if _, err := os.Lstat(dst); err != nil {
			break
		}
		dst = fmt.Sprintf("%s.%d", trashPath, i)
	}
	if err := os.Rename(localPath, dst); err != nil {
		mlog.Warnf("downloader: moving a remotely deleted item to the trash failed (%s)", mlog.Cause(err))
		return err
	}
	if d.activity != nil {
		d.activity(remotePath, "delete", delBytes, nil)
	}
	return nil
}

func (d *Downloader) LocalPath(remotePath string) (string, bool) {
	return d.localPathWithin(remotePath)
}

func (d *Downloader) SuppressPath(localPath string, dur time.Duration) {
	d.suppress.Store(localPath, true)
	time.AfterFunc(dur, func() { d.suppress.Delete(localPath) })
}

func (d *Downloader) scanLocalNewFiles() int {
	queued, held := 0, 0
	filepath.WalkDir(d.syncDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !safeSyncPath(d.syncDir, path) {
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

		remotePath := d.pathToRemote(path)
		if remotePath == "" || remotePath == d.remotePath {
			return nil
		}

		existing, _ := d.cacheDB.GetInodeByPath(remotePath)
		if existing != nil {
			return nil
		}

		var tracked, wasQueued bool
		if entry.IsDir() {
			tracked, wasQueued = d.trackNewLocalDir(remotePath, name)
		} else if info, err := entry.Info(); err == nil {
			tracked, wasQueued = d.trackNewLocalFile(remotePath, name, info)
		}
		if wasQueued {
			queued++
		} else if tracked {
			held++
		}
		return nil
	})
	if held > 0 {
		mlog.Warnf("downloader: read-only mount, %d local item(s) tracked but not queued for upload", held)
	}
	return queued
}

func (d *Downloader) trackNewLocalDir(remotePath, name string) (tracked, queued bool) {
	id, err := d.cacheDB.UpsertInode(&cache.Inode{
		RemotePath:  remotePath,
		DisplayName: name,
		IsDir:       true,
		Mtime:       time.Now().Unix(),
		SyncStatus:  cache.StatusPending,
	})
	if err != nil {
		return false, false
	}
	return true, d.queueWriteback(id, "mkdir", remotePath)
}

func (d *Downloader) trackNewLocalFile(remotePath, name string, info os.FileInfo) (tracked, queued bool) {
	ok, reason := vfs.ValidateFile(name, info.Size())
	status := cache.StatusPending
	if !ok {
		status = cache.StatusRejected
	}
	id, err := d.cacheDB.UpsertInode(&cache.Inode{
		RemotePath:   remotePath,
		DisplayName:  name,
		Size:         info.Size(),
		Mtime:        info.ModTime().Unix(),
		Dirty:        true,
		SyncStatus:   status,
		StatusReason: reason,
	})
	if err != nil || !ok {
		return false, false
	}
	return true, d.queueWriteback(id, "upload", remotePath)
}

func (d *Downloader) downloadDue(id int64) bool {
	return d.cacheDB.TransferWithheld(id, cache.FailureDownload) == nil
}

func (d *Downloader) recordDownloadFailure(node *vfs.Node, err error) {
	if errors.Is(err, errDownloadLocalChanged) || errors.Is(err, errDownloadRemoteChanged) {
		mlog.Warnf("downloader: inode %d raced a local or remote change (%s)", node.ID, mlog.Cause(err))
		return
	}
	d.cacheDB.RecordTransferFailure("downloader", node.ID, cache.FailureDownload, err)
}

func (d *Downloader) deleteQueued(id int64) bool {
	if id == 0 {
		return false
	}
	active, err := d.cacheDB.HasActiveWriteback(id, "delete")
	return err != nil || active
}

func (d *Downloader) inodeDirty(id int64) bool {
	if id == 0 {
		return false
	}
	inode, err := d.cacheDB.GetInode(id)
	return err == nil && inode != nil && inode.Dirty
}

func (d *Downloader) toLocalPath(remotePath string) string {
	rel := remotePath
	if d.remotePath != "" && d.remotePath != "/" {
		rel = strings.TrimPrefix(remotePath, d.remotePath+"/")
	}
	return filepath.Join(d.syncDir, filepath.FromSlash(rel))
}

func (d *Downloader) localPathWithin(remotePath string) (string, bool) {
	p := d.toLocalPath(remotePath)
	if !safeSyncPath(d.syncDir, p) {
		return "", false
	}
	return p, true
}

func (d *Downloader) pathToRemote(localPath string) string {
	rel, err := filepath.Rel(d.syncDir, localPath)
	if err != nil {
		return filepath.Base(localPath)
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return d.remotePath
	}
	if d.remotePath == "" || d.remotePath == "/" {
		return rel
	}
	return d.remotePath + "/" + rel
}
