package syncer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"

	"github.com/fsnotify/fsnotify"
)

const (
	watchDebounce = 2 * time.Second

	syncWorkers = 4

	syncQueueSize = 1024
)

var ignoredNames = map[string]bool{
	".DS_Store":   true,
	"Thumbs.db":   true,
	"desktop.ini": true,
}

var ignoredPrefixes = []string{"~$", ".pig"}

var ignoredSuffixes = []string{".swp", ".tmp", ".crdownload", ".part"}

type Watcher struct {
	syncDir    string
	remotePath string
	cacheDB    *cache.DB
	store      *cache.Store
	evictor    *cache.Evictor
	vfs        *vfs.VFS
	suppress   *sync.Map

	fsWatcher *fsnotify.Watcher

	mu       sync.Mutex
	pending  map[string]time.Time
	wake     chan struct{}
	vanished map[string]vanishedItem

	healthMu sync.Mutex
	started  bool
	watchErr string

	syncCh chan string
	stopCh chan struct{}
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{}
}

func NewWatcher(syncDir, remotePath string, cacheDB *cache.DB, store *cache.Store,
	evictor *cache.Evictor, v *vfs.VFS, suppress *sync.Map) (*Watcher, error) {

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		syncDir:    syncDir,
		remotePath: remotePath,
		cacheDB:    cacheDB,
		store:      store,
		evictor:    evictor,
		vfs:        v,
		suppress:   suppress,
		fsWatcher:  fsw,
		pending:    make(map[string]time.Time),
		wake:       make(chan struct{}, 1),
		syncCh:     make(chan string, syncQueueSize),
		stopCh:     make(chan struct{}),
	}, nil
}

func (w *Watcher) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	w.setWatchErr("")
	w.addRecursive(w.syncDir)

	for range syncWorkers {
		w.wg.Go(func() {
			w.syncWorker(ctx)
		})
	}
	w.wg.Go(func() {
		w.dispatch(ctx)
	})
	w.wg.Go(func() {
		w.loop(ctx)
	})
	w.healthMu.Lock()
	w.started = true
	w.healthMu.Unlock()
	done := make(chan struct{})
	w.done = done
	go func() {
		w.wg.Wait()
		close(done)
	}()
	mlog.Infof("watcher: monitoring the sync folder")
	return nil
}

func (w *Watcher) syncWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-w.syncCh:
			w.syncFile(p)
		}
	}
}

func (w *Watcher) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}

	w.mu.Lock()
	w.pending = make(map[string]time.Time)
	w.mu.Unlock()

	w.fsWatcher.Close()
	awaitLoopExit(w.done, "watcher")
}

func (w *Watcher) Health() (started, ok bool, category string) {
	w.healthMu.Lock()
	defer w.healthMu.Unlock()
	return w.started, w.watchErr == "", w.watchErr
}

func (w *Watcher) setWatchErr(category string) {
	w.healthMu.Lock()
	defer w.healthMu.Unlock()
	w.watchErr = category
}

func (w *Watcher) addRecursive(dir string) {
	failure := ""
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !safeSyncPath(w.syncDir, path) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != w.syncDir && (shouldIgnore(name) || name == ".pigcloud") {
				return filepath.SkipDir
			}
			if err := w.fsWatcher.Add(path); err != nil && failure == "" {
				failure = "watch_failed"
				if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EMFILE) {
					failure = "watch_limit"
				}
			}
		}
		return nil
	})
	if failure != "" {
		w.setWatchErr(failure)
		mlog.Warnf("watcher: some folders are not watched (%s); changes there wait for the reconciler", failure)
	}
}

func (w *Watcher) loop(ctx context.Context) {
	defer mlog.RecoverPanic("watcher")

	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}
			w.handleEvent(ctx, event)

		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			mlog.Errorf("watcher: error (%s)", mlog.Cause(err))
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				mlog.Warnf("watcher: event overflow, rescanning the sync folder")
				w.wg.Go(func() {
					w.rescan(ctx)
				})
			}
		}
	}
}

func (w *Watcher) rescan(ctx context.Context) {
	w.setWatchErr("")
	w.addRecursive(w.syncDir)
	filepath.WalkDir(w.syncDir, func(path string, entry os.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil || path == w.syncDir {
			return nil
		}
		if !safeSyncPath(w.syncDir, path) || shouldIgnore(entry.Name()) || entry.Name() == ".pigcloud" {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		inode, _ := w.cacheDB.GetInodeByPath(w.toRemotePath(path))
		if entry.IsDir() {
			if inode == nil {
				w.handleCreate(ctx, path)
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		if inode == nil || inode.Dirty || info.Size() != inode.Size || info.ModTime().Unix() != inode.LocalMtime {
			w.scheduleSync(path)
		}
		return nil
	})
	w.queueMissedDeletes(ctx, "")
}

func (w *Watcher) queueMissedDeletes(ctx context.Context, under string) {
	inodes, err := w.cacheDB.InodesUnder(under)
	if under == "" {
		inodes, err = w.cacheDB.AllInodes()
	}
	if err != nil {
		return
	}
	missing := func(p string) bool {
		_, err := os.Lstat(p)
		return os.IsNotExist(err)
	}
	targets := map[string]bool{}
	var candidateIDs []int64
	for _, in := range inodes {
		lp, ok := w.toLocalPath(in.RemotePath)
		if !ok || !missing(lp) || !localDeleteEvidence(w.cacheDB, in, in.Etag) || onOtherDevice(in, lp) {
			continue
		}
		if active, _ := w.cacheDB.HasActiveWriteback(in.ID, "delete"); active {
			continue
		}
		candidateIDs = append(candidateIDs, in.ID)
		for parent := filepath.Dir(lp); parent != w.syncDir && strings.HasPrefix(parent, w.syncDir) && missing(parent); parent = filepath.Dir(parent) {
			if tracked, _ := w.cacheDB.GetInodeByPath(w.toRemotePath(parent)); tracked == nil {
				break
			}
			lp = parent
		}
		targets[lp] = true
	}
	held := massDelete(w.cacheDB, len(candidateIDs))
	if under == "" {
		var heldIDs []int64
		if held {
			heldIDs = candidateIDs
		}
		w.cacheDB.SetMassDeleteHeld("watcher", heldIDs)
	}
	if held {
		mlog.Warnf("watcher: holding %d missing files instead of deleting them remotely", len(candidateIDs))
		return
	}
	for target := range targets {
		w.handleRemove(ctx, target)
	}
}

func (w *Watcher) toLocalPath(remotePath string) (string, bool) {
	rel := remotePath
	if w.remotePath != "" && w.remotePath != "/" {
		if !strings.HasPrefix(remotePath, w.remotePath+"/") {
			return "", false
		}
		rel = strings.TrimPrefix(remotePath, w.remotePath+"/")
	}
	if rel == "" {
		return "", false
	}
	p := filepath.Join(w.syncDir, filepath.FromSlash(rel))
	return p, safeSyncPath(w.syncDir, p)
}

func (w *Watcher) handleEvent(ctx context.Context, event fsnotify.Event) {
	localPath := filepath.Clean(event.Name)
	name := filepath.Base(localPath)

	if shouldIgnore(name) {
		return
	}

	rel, err := filepath.Rel(w.syncDir, localPath)
	if err != nil {
		return
	}
	if strings.HasPrefix(rel, ".pigcloud") {
		return
	}

	if _, suppressed := w.suppress.Load(localPath); suppressed {
		return
	}

	switch {
	case event.Has(fsnotify.Create):
		w.handleCreate(ctx, localPath)

	case event.Has(fsnotify.Write):
		w.handleWrite(ctx, localPath)

	case event.Has(fsnotify.Remove):
		w.handleRemove(ctx, localPath)

	case event.Has(fsnotify.Rename):
		w.handleRemove(ctx, localPath)
	}
}

func (w *Watcher) handleCreate(ctx context.Context, localPath string) {
	if !safeSyncPath(w.syncDir, localPath) {
		return
	}
	info, err := os.Stat(localPath)
	if err != nil {
		return
	}

	if info.IsDir() {
		w.fsWatcher.Add(localPath)
		w.addRecursive(localPath)
		if w.claimMove(localPath, info) {
			return
		}

		remotePath := w.toRemotePath(localPath)
		name := filepath.Base(localPath)

		ok, _ := vfs.ValidateDirName(name)
		if !ok {
			return
		}

		if existing, _ := w.cacheDB.GetInodeByPath(remotePath); existing != nil {
			if deleting, _ := w.cacheDB.HasActiveWriteback(existing.ID, "delete"); deleting {
				if w.cacheDB.CancelPendingWriteback(existing.ID, "delete") {
					w.enqueueExistingChildren(ctx, localPath)
					w.queueMissedDeletes(ctx, remotePath)
					return
				}
				requeueTree(w.cacheDB, remotePath, w.toLocalPath)
				w.enqueueExistingChildren(ctx, localPath)
			}
			return
		}

		inode := &cache.Inode{
			RemotePath:  remotePath,
			DisplayName: name,
			IsDir:       true,
			Mtime:       time.Now().Unix(),
			SyncStatus:  cache.StatusPending,
		}
		id, err := w.cacheDB.UpsertInode(inode)
		if err != nil {
			mlog.Warnf("watcher: create folder row failed (%s)", mlog.Cause(err))
			return
		}
		w.cacheDB.EnqueueWriteback(id, "mkdir", remotePath, "")
		mlog.Debugf("watcher: new folder inode %d", id)

		w.enqueueExistingChildren(ctx, localPath)
		return
	}

	if w.claimMove(localPath, info) {
		return
	}
	w.scheduleSync(localPath)
}

func (w *Watcher) enqueueExistingChildren(ctx context.Context, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if shouldIgnore(name) || name == ".pigcloud" {
			continue
		}
		childPath := filepath.Join(dir, name)
		if e.IsDir() {
			w.handleCreate(ctx, childPath)
		} else {
			w.scheduleSync(childPath)
		}
	}
}

func (w *Watcher) handleWrite(_ context.Context, localPath string) {
	if !safeSyncPath(w.syncDir, localPath) {
		return
	}
	info, err := os.Stat(localPath)
	if err != nil || info.IsDir() {
		return
	}
	w.scheduleSync(localPath)
}

func (w *Watcher) handleRemove(_ context.Context, localPath string) {
	if !safeSyncPath(w.syncDir, localPath) {
		return
	}
	remotePath := w.toRemotePath(localPath)

	existing, err := w.cacheDB.GetInodeByPath(remotePath)
	if err != nil || existing == nil {
		return
	}

	remote := existing.NodeID != "" || existing.Etag != "" ||
		existing.SyncStatus == cache.StatusSynced || existing.SyncStatus == cache.StatusConflict
	if !remote {
		w.cacheDB.DeleteWritebackByInode(existing.ID)
		w.cacheDB.DeleteInode(remotePath)
		mlog.Debugf("watcher: removed local-only inode %d (was %s)", existing.ID, existing.SyncStatus)
		return
	}

	if w.parkForMove(existing, remotePath, localPath) {
		return
	}
	w.cacheDB.EnqueueWriteback(existing.ID, "delete", remotePath, "")
	mlog.Debugf("watcher: queued delete of inode %d", existing.ID)
}

func (w *Watcher) scheduleSync(localPath string) {
	w.mu.Lock()
	if w.pending == nil {
		w.pending = make(map[string]time.Time)
	}
	w.pending[localPath] = time.Now().Add(watchDebounce)
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Watcher) dispatch(ctx context.Context) {
	timer := time.NewTimer(watchDebounce)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-timer.C:
		}
		due, wait := w.takeDue(time.Now())
		for _, p := range due {
			select {
			case w.syncCh <- p:
			case <-ctx.Done():
				return
			}
		}
		timer.Reset(wait)
	}
}

func (w *Watcher) takeDue(now time.Time) ([]string, time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	wait := watchDebounce
	var due []string
	for p, at := range w.pending {
		if !at.After(now) {
			due = append(due, p)
			delete(w.pending, p)
		} else if d := at.Sub(now); d < wait {
			wait = d
		}
	}
	return due, wait
}

func (w *Watcher) syncFile(localPath string) {
	if !safeSyncPath(w.syncDir, localPath) {
		return
	}
	info, err := os.Stat(localPath)
	if err != nil {
		w.expireVanished(localPath)
		return
	}
	if info.IsDir() {
		return
	}

	name := filepath.Base(localPath)
	remotePath := w.toRemotePath(localPath)
	size := info.Size()

	ok, reason := vfs.ValidateFile(name, size)
	rejected := !ok

	if !safeSyncPath(w.syncDir, localPath) {
		return
	}
	hash, err := w.store.PutFile(localPath)
	if err != nil {
		mlog.Warnf("watcher: cache put failed (%s)", mlog.Cause(err))
		return
	}
	if w.evictor != nil {
		w.evictor.RunIfNeeded()
	}

	existing, _ := w.cacheDB.GetInodeByPath(remotePath)

	if existing != nil && existing.SyncStatus == cache.StatusSynced {
		if existing.ContentHash == hash {
			return
		}
		if _, baseline, _, err := w.cacheDB.LocalContentState(existing.ID); err == nil && baseline == hash {
			cache.ReleaseBlob(w.cacheDB, w.store, hash, 0)
			return
		}
	}

	supersededHash := ""
	if existing != nil && existing.ContentHash != hash {
		supersededHash = existing.ContentHash
	}

	status := cache.StatusPending
	if rejected {
		status = cache.StatusRejected
	}

	inode := &cache.Inode{
		RemotePath:   remotePath,
		DisplayName:  name,
		IsDir:        false,
		Size:         size,
		Mtime:        info.ModTime().Unix(),
		Cached:       true,
		Dirty:        true,
		ContentHash:  hash,
		SyncStatus:   status,
		StatusReason: reason,
	}
	id, err := w.cacheDB.UpsertInode(inode)
	if err != nil {
		mlog.Warnf("watcher: upsert of a changed file failed (%s)", mlog.Cause(err))
		return
	}
	cache.ReleaseBlob(w.cacheDB, w.store, supersededHash, id)
	if existing == nil || existing.ContentHash != hash {
		w.cacheDB.ClearSyncFailure(id, cache.FailureUpload)
	}

	if rejected {
		mlog.Warnf("watcher: rejected inode %d (see pc mn files for the reason)", id)
		return
	}

	w.cacheDB.EnqueueWriteback(id, "upload", remotePath, "")
	mlog.Debugf("watcher: queued upload of inode %d (%d bytes)", id, size)
}

func (w *Watcher) toRemotePath(localPath string) string {
	rel, err := filepath.Rel(w.syncDir, localPath)
	if err != nil {
		return filepath.Base(localPath)
	}
	rel = filepath.ToSlash(rel)
	if w.remotePath == "" || w.remotePath == "/" {
		return rel
	}
	return w.remotePath + "/" + rel
}

func shouldIgnore(name string) bool {
	if ignoredNames[name] {
		return true
	}
	for _, prefix := range ignoredPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	for _, suffix := range ignoredSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	if strings.HasPrefix(name, ".") && name != "." && name != ".." {
		return true
	}
	return false
}
