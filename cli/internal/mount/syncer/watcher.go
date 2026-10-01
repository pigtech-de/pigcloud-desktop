package syncer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	debounce map[string]*time.Timer

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
		debounce:   make(map[string]*time.Timer),
		syncCh:     make(chan string, syncQueueSize),
		stopCh:     make(chan struct{}),
	}, nil
}

func (w *Watcher) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel

	if err := w.addRecursive(w.syncDir); err != nil {
		cancel()
		return err
	}

	for range syncWorkers {
		w.wg.Go(func() {
			w.syncWorker(ctx)
		})
	}
	w.wg.Go(func() {
		w.loop(ctx)
	})
	done := make(chan struct{})
	w.done = done
	go func() {
		w.wg.Wait()
		close(done)
	}()
	mlog.Infof("watcher: monitoring %s", w.syncDir)
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
	for _, t := range w.debounce {
		t.Stop()
	}
	w.debounce = make(map[string]*time.Timer)
	w.mu.Unlock()

	w.fsWatcher.Close()
	awaitLoopExit(w.done, "watcher")
}

func (w *Watcher) addRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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
			if shouldIgnore(name) || name == ".pigcloud" {
				return filepath.SkipDir
			}
			return w.fsWatcher.Add(path)
		}
		return nil
	})
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
			mlog.Errorf("watcher: error: %v", err)
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				mlog.Warnf("watcher: event overflow — rescanning %s", w.syncDir)
				w.wg.Go(func() {
					w.addRecursive(w.syncDir)
					w.enqueueExistingChildren(ctx, w.syncDir)
				})
			}
		}
	}
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

		remotePath := w.toRemotePath(localPath)
		name := filepath.Base(localPath)

		ok, _ := vfs.ValidateDirName(name)
		if !ok {
			return
		}

		if existing, _ := w.cacheDB.GetInodeByPath(remotePath); existing != nil {
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
			mlog.Warnf("watcher: create dir inode: %v", err)
			return
		}
		w.cacheDB.EnqueueWriteback(id, "mkdir", remotePath, "")
		mlog.Debugf("watcher: new directory %s", remotePath)

		w.enqueueExistingChildren(ctx, localPath)
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

	if existing.SyncStatus != cache.StatusSynced && existing.SyncStatus != cache.StatusConflict {
		w.cacheDB.DeleteWritebackByInode(existing.ID)
		w.cacheDB.DeleteInode(remotePath)
		mlog.Debugf("watcher: removed local-only %s (was %s)", remotePath, existing.SyncStatus)
		return
	}

	w.cacheDB.EnqueueWriteback(existing.ID, "delete", remotePath, "")
	mlog.Debugf("watcher: queued delete %s", remotePath)
}

func (w *Watcher) scheduleSync(localPath string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if t, ok := w.debounce[localPath]; ok {
		t.Stop()
	}

	w.debounce[localPath] = time.AfterFunc(watchDebounce, func() {
		w.mu.Lock()
		delete(w.debounce, localPath)
		w.mu.Unlock()

		select {
		case w.syncCh <- localPath:
		case <-w.stopCh:
		}
	})
}

func (w *Watcher) syncFile(localPath string) {
	if !safeSyncPath(w.syncDir, localPath) {
		return
	}
	info, err := os.Stat(localPath)
	if err != nil {
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
		mlog.Warnf("watcher: cache put %s: %v", localPath, err)
		return
	}
	if w.evictor != nil {
		w.evictor.RunIfNeeded()
	}

	existing, _ := w.cacheDB.GetInodeByPath(remotePath)

	if existing != nil && existing.ContentHash == hash && existing.SyncStatus == cache.StatusSynced {
		return
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
		mlog.Warnf("watcher: upsert inode %s: %v", remotePath, err)
		return
	}
	cache.ReleaseBlob(w.cacheDB, w.store, supersededHash, id)

	if rejected {
		mlog.Warnf("watcher: rejected %s: %s", remotePath, reason)
		return
	}

	w.cacheDB.EnqueueWriteback(id, "upload", remotePath, "")
	mlog.Debugf("watcher: queued upload %s (%d bytes)", remotePath, size)
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
