package syncer

import (
	"os"
	"path/filepath"
	"slices"
	"time"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"
)

type vanishedItem struct {
	inodeID    int64
	remotePath string
	localPath  string
	isDir      bool
	size       int64
	mtime      int64
	children   []string
}

func (w *Watcher) parkForMove(in *cache.Inode, remotePath, localPath string) bool {
	identity := fileIdentity(in.LocalFileID)
	if identity == "" || in.NodeID == "" || !w.cacheDB.TreeSettled(remotePath) {
		return false
	}
	item := vanishedItem{inodeID: in.ID, remotePath: remotePath, localPath: localPath, isDir: in.IsDir, size: in.Size, mtime: in.LocalMtime}
	if in.IsDir {
		children, err := w.cacheDB.ChildNames(remotePath)
		if err != nil || len(children) == 0 {
			return false
		}
		slices.Sort(children)
		item.children = children
	}
	w.mu.Lock()
	if w.vanished == nil {
		w.vanished = map[string]vanishedItem{}
	}
	w.vanished[identity] = item
	w.mu.Unlock()
	w.scheduleSync(localPath)
	return true
}

func (w *Watcher) expireVanished(localPath string) {
	w.mu.Lock()
	var item vanishedItem
	found := false
	for identity, v := range w.vanished {
		if v.localPath == localPath {
			item, found = v, true
			delete(w.vanished, identity)
			break
		}
	}
	w.mu.Unlock()
	if found {
		w.cacheDB.EnqueueWriteback(item.inodeID, "delete", item.remotePath, "")
		mlog.Debugf("watcher: queued delete of inode %d", item.inodeID)
	}
}

func samePayload(item vanishedItem, localPath string, info os.FileInfo) bool {
	if item.isDir != info.IsDir() {
		return false
	}
	if !item.isDir {
		return info.Size() == item.size && info.ModTime().Unix() == item.mtime
	}
	entries, err := os.ReadDir(localPath)
	if err != nil {
		return false
	}
	var names []string
	for _, e := range entries {
		if !shouldIgnore(e.Name()) {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return slices.Equal(names, item.children)
}

func (w *Watcher) claimMove(localPath string, info os.FileInfo) bool {
	identity := fileIdentity(localFileID(info) + "@0")
	if identity == "" {
		return false
	}
	w.mu.Lock()
	item, ok := w.vanished[identity]
	if ok {
		delete(w.vanished, identity)
		delete(w.pending, item.localPath)
	}
	w.mu.Unlock()
	if !ok || item.localPath == localPath {
		return false
	}
	name := filepath.Base(localPath)
	valid, _ := vfs.ValidateDirName(name)
	if !info.IsDir() {
		valid, _ = vfs.ValidateFile(name, info.Size())
	}
	newRemote := w.toRemotePath(localPath)
	if !valid || !samePayload(item, localPath, info) || w.cacheDB.MoveInodeTree(item.remotePath, newRemote, name) != nil {
		w.cacheDB.EnqueueWriteback(item.inodeID, "delete", item.remotePath, "")
		return false
	}
	w.cacheDB.SetLocalFileID(item.inodeID, recordedSignature(info, time.Now()))
	w.cacheDB.EnqueueWriteback(item.inodeID, "rename", item.remotePath, cache.WritebackExtra{Target: newRemote}.Marshal())
	if w.vfs != nil {
		if node := w.vfs.NodeByID(item.inodeID); node != nil && node.Parent != nil {
			w.vfs.DetachChild(node.Parent, node.Name)
		}
	}
	mlog.Debugf("watcher: queued move of inode %d", item.inodeID)
	return true
}
