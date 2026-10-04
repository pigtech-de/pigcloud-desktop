package vfs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/transfer"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrNotEmpty    = errors.New("directory not empty")
	ErrExists      = errors.New("already exists")
	ErrIsDir       = errors.New("is a directory")
	ErrReadOnly    = errors.New("read-only filesystem")
	ErrInvalidName = errors.New("invalid name")
)

type VFS struct {
	Root       *Node
	RemoteBase string

	Cache   *cache.DB
	Store   *cache.Store
	Evictor *cache.Evictor
	Client  *api.Client

	PublicKey  *crypto.PublicKeySet
	PrivateKey *crypto.PrivateKeySet
	NameKey    []byte

	SigningPublicKey  *crypto.SigningPublicKeySet
	SigningPrivateKey *crypto.SigningPrivateKeySet

	DirTTL time.Duration
	readOnly bool

	Online    bool
	nodesByID map[int64]*Node
	idMu      sync.RWMutex

	dlSem chan struct{}

	ctx    context.Context
	cancel context.CancelFunc

	statfsMu    sync.Mutex
	statfsUsed  int64
	statfsLimit int64
	statfsAt    time.Time
}

const (
	accessFlushInterval = 60 * time.Second

	statfsTTL = 30 * time.Second
)

func New(remoteBase string, cacheDB *cache.DB, store *cache.Store, evictor *cache.Evictor,
	client *api.Client, pubKey *crypto.PublicKeySet, privKey *crypto.PrivateKeySet, nameKey []byte,
	signPub *crypto.SigningPublicKeySet, signPriv *crypto.SigningPrivateKeySet) *VFS {

	if remoteBase == "/" {
		remoteBase = ""
	}
	remoteBase = strings.TrimPrefix(remoteBase, "/")

	vfs := &VFS{
		Root:              NewRootNode(remoteBase),
		RemoteBase:        remoteBase,
		Cache:             cacheDB,
		Store:             store,
		Evictor:           evictor,
		Client:            client,
		PublicKey:         pubKey,
		PrivateKey:        privKey,
		NameKey:           nameKey,
		SigningPublicKey:  signPub,
		SigningPrivateKey: signPriv,
		DirTTL:            30 * time.Second,
		Online:            true,
		nodesByID:         make(map[int64]*Node),
		dlSem:             make(chan struct{}, 4),
	}
	vfs.ctx, vfs.cancel = context.WithCancel(context.Background())

	if evictor != nil {
		evictor.SetHooks(vfs.evictInUse, vfs.evictClear)
	}

	return vfs
}

func (v *VFS) SetReadOnly(ro bool) {
	v.readOnly = ro
	if v.Cache != nil {
		v.Cache.SetWritebackDisabled(ro)
	}
}

func (v *VFS) evictInUse(id int64) bool {
	n := v.NodeByID(id)
	if n == nil {
		return false
	}
	n.Mu.RLock()
	defer n.Mu.RUnlock()
	return n.OpenCount > 0 || n.Dirty
}

func (v *VFS) evictClear(id int64) {
	n := v.NodeByID(id)
	if n == nil {
		return
	}
	n.Mu.Lock()
	n.Cached = false
	n.ContentHash = ""
	n.Mu.Unlock()
}

func (v *VFS) Lookup(parent *Node, name string) (*Node, error) {
	if IsExcludedDir(name) {
		return nil, fmt.Errorf("excluded directory: %s", name)
	}

	child := parent.GetChild(name)
	if child != nil {
		return child, nil
	}

	if !parent.Loaded {
		if err := v.populateDir(parent); err != nil {
			return nil, err
		}
		child = parent.GetChild(name)
	}

	if child == nil {
		return nil, fmt.Errorf("not found: %s", name)
	}
	return child, nil
}

func (v *VFS) Readdir(parent *Node) ([]*Node, error) {
	if !parent.IsDir {
		return nil, fmt.Errorf("not a directory")
	}

	if !parent.Loaded {
		if err := v.populateDir(parent); err != nil {
			return nil, err
		}
	}

	return parent.ListChildren(), nil
}

func (v *VFS) Open(node *Node) error {
	node.Mu.Lock()
	node.OpenCount++

	if node.Cached || node.Dirty {
		now := time.Now()
		doTouch := now.Sub(node.lastAccessFlush) > accessFlushInterval
		if doTouch {
			node.lastAccessFlush = now
		}
		node.Mu.Unlock()
		if doTouch {
			v.Cache.TouchAccess(node.ID)
		}
		return nil
	}

	if node.Downloading {
		ch := node.DownloadCh
		node.Mu.Unlock()
		<-ch
		node.Mu.RLock()
		cached, cause := node.Cached, node.DownloadErr
		node.Mu.RUnlock()
		if cached {
			return nil
		}
		node.Mu.Lock()
		node.OpenCount--
		node.Mu.Unlock()
		if cause != nil {
			return cause
		}
		return fmt.Errorf("download failed (waited)")
	}

	node.Downloading = true
	node.DownloadCh = make(chan struct{})
	node.Mu.Unlock()

	var err error
	defer func() { v.finishDownload(node, err) }()

	err = v.downloadFailureBarrier(node)
	if err == nil {
		err = v.downloadAndCache(node)
		v.settleDownloadFailure(node, err)
	}

	return err
}

func (v *VFS) finishDownload(node *Node, err error) {
	node.Mu.Lock()
	node.Downloading = false
	node.DownloadErr = err
	close(node.DownloadCh)
	if err != nil {
		node.OpenCount--
	}
	node.Mu.Unlock()
}

func (v *VFS) downloadFailureBarrier(node *Node) error {
	if v.Cache == nil {
		return nil
	}
	f := v.Cache.TransferWithheld(node.ID, cache.FailureDownload)
	if f == nil {
		return nil
	}
	if f.LastError == "" {
		return fmt.Errorf("download withheld after %d failed attempt(s)", f.Attempts)
	}
	return errors.New(f.LastError)
}

func (v *VFS) settleDownloadFailure(node *Node, err error) {
	if node.ID == 0 || v.Cache == nil {
		return
	}
	if err == nil {
		v.Cache.ClearSyncFailure(node.ID, cache.FailureDownload)
		v.Cache.SetSyncStatus(node.ID, cache.StatusSynced, "")
		return
	}
	v.Cache.RecordTransferFailure("vfs", node.RemotePath, node.ID, cache.FailureDownload, err)
}

func (v *VFS) Read(node *Node, off int64, size int) ([]byte, error) {
	node.Mu.RLock()
	defer node.Mu.RUnlock()

	if node.Dirty && node.Data != nil {
		end := off + int64(size)
		if off >= int64(len(node.Data)) {
			return nil, nil
		}
		if end > int64(len(node.Data)) {
			end = int64(len(node.Data))
		}
		return node.Data[off:end], nil
	}

	if !node.Cached || node.ContentHash == "" {
		return nil, fmt.Errorf("file not cached: %s", node.RemotePath)
	}

	return v.Store.ReadAt(node.ContentHash, off, size)
}

func (v *VFS) Write(node *Node, off int64, data []byte) (int, error) {
	if v.readOnly {
		return 0, ErrReadOnly
	}
	node.Mu.Lock()
	defer node.Mu.Unlock()

	if node.Data == nil && node.Cached && node.ContentHash != "" {
		existing, err := v.Store.Get(node.ContentHash)
		if err != nil {
			return 0, fmt.Errorf("read cached content: %w", err)
		}
		node.Data = existing
	}
	if node.Data == nil {
		node.Data = make([]byte, 0)
	}

	end := off + int64(len(data))
	if end > int64(len(node.Data)) {
		extended := make([]byte, end)
		copy(extended, node.Data)
		node.Data = extended
	}
	copy(node.Data[off:], data)

	node.Size = int64(len(node.Data))
	node.Mtime = time.Now()
	node.Dirty = true
	node.WriteGen++
	node.SyncStatus = cache.StatusPending

	return len(data), nil
}

func (v *VFS) Flush(node *Node) error {
	node.Mu.Lock()
	if !node.Dirty || node.Data == nil {
		node.Mu.Unlock()
		return nil
	}
	data := node.Data
	node.Mu.Unlock()

	hash, err := v.Store.Put(data)
	if err != nil {
		return fmt.Errorf("write to cache: %w", err)
	}

	node.Mu.Lock()
	superseded := node.ContentHash
	node.ContentHash = hash
	node.Cached = true
	node.Mu.Unlock()

	v.Cache.MarkCached(node.ID, hash)
	v.Cache.MarkDirty(node.ID)
	if superseded != hash {
		cache.ReleaseBlob(v.Cache, v.Store, superseded, node.ID)
	}

	ok, reason := ValidateFile(node.Name, node.Size)
	if !ok {
		v.Cache.SetSyncStatus(node.ID, cache.StatusRejected, reason)
		node.Mu.Lock()
		node.SyncStatus = cache.StatusRejected
		node.StatusReason = reason
		node.Mu.Unlock()
		return nil
	}

	v.Cache.EnqueueWriteback(node.ID, "upload", node.RemotePath, "")

	return nil
}

func (v *VFS) Release(node *Node) error {
	node.Mu.Lock()
	node.OpenCount--
	shouldFlush := node.OpenCount <= 0 && node.Dirty
	node.Mu.Unlock()

	if shouldFlush {
		return v.Flush(node)
	}
	return nil
}

func (v *VFS) Create(parent *Node, name string) (*Node, error) {
	if v.readOnly {
		return nil, ErrReadOnly
	}
	if !parent.IsDir {
		return nil, fmt.Errorf("parent is not a directory")
	}

	if existing := parent.GetChild(name); existing != nil {
		if existing.IsDir {
			return nil, ErrExists
		}
		if err := v.Truncate(existing, 0); err != nil {
			return nil, err
		}
		return existing, nil
	}

	remotePath := joinPath(parent.RemotePath, name)

	ok, reason := ValidateFile(name, 0)
	status := cache.StatusPending
	if !ok {
		status = cache.StatusRejected
	}

	node := NewFileNode(name, remotePath, 0, time.Now(), parent)
	node.SyncStatus = status
	node.StatusReason = reason
	node.Dirty = true
	node.Data = make([]byte, 0)

	inode := &cache.Inode{
		RemotePath:   remotePath,
		DisplayName:  name,
		IsDir:        false,
		Size:         0,
		Mtime:        time.Now().Unix(),
		Dirty:        true,
		SyncStatus:   status,
		StatusReason: reason,
		ParentID:     parent.ID,
	}
	id, err := v.Cache.UpsertInode(inode)
	if err != nil {
		return nil, fmt.Errorf("persist inode: %w", err)
	}
	node.ID = id

	v.AttachChild(parent, node)

	return node, nil
}

func (v *VFS) Mkdir(parent *Node, name string) (*Node, error) {
	if v.readOnly {
		return nil, ErrReadOnly
	}
	if !parent.IsDir {
		return nil, fmt.Errorf("parent is not a directory")
	}

	ok, reason := ValidateDirName(name)
	if !ok {
		return nil, fmt.Errorf("invalid directory name: %s", reason)
	}

	remotePath := joinPath(parent.RemotePath, name)
	fullPath := remotePath

	options := map[string]string{
		"source": "/" + remotePath,
	}
	v.addE2eeNameFields(options, name, fullPath)
	v.addPathTokens(options, []string{fullPath})

	resp, err := v.Client.Execute(context.Background(), "mk", options)
	if err != nil {
		return nil, fmt.Errorf("mkdir API call: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("mkdir failed: %s", resp.Message)
	}

	node := NewDirNode(name, remotePath, parent)

	inode := &cache.Inode{
		RemotePath:  remotePath,
		DisplayName: name,
		IsDir:       true,
		Mtime:       time.Now().Unix(),
		SyncStatus:  cache.StatusSynced,
		ParentID:    parent.ID,
	}
	id, err := v.Cache.UpsertInode(inode)
	if err != nil {
		return nil, fmt.Errorf("persist inode: %w", err)
	}
	node.ID = id

	v.AttachChild(parent, node)

	return node, nil
}

func (v *VFS) Unlink(parent *Node, name string) error {
	if v.readOnly {
		return ErrReadOnly
	}
	child := parent.GetChild(name)
	if child == nil {
		return ErrNotFound
	}
	if child.IsDir {
		return ErrIsDir
	}

	child.Mu.RLock()
	remotePath := child.RemotePath
	contentHash := child.ContentHash
	childID := child.ID
	uploaded := child.SyncStatus == cache.StatusSynced || child.SyncStatus == cache.StatusConflict
	child.Mu.RUnlock()

	if uploaded {
		options := map[string]string{"source": "/" + remotePath}
		v.addPathTokens(options, []string{remotePath})
		resp, err := v.Client.Execute(context.Background(), "rm", options)
		if err != nil {
			return fmt.Errorf("rm API call: %w", err)
		}
		if !resp.Success {
			return fmt.Errorf("rm failed: %s", resp.Message)
		}
	}

	parent.RemoveChild(name)
	v.Cache.DeleteWritebackByInode(childID)
	cache.ReleaseBlob(v.Cache, v.Store, contentHash, childID)
	v.Cache.DeleteInode(remotePath)
	v.untrackNode(child)

	return nil
}

func (v *VFS) Rmdir(parent *Node, name string) error {
	if v.readOnly {
		return ErrReadOnly
	}
	child := parent.GetChild(name)
	if child == nil {
		return ErrNotFound
	}
	if !child.IsDir {
		return fmt.Errorf("not a directory: %s", name)
	}
	if !child.Loaded {
		if err := v.populateDir(child); err != nil {
			return fmt.Errorf("rmdir: list %s: %w", name, err)
		}
	}
	if child.ChildCount() > 0 {
		return ErrNotEmpty
	}

	remotePath := child.RemotePath
	options := map[string]string{
		"source": "/" + remotePath,
	}
	v.addPathTokens(options, []string{remotePath})

	resp, err := v.Client.Execute(context.Background(), "rm", options)
	if err != nil {
		return fmt.Errorf("rm API call: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rm failed: %s", resp.Message)
	}

	parent.RemoveChild(name)
	v.Cache.DeleteChildren(child.ID)
	v.Cache.DeleteInode(remotePath)
	v.untrackNode(child)

	return nil
}

func (v *VFS) Rename(oldParent *Node, oldName string, newParent *Node, newName string) error {
	if v.readOnly {
		return ErrReadOnly
	}
	child := oldParent.GetChild(oldName)
	if child == nil {
		return ErrNotFound
	}

	newRemotePath := joinPath(newParent.RemotePath, newName)

	child.Mu.RLock()
	uploaded := child.SyncStatus == cache.StatusSynced || child.SyncStatus == cache.StatusConflict
	isDir := child.IsDir
	child.Mu.RUnlock()

	if !fsutil.IsSafeName(newName) {
		return ErrInvalidName
	}
	if isDir {
		if ok, _ := ValidateDirName(newName); !ok {
			return ErrInvalidName
		}
	} else if !validNameRegex.MatchString(newName) {
		return ErrInvalidName
	}

	if !uploaded && !isDir {
		return v.renameLocalOnlyFile(oldParent, child, oldName, newParent, newName, newRemotePath)
	}

	options := map[string]string{
		"source": "/" + child.RemotePath,
		"target": "/" + newRemotePath,
	}
	v.addE2eeNameFields(options, newName, newRemotePath)
	v.addPathTokens(options, []string{child.RemotePath, newRemotePath})

	resp, err := v.Client.Execute(context.Background(), "mv", options)
	if err != nil {
		return fmt.Errorf("mv API call: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("mv failed: %s", resp.Message)
	}

	child.Mu.RLock()
	oldRemotePath := child.RemotePath
	child.Mu.RUnlock()

	oldParent.RemoveChild(oldName)
	v.untrackNode(child)
	child.Mu.Lock()
	child.Name = newName
	child.RemotePath = newRemotePath
	child.Parent = newParent
	child.Mu.Unlock()
	newParent.AddChild(child)

	v.Cache.DeleteInode(oldRemotePath)
	id, _ := v.Cache.UpsertInode(nodeToInode(child, newParent.ID))
	child.Mu.Lock()
	child.ID = id
	child.Mu.Unlock()
	v.trackNode(child)

	if isDir {
		v.rewriteSubtree(child, oldRemotePath, newRemotePath)
	}

	return nil
}

func (v *VFS) rewriteSubtree(dir *Node, oldPrefix, newPrefix string) {
	for _, child := range dir.ListChildren() {
		child.Mu.RLock()
		oldPath := child.RemotePath
		childIsDir := child.IsDir
		child.Mu.RUnlock()

		newPath := newPrefix + strings.TrimPrefix(oldPath, oldPrefix)

		v.untrackNode(child)
		child.Mu.Lock()
		child.RemotePath = newPath
		child.Mu.Unlock()

		v.Cache.DeleteInode(oldPath)
		id, _ := v.Cache.UpsertInode(nodeToInode(child, dir.ID))
		child.Mu.Lock()
		child.ID = id
		child.Mu.Unlock()
		v.trackNode(child)

		if childIsDir {
			v.rewriteSubtree(child, oldPath, newPath)
		}
	}
}

func (v *VFS) renameLocalOnlyFile(oldParent, child *Node, oldName string, newParent *Node, newName, newRemotePath string) error {
	child.Mu.RLock()
	oldRemotePath := child.RemotePath
	oldID := child.ID
	child.Mu.RUnlock()

	oldParent.RemoveChild(oldName)
	v.untrackNode(child)
	child.Mu.Lock()
	child.Name = newName
	child.RemotePath = newRemotePath
	child.Parent = newParent
	child.Mu.Unlock()
	newParent.AddChild(child)

	v.Cache.DeleteWritebackByInode(oldID)
	v.Cache.DeleteInode(oldRemotePath)
	id, _ := v.Cache.UpsertInode(nodeToInode(child, newParent.ID))
	child.Mu.Lock()
	child.ID = id
	child.Mu.Unlock()
	v.trackNode(child)

	v.Cache.EnqueueWriteback(id, "upload", newRemotePath, "")
	return nil
}

func (v *VFS) Truncate(node *Node, size int64) error {
	if v.readOnly {
		return ErrReadOnly
	}
	node.Mu.Lock()
	defer node.Mu.Unlock()

	if node.Data == nil {
		if node.Cached && node.ContentHash != "" {
			existing, err := v.Store.Get(node.ContentHash)
			if err != nil {
				return err
			}
			node.Data = existing
		} else {
			node.Data = make([]byte, 0)
		}
	}

	if size < int64(len(node.Data)) {
		node.Data = node.Data[:size]
	} else if size > int64(len(node.Data)) {
		extended := make([]byte, size)
		copy(extended, node.Data)
		node.Data = extended
	}

	node.Size = size
	node.Mtime = time.Now()
	node.Dirty = true
	node.WriteGen++
	node.SyncStatus = cache.StatusPending

	return nil
}

func (v *VFS) Statfs() (usedBytes, limitBytes int64, err error) {
	v.statfsMu.Lock()
	if !v.statfsAt.IsZero() && time.Since(v.statfsAt) < statfsTTL {
		u, l := v.statfsUsed, v.statfsLimit
		v.statfsMu.Unlock()
		return u, l, nil
	}
	v.statfsMu.Unlock()

	resp, err := v.Client.Execute(context.Background(), "st", map[string]string{})
	if err != nil {
		return 0, 0, fmt.Errorf("stat API call: %w", err)
	}
	if !resp.Success {
		return 0, 0, fmt.Errorf("stat failed: %s", resp.Message)
	}

	var payload struct {
		UsedBytes  int64 `json:"usedBytes"`
		LimitBytes int64 `json:"limitBytes"`
	}
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return 0, 0, fmt.Errorf("parse stat response: %w", err)
	}

	v.statfsMu.Lock()
	v.statfsUsed, v.statfsLimit, v.statfsAt = payload.UsedBytes, payload.LimitBytes, time.Now()
	v.statfsMu.Unlock()

	return payload.UsedBytes, payload.LimitBytes, nil
}

func (v *VFS) CleanRejected() (int, error) {
	hashes, err := v.Cache.DeleteRejected()
	if err != nil {
		return 0, err
	}

	for _, h := range hashes {
		cache.ReleaseBlob(v.Cache, v.Store, h, 0)
	}

	count := v.removeFromTreeByStatus(cache.StatusRejected)

	return count, nil
}

func (v *VFS) populateDir(parent *Node) error {
	remotePath := parent.RemotePath
	source := "/"
	if remotePath != "" {
		source = "/" + remotePath
	}

	options := map[string]string{
		"source": source,
	}

	if remotePath != "" {
		v.addPathTokens(options, []string{remotePath})
	}

	resp, err := v.Client.Execute(context.Background(), "ls", options)
	if err != nil {
		v.Online = false
		mlog.Errorf("vfs: ls %q failed: %v", source, err)
		return fmt.Errorf("ls API call: %w", err)
	}
	v.Online = true

	if !resp.Success {
		return fmt.Errorf("ls failed: %s", resp.Message)
	}

	var payload api.ListPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return fmt.Errorf("parse ls response: %w", err)
	}

	parent.Mu.Lock()
	defer parent.Mu.Unlock()

	seen := make(map[string]bool)
	for _, entry := range payload.Entries {
		name := e2ee.OpenLocalName(entry.E2EEDisplayName, v.PrivateKey)
		if e2ee.IsNameUnavailable(name) {
			continue
		}

		if IsExcludedDir(name) {
			continue
		}

		seen[name] = true
		childPath := joinPath(remotePath, name)

		existing := parent.Children[name]
		if existing != nil {
			existing.Mu.Lock()
			cached, _ := v.Cache.GetInode(existing.ID)
			locallyDirty := existing.Dirty || (cached != nil && cached.Dirty)
			if locallyDirty && existing.Etag != entry.ETag {
				existing.SyncStatus = cache.StatusConflict
				existing.StatusReason = "remote changed while local edits pending"
				v.Cache.MarkLocalConflict(existing.ID, existing.StatusReason)
				existing.Mu.Unlock()
				continue
			}
			if !locallyDirty && existing.Etag != entry.ETag {
				existing.Cached = false
				v.Cache.InvalidateCache(existing.ID)
			}
			existing.Etag = entry.ETag
			v.Cache.SetRemoteVersion(existing.ID, entry.ETag)
			if entry.PlaintextSize != nil {
				existing.Size = *entry.PlaintextSize
			}
			if entry.Modified != nil {
				if t, err := time.Parse(time.RFC3339, *entry.Modified); err == nil {
					existing.Mtime = t
				}
			}
			existing.Mu.Unlock()
			continue
		}

		var node *Node
		isDir := entry.Type == "directory"
		if isDir {
			node = NewDirNode(name, childPath, parent)
		} else {
			size := int64(0)
			if entry.PlaintextSize != nil {
				size = *entry.PlaintextSize
			} else if dbInode, _ := v.Cache.GetInodeByPath(childPath); dbInode != nil {
				size = dbInode.Size
			}
			mtime := time.Now()
			if entry.Modified != nil {
				if t, err := time.Parse(time.RFC3339, *entry.Modified); err == nil {
					mtime = t
				}
			}
			node = NewFileNode(name, childPath, size, mtime, parent)
		}

		node.Etag = entry.ETag
		if prior, lookupErr := v.Cache.GetInodeByPath(childPath); lookupErr == nil && prior != nil && prior.Dirty {
			node.Dirty = true
			node.Etag = prior.Etag
			node.Size = prior.Size
			node.Mtime = time.Unix(prior.Mtime, 0)
			node.SyncStatus = prior.SyncStatus
			node.StatusReason = prior.StatusReason
			if prior.Etag != entry.ETag {
				node.SyncStatus = cache.StatusConflict
				node.StatusReason = "remote changed while local edits pending"
			}
		}
		inode := nodeToInode(node, parent.ID)
		id, err := v.Cache.UpsertInode(inode)
		if err == nil {
			node.ID = id
		}

		parent.Children[name] = node
		v.trackNode(node)
	}

	for name, child := range parent.Children {
		if !seen[name] && !child.Dirty {
			delete(parent.Children, name)
			v.untrackNode(child)
		}
	}

	parent.Loaded = true
	return nil
}

func (v *VFS) Shutdown() {
	if v.cancel != nil {
		v.cancel()
	}
}

func (v *VFS) downloadAndCache(node *Node) error {
	v.dlSem <- struct{}{}
	defer func() { <-v.dlSem }()

	mlog.Debugf("vfs: downloading %s (%d bytes)", node.RemotePath, node.Size)

	fetcher := transfer.Fetcher{
		Client: v.Client,
		Keys:   transfer.Keys{NameKey: v.NameKey, PrivateKey: v.PrivateKey, SigningKey: v.SigningPrivateKey},
		Tag:    "vfs",
	}
	plaintext, dlResult, err := fetcher.Fetch(v.ctx, node.RemotePath)
	if err != nil {
		return err
	}

	hash, err := v.Store.Put(plaintext)
	if err != nil {
		return fmt.Errorf("cache put: %w", err)
	}

	node.Mu.Lock()
	node.ContentHash = hash
	node.Cached = true
	node.Size = int64(len(plaintext))
	node.SealedKey = dlResult.SealedKey
	node.EncMeta = dlResult.EncryptionMeta
	node.Mu.Unlock()

	v.Cache.MarkCached(node.ID, hash)
	v.Cache.SetInodeSize(node.ID, int64(len(plaintext)))
	v.Evictor.RunIfNeeded()

	return nil
}

func (v *VFS) addE2eeNameFields(options map[string]string, fileName, fullPath string) {
	sealedName, err := crypto.SealDisplayName(fileName, v.PublicKey)
	if err != nil {
		return
	}
	pathToken, err := crypto.ComputePathToken(v.NameKey, fullPath)
	if err != nil {
		return
	}

	options["e2ee_display_name"] = base64.StdEncoding.EncodeToString(sealedName)
	options["e2ee_path_token"] = fmt.Sprintf("%x", pathToken)
}

func (v *VFS) AddPathTokensPublic(options map[string]string, paths []string) {
	v.addPathTokens(options, paths)
}

func (v *VFS) addPathTokens(options map[string]string, paths []string) {
	var expanded []string
	for _, p := range paths {
		expanded = append(expanded, crypto.PathTokenPaths(p, crypto.PathTokenSelfAndAncestors)...)
	}
	crypto.AddPathTokenOptions(options, v.NameKey, expanded)
}

func (v *VFS) AttachChild(parent, child *Node) {
	parent.AddChild(child)
	v.trackNode(child)
}

func (v *VFS) DetachChild(parent *Node, name string) {
	if child := parent.RemoveChild(name); child != nil {
		v.untrackNode(child)
	}
}

func (v *VFS) trackNode(node *Node) {
	if node.ID == 0 {
		return
	}
	v.idMu.Lock()
	v.nodesByID[node.ID] = node
	v.idMu.Unlock()
}

func (v *VFS) untrackNode(node *Node) {
	if node.ID == 0 {
		return
	}
	v.idMu.Lock()
	delete(v.nodesByID, node.ID)
	v.idMu.Unlock()
}

func (v *VFS) NodeByID(id int64) *Node {
	v.idMu.RLock()
	defer v.idMu.RUnlock()
	return v.nodesByID[id]
}

func (v *VFS) removeFromTreeByStatus(status cache.SyncStatus) int {
	count := 0
	var walk func(node *Node)
	walk = func(node *Node) {
		if !node.IsDir {
			return
		}
		node.Mu.Lock()
		for name, child := range node.Children {
			if child.SyncStatus == status {
				delete(node.Children, name)
				v.untrackNode(child)
				count++
			} else if child.IsDir {
				walk(child)
			}
		}
		node.Mu.Unlock()
	}
	walk(v.Root)
	return count
}

func nodeToInode(node *Node, parentID int64) *cache.Inode {
	return &cache.Inode{
		RemotePath:   node.RemotePath,
		DisplayName:  node.Name,
		IsDir:        node.IsDir,
		Size:         node.Size,
		Mtime:        node.Mtime.Unix(),
		Cached:       node.Cached,
		Dirty:        node.Dirty,
		ContentHash:  node.ContentHash,
		SealedKey:    node.SealedKey,
		EncMeta:      node.EncMeta,
		Etag:         node.Etag,
		ParentID:     parentID,
		SyncStatus:   node.SyncStatus,
		StatusReason: node.StatusReason,
	}
}

func joinPath(parent, child string) string {
	if parent == "" {
		return child
	}
	return path.Join(parent, child)
}
