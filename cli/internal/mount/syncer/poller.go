package syncer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"
	"pigcloud/internal/tree"
)

type Poller struct {
	vfs      *vfs.VFS
	client   *api.Client
	cacheDB  *cache.DB
	interval time.Duration

	mu       sync.Mutex
	online   bool
	lastPoll time.Time
	cancel   context.CancelFunc
	done     chan struct{}

	localDelete func(remotePath string)

	cycleTree *tree.Tree

	unusable map[int64]int
}

func (p *Poller) SetLocalDelete(fn func(remotePath string)) {
	p.localDelete = fn
}

func NewPoller(v *vfs.VFS, client *api.Client, cacheDB *cache.DB, interval time.Duration) *Poller {
	return &Poller{
		vfs:      v,
		client:   client,
		cacheDB:  cacheDB,
		interval: interval,
		online:   true,
	}
}

func (p *Poller) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan struct{})

	go func() {
		defer close(p.done)
		p.loop(ctx)
	}()
}

func (p *Poller) Stop() {
	if p.cancel != nil {
		p.cancel()
	}
	awaitLoopExit(p.done, "poller")
}

func (p *Poller) IsOnline() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.online
}

func (p *Poller) LastPoll() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPoll
}

func (p *Poller) loop(ctx context.Context) {
	defer mlog.RecoverPanic("poller")

	p.poll(ctx)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	p.cycleTree = p.loadCycleTree(ctx)
	err := p.pollRecursive(ctx, p.vfs.Root)
	p.cycleTree = nil

	p.mu.Lock()
	if err != nil {
		p.online = false
	} else {
		p.online = true
		p.lastPoll = time.Now()
	}
	p.mu.Unlock()

	p.vfs.Online = p.online
}

func (p *Poller) loadCycleTree(ctx context.Context) *tree.Tree {
	if p.vfs.PrivateKey == nil {
		return nil
	}
	parentKey, err := crypto.DeriveParentKey(p.vfs.PrivateKey)
	if err != nil {
		return nil
	}
	built, err := tree.Load(ctx, p.client, tree.Keys{Priv: p.vfs.PrivateKey, ParentKey: parentKey})
	if err != nil {
		return nil
	}
	return built
}

func (p *Poller) addScope(options map[string]string, remotePath string) {
	if p.cycleTree == nil {
		return
	}
	parentID := ""
	if trimmed := strings.Trim(remotePath, "/"); trimmed != "" {
		node, err := p.cycleTree.Resolve(trimmed)
		if err != nil || node == nil || !node.IsDir {
			return
		}
		parentID = node.ID
	}
	ids := []string{}
	for _, child := range p.cycleTree.Children(parentID) {
		ids = append(ids, child.ID)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return
	}
	options["scope_node_ids"] = string(encoded)
}

func (p *Poller) pollRecursive(ctx context.Context, parent *vfs.Node) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if !parent.Loaded {
		return nil
	}

	source := "/"
	if parent.RemotePath != "" {
		source = "/" + parent.RemotePath
	}

	options := map[string]string{"source": source}
	addPathTokens(options, parent.RemotePath, p.vfs.NameKey)
	p.addScope(options, parent.RemotePath)

	resp, err := p.client.Execute(ctx, "ls", options)
	if err != nil {
		return fmt.Errorf("poll %s: %w", source, err)
	}
	if !resp.Success {
		return fmt.Errorf("poll %s: %s", source, resp.Message)
	}

	var payload api.ListPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return fmt.Errorf("parse poll response: %w", err)
	}

	remoteEntries := make(map[string]*api.ListEntry)
	decryptFailed := false
	unusable := 0
	for i := range payload.Entries {
		entry := &payload.Entries[i]
		name, undecryptable := openPolledName(entry.E2EEDisplayName, p.vfs.PrivateKey)
		if undecryptable {
			decryptFailed = true
			continue
		}
		if name == "" || vfs.IsExcludedDir(name) {
			continue
		}
		if !fsutil.IsSafeName(name) {
			unusable++
			continue
		}
		remoteEntries[name] = entry
	}
	p.reportUnusable(parent.ID, unusable)

	parent.Mu.Lock()
	children := make(map[string]*vfs.Node)
	maps.Copy(children, parent.Children)
	parent.Mu.Unlock()

	for name, entry := range remoteEntries {
		existing := children[name]
		if existing != nil {
			existing.Mu.Lock()
			dbInode, _ := p.cacheDB.GetInode(existing.ID)
			locallyDirty := existing.Dirty || (dbInode != nil && dbInode.Dirty)

			newSize, haveSize := plaintextSizeOf(entry)
			var remoteMtime time.Time
			haveMtime := false
			if entry.Modified != nil {
				if t, err := time.Parse(time.RFC3339, *entry.Modified); err == nil {
					remoteMtime, haveMtime = t, true
				}
			}
			sizeChanged := haveSize && newSize != existing.Size
			mtimeAdvanced := haveMtime && remoteMtime.After(existing.Mtime)
			etagChanged := existing.Etag != entry.ETag
			remoteChanged := sizeChanged || mtimeAdvanced || etagChanged
			if existing.Etag != "" && entry.ETag != "" {
				remoteChanged = etagChanged
			}
			acknowledged := dbInode != nil && dbInode.SyncStatus != cache.StatusConflict &&
				entry.ETag != "" && dbInode.Etag == entry.ETag
			conflict := locallyDirty && remoteChanged && !acknowledged
			if conflict {
				if entry.ETag != "" {
					p.cacheDB.SetRemoteVersion(existing.ID, entry.ETag)
				}
				if dbInode == nil || dbInode.SyncStatus != cache.StatusConflict {
					existing.SyncStatus = cache.StatusConflict
					existing.StatusReason = "remote changed while local edits pending"
					p.cacheDB.SetSyncStatus(existing.ID, cache.StatusConflict, existing.StatusReason)
					mlog.Warnf("poller: conflict on inode %d (remote changed, local edits pending)", existing.ID)
				}
			} else if !locallyDirty && remoteChanged {
				if haveSize {
					existing.Size = newSize
				}
				supersededHash := existing.ContentHash
				existing.Cached = false
				existing.ContentHash = ""
				p.cacheDB.InvalidateCache(existing.ID)
				cache.ReleaseBlob(p.cacheDB, p.vfs.Store, supersededHash, existing.ID)
				p.cacheDB.ClearSyncFailure(existing.ID, cache.FailureDownload)
			}
			if haveMtime && !conflict {
				existing.Mtime = remoteMtime
			}
			if !conflict {
				existing.Etag = entry.ETag
				p.cacheDB.SetRemoteVersion(existing.ID, entry.ETag)
			}
			existing.Mu.Unlock()
		} else {
			if p.cacheDB.RenamePendingFor(entry.ID) {
				continue
			}
			isDir := entry.Type == "directory"
			childPath := vfs.JoinPath(parent.RemotePath, name)
			var node *vfs.Node
			if isDir {
				node = vfs.NewDirNode(name, childPath, parent)
			} else {
				size, _ := plaintextSizeOf(entry)
				mtime := time.Now()
				if entry.Modified != nil {
					if t, err := time.Parse(time.RFC3339, *entry.Modified); err == nil {
						mtime = t
					}
				}
				node = vfs.NewFileNode(name, childPath, size, mtime, parent)
			}

			node.Etag = entry.ETag
			node.NodeID = entry.ID
			inode := &cache.Inode{
				RemotePath:  node.RemotePath,
				DisplayName: name,
				IsDir:       isDir,
				Size:        node.Size,
				Mtime:       node.Mtime.Unix(),
				SyncStatus:  cache.StatusSynced,
				Etag:        entry.ETag,
				ParentID:    parent.ID,
				NodeID:      entry.ID,
			}
			if !isDir {
				if prior, _ := p.cacheDB.GetInodeByPath(childPath); prior != nil {
					adoptPendingLocal(node, inode, prior, entry)
				}
			}
			id, _ := p.cacheDB.UpsertInode(inode)
			node.ID = id
			if inode.SyncStatus == cache.StatusConflict {
				mlog.Warnf("poller: conflict on inode %d (remote file arrived over pending local edits)", id)
			}

			p.vfs.AttachChild(parent, node)

			if isDir {
				if _, err := p.vfs.Readdir(node); err != nil {
					mlog.Warnf("poller: load new folder inode %d failed (%s)", node.ID, mlog.Cause(err))
				}
			}
		}
	}

	if decryptFailed {
		mlog.Warnf("poller: folder inode %d has undecryptable entries; skipping prune this cycle", parent.ID)
	} else {
		for name, child := range children {
			if _, exists := remoteEntries[name]; exists {
				continue
			}
			dbInode, _ := p.cacheDB.GetInode(child.ID)
			if child.Dirty || (dbInode != nil && dbInode.Dirty) {
				p.vfs.ForgetVanished(child)
				if dbInode != nil && dbInode.SyncStatus == cache.StatusConflict {
					p.cacheDB.MarkDirty(child.ID)
					p.cacheDB.SetSyncStatus(child.ID, cache.StatusPending, "")
					p.cacheDB.EnqueueWriteback(child.ID, "upload", child.RemotePath, "")
					child.Mu.Lock()
					child.Dirty, child.SyncStatus, child.StatusReason = true, cache.StatusPending, ""
					child.Mu.Unlock()
				}
				continue
			}
			p.vfs.DetachChild(parent, name)
			if p.localDelete != nil {
				p.localDelete(child.RemotePath)
			}
			cache.ReleaseBlob(p.cacheDB, p.vfs.Store, child.ContentHash, child.ID)
			hashes, err := p.cacheDB.PruneInodeTree(child.RemotePath)
			if err != nil {
				mlog.Warnf("poller: prune rows under inode %d: %s", child.ID, mlog.Cause(err))
			}
			for _, h := range hashes {
				cache.ReleaseBlob(p.cacheDB, p.vfs.Store, h, 0)
			}
		}
	}

	for name := range remoteEntries {
		child := parent.GetChild(name)
		if child != nil && child.IsDir && child.Loaded {
			if err := p.pollRecursive(ctx, child); err != nil {
				return err
			}
		}
	}

	return nil
}

func openPolledName(sealedB64 string, priv *crypto.PrivateKeySet) (string, bool) {
	if sealedB64 == "" {
		return "", false
	}
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return "", true
	}
	name, err := crypto.UnsealDisplayName(sealed, priv)
	if err != nil {
		return "", true
	}
	return name, false
}

func (p *Poller) reportUnusable(folderID int64, count int) {
	p.mu.Lock()
	if p.unusable == nil {
		p.unusable = map[int64]int{}
	}
	changed := p.unusable[folderID] != count
	p.unusable[folderID] = count
	p.mu.Unlock()
	if changed && count > 0 {
		mlog.Warnf("poller: folder inode %d has %d remote name(s) this device cannot store; skipped", folderID, count)
	}
}

func adoptPendingLocal(node *vfs.Node, inode, prior *cache.Inode, entry *api.ListEntry) {
	if !prior.Dirty || (entry.ID != "" && entry.ID == prior.PendingNodeID) {
		return
	}
	status, reason, rowEtag := prior.SyncStatus, prior.StatusReason, prior.Etag
	if prior.Etag == "" || prior.Etag != entry.ETag {
		status, reason, rowEtag = cache.StatusConflict, "remote changed while local edits pending", entry.ETag
	}
	node.Dirty, node.Cached, node.ContentHash = true, prior.Cached, prior.ContentHash
	node.Size, node.Mtime, node.Etag = prior.Size, time.Unix(prior.Mtime, 0), prior.Etag
	node.SyncStatus, node.StatusReason = status, reason
	*inode = cache.Inode{
		RemotePath:   inode.RemotePath,
		DisplayName:  inode.DisplayName,
		Size:         prior.Size,
		Mtime:        prior.Mtime,
		Cached:       prior.Cached,
		Dirty:        true,
		ContentHash:  prior.ContentHash,
		SealedKey:    prior.SealedKey,
		EncMeta:      prior.EncMeta,
		Etag:         rowEtag,
		ParentID:     inode.ParentID,
		SyncStatus:   status,
		StatusReason: reason,
		NodeID:       entry.ID,
	}
}

func addPathTokens(options map[string]string, remotePath string, nameKey []byte) {
	if remotePath == "" || nameKey == nil {
		return
	}
	crypto.AddPathTokenOptions(options, nameKey, crypto.PathTokenPaths(remotePath, crypto.PathTokenSelfAndAncestors))
}

func plaintextSizeOf(entry *api.ListEntry) (int64, bool) {
	if entry.PlaintextSize != nil {
		return *entry.PlaintextSize, true
	}
	return 0, false
}
