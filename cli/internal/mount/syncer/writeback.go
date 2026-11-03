package syncer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"
)

const (
	debounceDelay = 2 * time.Second

	maxRetries = 3

	processBatchSize = 10

	parentWaitDelay = 10 * time.Second

	writebackParallel = 3
)

var errTeeSealStale = errors.New("upload was sealed to a retired scanner key")

var errDeleteSuperseded = errors.New("local file exists again; its upload replaces the queued delete")

var errRenameCollision = errors.New("a remote item already uses the new name")

type WritebackProcessor struct {
	vfs      *vfs.VFS
	client   *api.Client
	cacheDB  *cache.DB
	store    *cache.Store
	syncDir  string
	activity ActivityFunc
	upload   func(context.Context, *cache.WritebackEntry) (uploadedContent, error)

	cancel context.CancelFunc
	done   chan struct{}
}

func (w *WritebackProcessor) SetActivityCallback(fn ActivityFunc) {
	w.activity = fn
}

func NewWritebackProcessor(v *vfs.VFS, client *api.Client, cacheDB *cache.DB, store *cache.Store, syncDir string) *WritebackProcessor {
	return &WritebackProcessor{
		vfs:     v,
		client:  client,
		cacheDB: cacheDB,
		store:   store,
		syncDir: syncDir,
	}
}

func (w *WritebackProcessor) localPath(remotePath string) (string, bool) {
	if w.syncDir == "" || remotePath == "" {
		return "", false
	}
	rel := remotePath
	if base := w.vfs.RemoteBase; base != "" {
		rel = strings.TrimPrefix(remotePath, base+"/")
	}
	p := filepath.Join(w.syncDir, filepath.FromSlash(rel))
	if !safeSyncPath(w.syncDir, p) {
		return "", false
	}
	return p, true
}

func (w *WritebackProcessor) Start() {
	if w.readOnly() {
		mlog.Infof("writeback: read-only mount, processor not started")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		w.loop(ctx)
	}()
}

func (w *WritebackProcessor) Stop() {
	if w.cancel != nil {
		w.cancel()
	}
	awaitLoopExit(w.done, "writeback")
}

func (w *WritebackProcessor) readOnly() bool {
	return w.cacheDB != nil && w.cacheDB.WritebackDisabled()
}

type FlushResult struct {
	Flushed  int
	Deferred int
	NextDue  time.Duration
}

func (w *WritebackProcessor) FlushAll(timeout time.Duration) (FlushResult, error) {
	if w.readOnly() {
		return FlushResult{}, cache.ErrReadOnlyMount
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var res FlushResult
	for {
		entries, err := w.cacheDB.DequeueWriteback(processBatchSize, 0)
		if err != nil {
			return w.withDeferred(res), err
		}
		if len(entries) == 0 {
			break
		}

		var held []*cache.WritebackEntry
		for i, entry := range entries {
			if ctx.Err() != nil {
				w.requeue(entries[i:])
				w.requeue(held)
				return w.withDeferred(res), fmt.Errorf("flush timeout with entries remaining")
			}
			if w.heldByConflict(entry) {
				held = append(held, entry)
				continue
			}
			if w.processEntry(ctx, entry) {
				res.Flushed++
			}
		}
		w.requeue(held)
		if len(held) == len(entries) {
			break
		}
	}
	res = w.withDeferred(res)
	if res.Deferred > 0 {
		mlog.Infof("writeback: flushed %d, %d deferred, next due in %s", res.Flushed, res.Deferred, res.NextDue.Round(time.Second))
	}
	return res, nil
}

func (w *WritebackProcessor) withDeferred(res FlushResult) FlushResult {
	if w.cacheDB == nil {
		return res
	}
	horizon := time.Now().Unix() + 1
	count, next, err := w.cacheDB.DeferredWritebackCount(horizon)
	if err != nil {
		return res
	}
	res.Deferred = count
	if next > horizon {
		res.NextDue = time.Duration(next-horizon) * time.Second
	}
	return res
}

func (w *WritebackProcessor) heldByConflict(entry *cache.WritebackEntry) bool {
	if entry.Action != "upload" {
		return false
	}
	inode, err := w.cacheDB.GetInode(entry.InodeID)
	return err == nil && inode != nil && inode.SyncStatus == cache.StatusConflict
}

func (w *WritebackProcessor) requeue(entries []*cache.WritebackEntry) {
	for _, e := range entries {
		w.cacheDB.UpdateWriteback(e.ID, "pending", e.LastError, e.Attempts)
	}
}

func (w *WritebackProcessor) loop(ctx context.Context) {
	defer mlog.RecoverPanic("writeback")

	ticker := time.NewTicker(debounceDelay)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.processBatch(ctx)
		}
	}
}

func (w *WritebackProcessor) processBatch(ctx context.Context) {
	claimBefore := time.Now().Add(-debounceDelay).Unix()
	entries, err := w.cacheDB.DequeueWriteback(processBatchSize, claimBefore)
	if err != nil || len(entries) == 0 {
		return
	}

	var mu sync.Mutex
	var held []*cache.WritebackEntry
	var wg sync.WaitGroup
	sem := make(chan struct{}, writebackParallel)
	for _, group := range groupWriteback(entries) {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			w.requeue(group)
			continue
		}
		wg.Go(func() {
			defer func() { <-sem }()
			for i, entry := range group {
				if ctx.Err() != nil {
					w.requeue(group[i:])
					return
				}
				if w.heldByConflict(entry) {
					mu.Lock()
					held = append(held, entry)
					mu.Unlock()
					continue
				}
				w.processEntry(ctx, entry)
			}
		})
	}
	wg.Wait()
	w.requeue(held)
}

func (w *WritebackProcessor) processEntry(ctx context.Context, entry *cache.WritebackEntry) bool {
	var preNode *vfs.Node
	var preGen uint64
	if entry.Action == "upload" {
		if n := w.vfs.NodeByID(entry.InodeID); n != nil {
			n.Mu.RLock()
			preNode = n
			preGen = n.WriteGen
			n.Mu.RUnlock()
		}
	}

	var uploadBytes int64
	if entry.Action == "upload" {
		if inode, gerr := w.cacheDB.GetInode(entry.InodeID); gerr == nil && inode != nil {
			uploadBytes = inode.Size
		}
	}

	var err error
	var uploaded uploadedContent
	switch entry.Action {
	case "upload":
		upload := w.upload
		if upload == nil {
			upload = w.processUpload
		}
		uploaded, err = upload(ctx, entry)
		if errors.Is(err, errTeeSealStale) {
			mlog.Warnf("writeback: the scanner's sealing key changed, sealing inode %d again", entry.InodeID)
			uploaded, err = upload(ctx, entry)
		}
	case "mkdir":
		err = w.processMkdir(ctx, entry)
	case "delete":
		err = w.processDelete(ctx, entry)
	case "rename":
		err = w.processRename(ctx, entry)
	default:
		err = fmt.Errorf("unknown action: %s", entry.Action)
	}

	if errors.Is(err, errDeleteSuperseded) {
		w.cacheDB.DeleteWriteback(entry.ID)
		return true
	}
	if errors.Is(err, vfs.ErrParentPending) {
		w.cacheDB.DeferWriteback(entry.ID, err.Error(), entry.Attempts, time.Now().Add(parentWaitDelay).Unix())
		return false
	}
	if err != nil {
		attempts := entry.Attempts + 1
		if entry.Action == "upload" {
			if prev, _ := w.cacheDB.GetSyncFailure(entry.InodeID, cache.FailureUpload); prev != nil && prev.Attempts >= attempts {
				attempts = prev.Attempts + 1
			}
		}
		if (attempts >= maxRetries || isPermanent(err)) && entry.Action == "rename" {
			w.abandonRename(entry, err)
			return false
		}
		if attempts >= maxRetries || isPermanent(err) {
			w.cacheDB.UpdateWriteback(entry.ID, "failed", err.Error(), attempts)
			w.cacheDB.SetSyncStatus(entry.InodeID, cache.StatusFailed, err.Error())
			if entry.Action == "upload" {
				f := &cache.SyncFailure{
					InodeID:   entry.InodeID,
					Kind:      cache.FailureUpload,
					Permanent: isPermanent(err),
					Attempts:  attempts,
					LastError: err.Error(),
				}
				if !f.Permanent {
					f.NextRetryAt = time.Now().Add(writebackRetryDelay(err, attempts)).Unix()
				}
				w.cacheDB.RecordSyncFailure(f)
			}
			if node := w.vfs.NodeByID(entry.InodeID); node != nil {
				node.Mu.Lock()
				node.SyncStatus = cache.StatusFailed
				node.StatusReason = err.Error()
				node.Mu.Unlock()
			}
			w.emitUpload(entry, uploadBytes, err)
		} else {
			delay := writebackRetryDelay(err, attempts)
			if api.IsRateLimited(err) {
				mlog.Warnf("writeback: rate limited on inode %d, next attempt in %v (attempt %d)", entry.InodeID, delay, attempts)
			}
			w.cacheDB.SetSyncStatus(entry.InodeID, cache.StatusPending, err.Error())
			w.cacheDB.DeferWriteback(entry.ID, err.Error(), attempts, time.Now().Add(delay).Unix())
		}
		return false
	}

	w.cacheDB.DeleteWriteback(entry.ID)
	if entry.Action == "upload" {
		w.cacheDB.ClearSyncFailure(entry.InodeID, cache.FailureUpload)
		if uploaded.nodeID != "" {
			w.cacheDB.SetInodeNodeID(entry.InodeID, uploaded.nodeID)
			if preNode != nil {
				preNode.Mu.Lock()
				preNode.NodeID = uploaded.nodeID
				preNode.Mu.Unlock()
			}
		}
		w.recordUploaded(entry, uploaded.digest, uploaded.etag)
	}
	if entry.Action == "delete" {
		w.finishDelete(entry)
		return true
	}
	if entry.Action == "rename" {
		w.cacheDB.SetSyncStatus(entry.InodeID, cache.StatusSynced, "")
		return true
	}
	w.emitUpload(entry, uploadBytes, nil)
	localChanged, localMissing := false, false
	if entry.Action == "upload" && w.syncDir != "" {
		localPath, safe := w.localPath(entry.RemotePath)
		if !safe {
			localChanged = true
		} else {
			digest, readErr := hashLocalFile(localPath)
			localChanged = readErr != nil || digest != uploaded.digest
			localMissing = os.IsNotExist(readErr)
		}
	}

	if preNode != nil {
		preNode.Mu.Lock()
		preNode.Etag = uploaded.etag
		if preNode.WriteGen != preGen || localChanged {
			rp := preNode.RemotePath
			preNode.Dirty = true
			preNode.SyncStatus = cache.StatusPending
			preNode.StatusReason = ""
			preNode.Mu.Unlock()
			w.cacheDB.MarkDirty(entry.InodeID)
			nextAction := "upload"
			if localMissing {
				nextAction = "delete"
			}
			if err := w.cacheDB.EnqueueWriteback(entry.InodeID, nextAction, rp, ""); err != nil {
				mlog.Errorf("writeback re-enqueue failed (inode %d): %s", entry.InodeID, mlog.Cause(err))
				w.cacheDB.SetSyncStatus(entry.InodeID, cache.StatusPending, "re-enqueue failed")
				preNode.Mu.Lock()
				preNode.Dirty = true
				preNode.SyncStatus = cache.StatusPending
				preNode.StatusReason = "re-enqueue failed"
				preNode.Mu.Unlock()
			}
			return true
		}
		preNode.Dirty = false
		preNode.SyncStatus = cache.StatusSynced
		preNode.StatusReason = ""
		preNode.Data = nil
		preNode.Mu.Unlock()
	}

	if localChanged {
		w.cacheDB.MarkDirty(entry.InodeID)
		nextAction := "upload"
		if localMissing {
			nextAction = "delete"
		}
		if err := w.cacheDB.EnqueueWriteback(entry.InodeID, nextAction, entry.RemotePath, ""); err != nil {
			w.cacheDB.SetSyncStatus(entry.InodeID, cache.StatusPending, "re-enqueue failed")
		}
		return true
	}
	w.cacheDB.MarkSynced(entry.InodeID, uploaded.etag)
	return true
}

func (w *WritebackProcessor) recordUploaded(entry *cache.WritebackEntry, digest string, confirmedEtag ...string) {
	if digest == "" {
		return
	}
	var mtime int64
	if lp, ok := w.localPath(entry.RemotePath); ok {
		if fi, err := os.Stat(lp); err == nil {
			mtime = fi.ModTime().Unix()
			w.cacheDB.SetLocalFileID(entry.InodeID, recordedSignature(fi, time.Now()))
		}
	}
	if len(confirmedEtag) > 0 {
		w.cacheDB.SetRemoteVersion(entry.InodeID, confirmedEtag[0])
		w.cacheDB.SetLocalContentForVersion(entry.InodeID, digest, mtime, confirmedEtag[0])
	} else {
		w.cacheDB.SetLocalContent(entry.InodeID, digest, mtime)
	}
}

func (w *WritebackProcessor) emitUpload(entry *cache.WritebackEntry, bytes int64, err error) {
	if w.activity == nil || entry.Action != "upload" {
		return
	}
	w.activity(entry.RemotePath, "upload", bytes, err)
}

func writeTempPlaintext(data []byte) (string, func(), error) {
	tmp, err := os.CreateTemp("", "pigcloud-mount-ul-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	cleanup := func() { os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close temp file: %w", err)
	}
	return name, cleanup, nil
}

func (w *WritebackProcessor) streamStoreToTemp(hash string) (string, func(), error) {
	tmp, err := os.CreateTemp("", "pigcloud-mount-ul-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp file: %w", err)
	}
	name := tmp.Name()
	cleanup := func() { os.Remove(name) }
	if _, err := w.store.WriteTo(hash, tmp); err != nil {
		tmp.Close()
		cleanup()
		return "", nil, err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("close temp file: %w", err)
	}
	return name, cleanup, nil
}

func (w *WritebackProcessor) processUpload(ctx context.Context, entry *cache.WritebackEntry) (uploadedContent, error) {
	if w.syncDir != "" {
		if _, safe := w.localPath(entry.RemotePath); !safe {
			return uploadedContent{}, permanent(fmt.Errorf("upload path leaves the selected sync folder through a link"))
		}
	}
	var name, remotePath, contentHash string
	var virtualBuf []byte

	node := w.vfs.NodeByID(entry.InodeID)
	if node != nil {
		node.Mu.RLock()
		name = node.Name
		remotePath = node.RemotePath
		if w.syncDir == "" {
			if node.Data != nil {
				virtualBuf = node.Data
			} else if node.Cached && node.ContentHash != "" {
				contentHash = node.ContentHash
			}
		}
		node.Mu.RUnlock()
	}

	if virtualBuf == nil && contentHash == "" {
		inode, err := w.cacheDB.GetInode(entry.InodeID)
		if err != nil || inode == nil {
			return uploadedContent{}, fmt.Errorf("inode %d not found", entry.InodeID)
		}
		if name == "" {
			name = inode.DisplayName
		}
		if remotePath == "" {
			remotePath = inode.RemotePath
		}
		contentHash = inode.ContentHash
	}

	var plainPath string
	livePlaintext := false
	var cleanup func()
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	if virtualBuf != nil {
		p, cl, err := writeTempPlaintext(virtualBuf)
		if err != nil {
			return uploadedContent{}, err
		}
		plainPath, cleanup = p, cl
	}

	if plainPath == "" && contentHash != "" {
		p, cl, err := w.streamStoreToTemp(contentHash)
		if err != nil {
			if w.syncDir == "" {
				return uploadedContent{}, fmt.Errorf("read cache: %w", err)
			}
		} else {
			plainPath, cleanup = p, cl
		}
	}

	if plainPath == "" {
		if lp, ok := w.localPath(remotePath); ok {
			if _, err := os.Stat(lp); err == nil {
				plainPath = lp
				livePlaintext = true
			}
		}
	}

	if plainPath == "" {
		return uploadedContent{}, fmt.Errorf("no content to upload")
	}

	ident, err := w.resolveIdentity(ctx, entry, remotePath, false)
	if err != nil {
		return uploadedContent{}, err
	}

	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		return uploadedContent{}, fmt.Errorf("generate data key: %w", err)
	}

	tmpEncFile, err := os.CreateTemp("", "pigcloud-mount-enc-*")
	if err != nil {
		return uploadedContent{}, fmt.Errorf("create encrypted temp file: %w", err)
	}
	tmpEncPath := tmpEncFile.Name()
	tmpEncFile.Close()
	defer os.Remove(tmpEncPath)

	if livePlaintext && !safeSyncPath(w.syncDir, plainPath) {
		return uploadedContent{}, permanent(fmt.Errorf("upload path changed before encryption"))
	}
	encMeta, err := crypto.EncryptFile(plainPath, tmpEncPath, dataKey)
	if err != nil {
		return uploadedContent{}, fmt.Errorf("encrypt: %w", err)
	}

	sealedKey, err := crypto.SealDataKey(dataKey, w.vfs.PublicKey)
	if err != nil {
		return uploadedContent{}, fmt.Errorf("seal data key: %w", err)
	}

	metaJSON, err := encMeta.WireJSON()
	if err != nil {
		return uploadedContent{}, fmt.Errorf("marshal encryption meta: %w", err)
	}

	signPub := w.vfs.SigningPublicKey
	signPriv := w.vfs.SigningPrivateKey
	if signPub == nil || signPriv == nil {
		return uploadedContent{}, fmt.Errorf("signing keys unavailable; unlock with 'pc uk' and restart the mount")
	}
	encFile, err := os.Open(tmpEncPath)
	if err != nil {
		return uploadedContent{}, fmt.Errorf("open encrypted file for signing: %w", err)
	}
	sigEd, sigMldsa, signErr := crypto.SignFileBytes(encFile, signPriv)
	encFile.Close()
	if signErr != nil {
		return uploadedContent{}, fmt.Errorf("sign upload: %w", signErr)
	}

	if ident, err = w.sealIdentity(ident); err != nil {
		return uploadedContent{}, err
	}

	e2eeOpts := map[string]string{
		"sealed_key":         base64.StdEncoding.EncodeToString(sealedKey),
		"encryption_meta":    base64.StdEncoding.EncodeToString(metaJSON),
		"_original_name":     name,
		"signature_ed25519":  base64.StdEncoding.EncodeToString(sigEd),
		"signature_mldsa":    base64.StdEncoding.EncodeToString(sigMldsa),
		"signing_pk_ed25519": base64.StdEncoding.EncodeToString(signPub.Ed25519[:]),
		"signing_pk_mldsa":   base64.StdEncoding.EncodeToString(signPub.Mldsa),
	}

	teeKeys := e2ee.FetchTeeEnclaveKeySet(ctx)
	if teeKeys == nil && !e2ee.TeeScannerDisabledByServer() {
		if refusal := e2ee.TeeEnclaveKeyRefusal(); refusal != nil {
			return uploadedContent{}, fmt.Errorf("scanner key refused: %w", refusal)
		}
		return uploadedContent{}, fmt.Errorf("scanner key unavailable; scanner cannot decrypt the upload")
	}
	if teeKeys != nil {
		teeSealed, err := crypto.SealDataKey(dataKey, teeKeys)
		if err != nil {
			return uploadedContent{}, fmt.Errorf("seal data key to the scanner: %w", err)
		}
		e2eeOpts["tee_sealed_key"] = base64.StdEncoding.EncodeToString(teeSealed)
	}
	if w.vfs.NameKey != nil {
		if h, err := crypto.ComputePlaintextHmac(encMeta.PlaintextSHA256, w.vfs.NameKey); err == nil {
			e2eeOpts["plaintext_hmac"] = h
		}
	}

	sealedName, err := crypto.SealDisplayName(name, w.vfs.PublicKey)
	if err == nil {
		e2eeOpts["e2ee_display_name"] = base64.StdEncoding.EncodeToString(sealedName)
	}
	pathToken, err := crypto.ComputePathToken(w.vfs.NameKey, remotePath)
	if err == nil {
		e2eeOpts["e2ee_path_token"] = fmt.Sprintf("%x", pathToken)
	}

	addPathTokens(e2eeOpts, remotePath, w.vfs.NameKey)
	e2eeOpts["e2ee_node_id"] = ident.nodeID
	e2eeOpts["e2ee_sealed_parent"] = ident.sealed

	identity, err := uploadIdentityKey(w.vfs.NameKey, cache.UploadKeyFromExtra(entry.ExtraJSON), remotePath, encMeta.PlaintextSHA256)
	if err != nil {
		return uploadedContent{}, permanent(err)
	}
	e2eeOpts["upload_idempotency_key"] = identity

	uploadDir := "/"
	if idx := strings.LastIndex(remotePath, "/"); idx >= 0 {
		uploadDir = "/" + remotePath[:idx]
	}
	resp, err := w.sendCreate(ctx, entry, remotePath, e2eeOpts, func(opts map[string]string) (*api.Response, error) {
		return w.client.Upload(ctx, tmpEncPath, uploadDir, nil, maps.Clone(opts))
	})
	if err != nil {
		if isPermanent(err) {
			return uploadedContent{}, err
		}
		if teeKeys != nil {
			stale, refusal := e2ee.TeeSealWentStale(ctx, err, teeKeys)
			if refusal != nil {
				return uploadedContent{}, fmt.Errorf("scanner key refused: %w", refusal)
			}
			if stale {
				return uploadedContent{}, fmt.Errorf("%w: %w", errTeeSealStale, classifyUploadError(err))
			}
		}
		return uploadedContent{}, classifyUploadError(err)
	}
	if resp == nil || !resp.Success {
		msg := "unknown error"
		if resp != nil && resp.Message != "" {
			msg = resp.Message
		}
		return uploadedContent{}, fmt.Errorf("upload rejected: %s", msg)
	}

	return confirmedUploadContent(resp, encMeta.PlaintextSHA256), nil
}

func classifyUploadError(err error) error {
	if api.IsPermanent(err) {
		return permanent(fmt.Errorf("upload: %w", err))
	}
	return fmt.Errorf("upload: %w", err)
}

func (w *WritebackProcessor) processMkdir(ctx context.Context, entry *cache.WritebackEntry) error {
	if active, err := w.cacheDB.HasActiveWriteback(entry.InodeID, "delete"); err != nil || active {
		return vfs.ErrParentPending
	}
	options := map[string]string{
		"source": "/" + entry.RemotePath,
	}
	addPathTokens(options, entry.RemotePath, w.vfs.NameKey)

	name := entry.RemotePath
	if idx := strings.LastIndex(entry.RemotePath, "/"); idx >= 0 {
		name = entry.RemotePath[idx+1:]
	}
	if sealedName, err := crypto.SealDisplayName(name, w.vfs.PublicKey); err == nil {
		options["e2ee_display_name"] = base64.StdEncoding.EncodeToString(sealedName)
	}
	if token, err := crypto.ComputePathToken(w.vfs.NameKey, entry.RemotePath); err == nil {
		options["e2ee_path_token"] = fmt.Sprintf("%x", token)
	}
	ident, err := w.createIdentity(ctx, entry, entry.RemotePath, false)
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	options["e2ee_node_id"] = ident.nodeID
	options["e2ee_sealed_parent"] = ident.sealed

	resp, err := w.sendCreate(ctx, entry, entry.RemotePath, options, func(opts map[string]string) (*api.Response, error) {
		return w.client.Execute(ctx, "mk", opts)
	})
	if err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if !resp.Success && resp.ErrorCode == "path_exists" {
		if _, err := w.vfs.LookupNodeID(ctx, entry.RemotePath); err != nil {
			return fmt.Errorf("mkdir: folder exists but its id did not resolve: %w", err)
		}
		return nil
	}
	if !resp.Success {
		return fmt.Errorf("mkdir: %s", resp.Message)
	}
	w.cacheDB.SetInodeNodeID(entry.InodeID, options["e2ee_node_id"])
	return nil
}

type nodeIdentity struct {
	nodeID, parentID, sealed string
}

func (w *WritebackProcessor) resolveIdentity(ctx context.Context, entry *cache.WritebackEntry, remotePath string, remint bool) (nodeIdentity, error) {
	x := cache.ParseWritebackExtra(entry.ExtraJSON)
	nodeID := x.NodeID
	if remint {
		nodeID, x = "", cache.WritebackExtra{}
	} else if nodeID == "" {
		if inode, err := w.cacheDB.GetInode(entry.InodeID); err == nil && inode != nil {
			nodeID = inode.NodeID
			if nodeID == "" {
				nodeID = inode.PendingNodeID
			}
		}
	}
	if nodeID == "" {
		var err error
		if nodeID, err = cache.MintNodeID(); err != nil {
			return nodeIdentity{}, err
		}
		w.cacheDB.SetPendingNodeID(entry.InodeID, nodeID)
	}
	parentID, err := w.vfs.ResolveNodeID(ctx, cache.RemoteParentPath(remotePath))
	if errors.Is(err, vfs.ErrParentPending) || isPermanent(err) {
		return nodeIdentity{}, err
	}
	if err != nil {
		return nodeIdentity{}, fmt.Errorf("parent folder id unresolved, will retry: %w", err)
	}
	ident := nodeIdentity{nodeID: nodeID, parentID: parentID}
	if x.SealedParent != "" && x.NodeID == nodeID && x.ParentID == parentID {
		ident.sealed = x.SealedParent
	}
	return ident, nil
}

func (w *WritebackProcessor) sealIdentity(ident nodeIdentity) (nodeIdentity, error) {
	if ident.sealed != "" {
		return ident, nil
	}
	sealed, err := w.vfs.SealParentRef(ident.nodeID, ident.parentID)
	if err != nil {
		return nodeIdentity{}, err
	}
	ident.sealed = sealed
	return ident, nil
}

func (w *WritebackProcessor) createIdentity(ctx context.Context, entry *cache.WritebackEntry, remotePath string, remint bool) (nodeIdentity, error) {
	ident, err := w.resolveIdentity(ctx, entry, remotePath, remint)
	if err != nil {
		return nodeIdentity{}, err
	}
	return w.sealIdentity(ident)
}

func (w *WritebackProcessor) sendCreate(ctx context.Context, entry *cache.WritebackEntry, remotePath string, options map[string]string, send func(map[string]string) (*api.Response, error)) (*api.Response, error) {
	resp, err := e2ee.SendCreate(func() (*api.Response, error) { return send(options) }, func() error {
		ident, err := w.createIdentity(ctx, entry, remotePath, true)
		if err != nil {
			return err
		}
		options["e2ee_node_id"], options["e2ee_sealed_parent"] = ident.nodeID, ident.sealed
		x := cache.ParseWritebackExtra(entry.ExtraJSON)
		x.NodeID, x.ParentID, x.SealedParent = ident.nodeID, ident.parentID, ident.sealed
		entry.ExtraJSON = x.Marshal()
		return w.cacheDB.SetWritebackExtra(entry.ID, entry.ExtraJSON)
	})
	if api.HasErrorCode(resp, err, e2ee.CodeNodeIDTaken) {
		msg := "the server refused the item's id twice"
		if resp != nil && resp.Message != "" {
			msg = resp.Message
		} else if err != nil {
			msg = err.Error()
		}
		return resp, permanent(errors.New(msg))
	}
	return resp, err
}

func (w *WritebackProcessor) processDelete(ctx context.Context, entry *cache.WritebackEntry) error {
	if inode, changed := w.localFileBack(entry); inode != nil {
		if !changed {
			return errDeleteSuperseded
		}
		if inode.SyncStatus != cache.StatusConflict {
			w.cacheDB.MarkDirty(inode.ID)
		}
		if err := w.cacheDB.EnqueueWriteback(inode.ID, "upload", entry.RemotePath, ""); err != nil {
			return err
		}
		return errDeleteSuperseded
	}
	options := map[string]string{
		"source": "/" + entry.RemotePath,
	}
	addPathTokens(options, entry.RemotePath, w.vfs.NameKey)

	resp, err := w.client.Execute(ctx, "rm", options)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete: %s", resp.Message)
	}
	w.cacheDB.ClearNodeIDs(entry.InodeID, true)
	return nil
}

func (w *WritebackProcessor) finishDelete(entry *cache.WritebackEntry) {
	if active, _ := w.cacheDB.HasActiveWriteback(entry.InodeID, "upload"); active {
		w.cacheDB.MarkDirty(entry.InodeID)
		return
	}
	if active, _ := w.cacheDB.HasActiveWriteback(entry.InodeID, "mkdir"); active {
		w.cacheDB.SetSyncStatus(entry.InodeID, cache.StatusPending, "")
		return
	}
	w.cacheDB.MarkSynced(entry.InodeID, "")
	hashes, err := w.cacheDB.PruneInodeTree(entry.RemotePath)
	if err != nil {
		mlog.Warnf("writeback: drop rows after deleting inode %d: %s", entry.InodeID, mlog.Cause(err))
	}
	for _, h := range hashes {
		cache.ReleaseBlob(w.cacheDB, w.store, h, 0)
	}
	if w.vfs == nil {
		return
	}
	if node := w.vfs.NodeByID(entry.InodeID); node != nil && node.Parent != nil {
		w.vfs.DetachChild(node.Parent, node.Name)
	}
}

func (w *WritebackProcessor) localFileBack(entry *cache.WritebackEntry) (*cache.Inode, bool) {
	lp, ok := w.localPath(entry.RemotePath)
	if !ok {
		return nil, false
	}
	inode, err := w.cacheDB.GetInode(entry.InodeID)
	if err != nil || inode == nil || inode.IsDir {
		return nil, false
	}
	if fi, err := os.Lstat(lp); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	dir, err := os.Open(filepath.Dir(lp))
	if err != nil {
		return nil, false
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, false
	}
	if !slices.Contains(names, filepath.Base(lp)) {
		return nil, false
	}
	if inode.Dirty {
		return inode, true
	}
	_, baseline, _, err := w.cacheDB.LocalContentState(inode.ID)
	if err != nil || baseline == "" {
		return inode, true
	}
	sum, err := hashLocalFile(lp)
	return inode, err != nil || sum != baseline
}

func (w *WritebackProcessor) processRename(ctx context.Context, entry *cache.WritebackEntry) error {
	var extra struct {
		Target string `json:"target"`
	}
	if entry.ExtraJSON != "" {
		json.Unmarshal([]byte(entry.ExtraJSON), &extra)
	}
	if extra.Target == "" {
		return fmt.Errorf("rename: missing target")
	}

	options := map[string]string{
		"source": "/" + entry.RemotePath,
		"target": "/" + extra.Target,
	}
	addPathTokens(options, entry.RemotePath, w.vfs.NameKey)
	addPathTokens(options, extra.Target, w.vfs.NameKey)

	var movedID string
	if inode, err := w.cacheDB.GetInode(entry.InodeID); err == nil && inode != nil {
		movedID = inode.NodeID
	}
	if movedID == "" {
		var err error
		if movedID, err = w.vfs.LookupNodeID(ctx, entry.RemotePath); err != nil {
			return fmt.Errorf("rename: moved item id unresolved, will retry: %w", err)
		}
	}
	destID, err := w.vfs.ResolveNodeID(ctx, cache.RemoteParentPath(extra.Target))
	if err != nil {
		return fmt.Errorf("rename: destination folder id unresolved, will retry: %w", err)
	}
	sealed, err := w.vfs.SealParentRef(movedID, destID)
	if err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	options["e2ee_sealed_parent"] = sealed

	resp, err := w.client.Execute(ctx, "mv", options)
	if api.HasErrorCode(resp, err, "path_exists") {
		return permanent(errRenameCollision)
	}
	if err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("rename: %s", resp.Message)
	}
	return nil
}

func (w *WritebackProcessor) abandonRename(entry *cache.WritebackEntry, err error) {
	w.cacheDB.DeleteWriteback(entry.ID)
	inode, gerr := w.cacheDB.GetInode(entry.InodeID)
	if gerr != nil || inode == nil {
		return
	}
	requeueTree(w.cacheDB, inode.RemotePath, w.localPath)
	if errors.Is(err, errRenameCollision) && !inode.IsDir {
		w.cacheDB.MarkLocalConflict(inode.ID, errRenameCollision.Error())
	}
	mlog.Warnf("writeback: move of inode %d failed (%s); re-creating it under the new name", inode.ID, mlog.Cause(err))
}
