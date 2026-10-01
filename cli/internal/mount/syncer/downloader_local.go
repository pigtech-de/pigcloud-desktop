package syncer

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

var errDownloadLocalChanged = errors.New("local content needs conflict resolution before downloading")
var errDownloadRemoteChanged = errors.New("remote version changed while downloading; retry with the current version")

type localDownloadState struct {
	info os.FileInfo
	hash string
}

func readLocalDownloadState(path string) (localDownloadState, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return localDownloadState{}, nil
	}
	if err != nil {
		return localDownloadState{}, err
	}
	if !info.Mode().IsRegular() {
		return localDownloadState{}, fmt.Errorf("local target is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return localDownloadState{}, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return localDownloadState{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return localDownloadState{}, err
	}
	return localDownloadState{info: info, hash: fmt.Sprintf("%x", hash.Sum(nil))}, nil
}

func sameLocalDownloadState(before, after localDownloadState) bool {
	if before.info == nil || after.info == nil {
		return before.info == nil && after.info == nil
	}
	return os.SameFile(before.info, after.info) && before.hash == after.hash &&
		before.info.ModTime().Equal(after.info.ModTime()) && before.info.Size() == after.info.Size()
}

func (d *Downloader) markLocalConflict(node *vfs.Node, reason string) error {
	if err := d.cacheDB.MarkLocalConflict(node.ID, reason); err != nil {
		return err
	}
	node.Mu.Lock()
	node.Dirty = true
	node.Cached = false
	node.SyncStatus = cache.StatusConflict
	node.StatusReason = reason
	node.Mu.Unlock()
	d.cacheDB.ClearSyncFailure(node.ID, cache.FailureDownload)
	return errDownloadLocalChanged
}

func (d *Downloader) localBaseline(nodeID int64) string {
	if d.cacheDB == nil {
		return ""
	}
	_, baseline, _, err := d.cacheDB.LocalContentState(nodeID)
	if err != nil {
		return ""
	}
	return baseline
}

func (d *Downloader) protectLocalCollision(node *vfs.Node, localPath string, info os.FileInfo) bool {
	if d.inodeDirty(node.ID) {
		return true
	}
	baseline := d.localBaseline(node.ID)
	if baseline == "" {
		d.markLocalConflict(node, "local and remote files share a name without a synchronized content baseline")
		return true
	}
	hash, err := hashLocalFile(localPath)
	if err != nil {
		d.markLocalConflict(node, "local file could not be verified before downloading")
		return true
	}
	if hash != baseline {
		node.Mu.RLock()
		remoteEtag := node.Etag
		node.Mu.RUnlock()
		_, _, synchronizedEtag, stateErr := d.cacheDB.LocalContentState(node.ID)
		if stateErr == nil && remoteEtag != "" && synchronizedEtag == remoteEtag {
			d.enqueueLocalUpload(node, localPath, info)
		} else {
			d.markLocalConflict(node, "local and remote content both differ from the synchronized baseline")
		}
		return true
	}
	return false
}

func (d *Downloader) validateDownloadPublication(node *vfs.Node, localPath string, before localDownloadState, remoteEtag string) error {
	node.Mu.RLock()
	changed := node.Etag != remoteEtag
	node.Mu.RUnlock()
	if changed {
		return errDownloadRemoteChanged
	}
	if checked, safe := d.localPathWithin(node.RemotePath); !safe || checked != localPath {
		return d.markLocalConflict(node, "local folder changed while remote content was downloading")
	}
	after, err := readLocalDownloadState(localPath)
	if err != nil || !sameLocalDownloadState(before, after) || d.inodeDirty(node.ID) {
		return d.markLocalConflict(node, "local file changed while remote content was downloading")
	}
	return nil
}
