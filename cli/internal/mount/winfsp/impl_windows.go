//go:build windows && cgo

package winfsp

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"

	cgofuse "github.com/winfsp/cgofuse/fuse"
)

func mapErr(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, vfs.ErrNotFound):
		return -cgofuse.ENOENT
	case errors.Is(err, vfs.ErrNotEmpty):
		return -cgofuse.ENOTEMPTY
	case errors.Is(err, vfs.ErrExists):
		return -cgofuse.EEXIST
	case errors.Is(err, vfs.ErrIsDir):
		return -cgofuse.EISDIR
	case errors.Is(err, vfs.ErrReadOnly):
		return -cgofuse.EROFS
	case errors.Is(err, vfs.ErrInvalidName):
		return -cgofuse.EINVAL
	default:
		return -cgofuse.EIO
	}
}

func safeCall(name string, fn func() int) int {
	defer func() {
		if r := recover(); r != nil {
			mlog.LogPanic("winfsp "+name, r)
		}
	}()
	return fn()
}

type Backend struct {
	host *cgofuse.FileSystemHost
	vfs  *vfs.VFS
	fs   *pigFS
}

func New() *Backend {
	return &Backend{}
}

func (b *Backend) Mount(mountpoint string, v *vfs.VFS) error {
	b.vfs = v
	b.fs = &pigFS{vfs: v, handles: make(map[uint64]*handleEntry)}
	b.host = cgofuse.NewFileSystemHost(b.fs)
	b.host.SetCapReaddirPlus(true)

	opts := []string{
		"-o", "volname=PigCloud",
		"-o", "FileSystemName=PigCloud",
		"-o", "uid=-1,gid=-1",
	}

	ok := b.host.Mount(mountpoint, opts)
	if !ok {
		return fmt.Errorf("WinFsp mount failed (is WinFsp installed?)")
	}
	return nil
}

func (b *Backend) Unmount() error {
	if b.host != nil {
		b.host.Unmount()
	}
	return nil
}

type handleEntry struct {
	node *vfs.Node
}

type pigFS struct {
	cgofuse.FileSystemBase
	vfs *vfs.VFS

	mu      sync.Mutex
	handles map[uint64]*handleEntry
	nextFH  uint64
}

func (fs *pigFS) allocHandle(node *vfs.Node) uint64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.nextFH++
	fh := fs.nextFH
	fs.handles[fh] = &handleEntry{node: node}
	return fh
}

func (fs *pigFS) getHandle(fh uint64) *handleEntry {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.handles[fh]
}

func (fs *pigFS) freeHandle(fh uint64) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	delete(fs.handles, fh)
}

func (fs *pigFS) resolvePath(path string) (*vfs.Node, error) {
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return fs.vfs.Root, nil
	}

	parts := strings.Split(path, "/")
	current := fs.vfs.Root
	for _, part := range parts {
		child, err := fs.vfs.Lookup(current, part)
		if err != nil {
			return nil, err
		}
		current = child
	}
	return current, nil
}

func (fs *pigFS) resolveParentAndName(path string) (*vfs.Node, string, error) {
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	name := parts[len(parts)-1]
	parentPath := strings.Join(parts[:len(parts)-1], "/")

	parent := fs.vfs.Root
	if parentPath != "" {
		var err error
		parent, err = fs.resolvePath("/" + parentPath)
		if err != nil {
			return nil, "", err
		}
	}
	return parent, name, nil
}

func (fs *pigFS) Getattr(path string, stat *cgofuse.Stat_t, fh uint64) int {
	return safeCall("Getattr", func() int {
		node, err := fs.resolvePath(path)
		if err != nil {
			return -cgofuse.ENOENT
		}
		fillStat(node, stat)
		return 0
	})
}

func (fs *pigFS) Readdir(path string, fill func(name string, stat *cgofuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	node, err := fs.resolvePath(path)
	if err != nil {
		return -cgofuse.ENOENT
	}

	fill(".", nil, 0)
	fill("..", nil, 0)

	children, err := fs.vfs.Readdir(node)
	if err != nil {
		return -cgofuse.EIO
	}

	for _, child := range children {
		var st cgofuse.Stat_t
		fillStat(child, &st)
		if !fill(child.Name, &st, 0) {
			break
		}
	}
	return 0
}

func (fs *pigFS) Open(path string, flags int) (errc int, fh uint64) {
	defer func() {
		if r := recover(); r != nil {
			mlog.LogPanic("winfsp Open("+path+")", r)
			errc = -cgofuse.EIO
			fh = 0
		}
	}()
	node, err := fs.resolvePath(path)
	if err != nil {
		return -cgofuse.ENOENT, 0
	}
	if err := fs.vfs.Open(node); err != nil {
		mlog.Warnf("winfsp: Open(%s) failed: %v", path, err)
		return -cgofuse.EIO, 0
	}
	return 0, fs.allocHandle(node)
}

func (fs *pigFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	return safeCall("Read", func() int {
		h := fs.getHandle(fh)
		if h == nil {
			return -cgofuse.EBADF
		}
		data, err := fs.vfs.Read(h.node, ofst, len(buff))
		if err != nil {
			mlog.Warnf("winfsp: Read(%s, off=%d, sz=%d) failed: %v", path, ofst, len(buff), err)
			return -cgofuse.EIO
		}
		if data == nil {
			return 0
		}
		copy(buff, data)
		return len(data)
	})
}

func (fs *pigFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	h := fs.getHandle(fh)
	if h == nil {
		return -cgofuse.EBADF
	}
	n, err := fs.vfs.Write(h.node, ofst, buff)
	if err != nil {
		return -cgofuse.EIO
	}
	return n
}

func (fs *pigFS) Flush(path string, fh uint64) int {
	h := fs.getHandle(fh)
	if h == nil {
		return 0
	}
	if err := fs.vfs.Flush(h.node); err != nil {
		return -cgofuse.EIO
	}
	return 0
}

func (fs *pigFS) Release(path string, fh uint64) int {
	h := fs.getHandle(fh)
	if h == nil {
		return 0
	}
	fs.vfs.Release(h.node)
	fs.freeHandle(fh)
	return 0
}

func (fs *pigFS) Create(path string, flags int, mode uint32) (int, uint64) {
	parent, name, err := fs.resolveParentAndName(path)
	if err != nil {
		return -cgofuse.ENOENT, 0
	}
	child, err := fs.vfs.Create(parent, name)
	if err != nil {
		return mapErr(err), 0
	}
	if err := fs.vfs.Open(child); err != nil {
		return -cgofuse.EIO, 0
	}
	return 0, fs.allocHandle(child)
}

func (fs *pigFS) Mkdir(path string, mode uint32) int {
	parent, name, err := fs.resolveParentAndName(path)
	if err != nil {
		return -cgofuse.ENOENT
	}
	_, err = fs.vfs.Mkdir(parent, name)
	return mapErr(err)
}

func (fs *pigFS) Unlink(path string) int {
	parent, name, err := fs.resolveParentAndName(path)
	if err != nil {
		return -cgofuse.ENOENT
	}
	return mapErr(fs.vfs.Unlink(parent, name))
}

func (fs *pigFS) Rmdir(path string) int {
	parent, name, err := fs.resolveParentAndName(path)
	if err != nil {
		return -cgofuse.ENOENT
	}
	return mapErr(fs.vfs.Rmdir(parent, name))
}

func (fs *pigFS) Rename(oldpath string, newpath string) int {
	oldParent, oldName, err := fs.resolveParentAndName(oldpath)
	if err != nil {
		return -cgofuse.ENOENT
	}
	newParent, newName, err := fs.resolveParentAndName(newpath)
	if err != nil {
		return -cgofuse.ENOENT
	}
	return mapErr(fs.vfs.Rename(oldParent, oldName, newParent, newName))
}

func (fs *pigFS) Truncate(path string, size int64, fh uint64) int {
	node, err := fs.resolvePath(path)
	if err != nil {
		return -cgofuse.ENOENT
	}
	return mapErr(fs.vfs.Truncate(node, size))
}

func (fs *pigFS) Statfs(path string, stat *cgofuse.Statfs_t) int {
	used, limit, err := fs.vfs.Statfs()
	if err != nil {
		return -cgofuse.EIO
	}
	blockSize := int64(4096)
	totalBlocks := limit / blockSize
	usedBlocks := used / blockSize
	freeBlocks := int64(0)
	if totalBlocks > usedBlocks {
		freeBlocks = totalBlocks - usedBlocks
	}
	stat.Bsize = uint64(blockSize)
	stat.Frsize = uint64(blockSize)
	stat.Blocks = uint64(totalBlocks)
	stat.Bfree = uint64(freeBlocks)
	stat.Bavail = uint64(freeBlocks)
	stat.Namemax = 255
	return 0
}

func (fs *pigFS) Chmod(path string, mode uint32) int {
	return 0
}

func (fs *pigFS) Chown(path string, uid uint32, gid uint32) int {
	return 0
}

func (fs *pigFS) Utimens(path string, tmsp []cgofuse.Timespec) int {
	return 0
}

func (fs *pigFS) Access(path string, mask uint32) int {
	return 0
}

func fillStat(node *vfs.Node, stat *cgofuse.Stat_t) {
	node.Mu.RLock()
	defer node.Mu.RUnlock()

	_ = cache.StatusSynced
	mtime := cgofuse.NewTimespec(node.Mtime)
	stat.Mtim = mtime
	stat.Atim = mtime
	stat.Ctim = mtime
	stat.Size = node.Size

	if node.IsDir {
		stat.Mode = cgofuse.S_IFDIR | 0755
		stat.Nlink = 2
	} else {
		stat.Mode = cgofuse.S_IFREG | 0644
		stat.Nlink = 1
	}
}
