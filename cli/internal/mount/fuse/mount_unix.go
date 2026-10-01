//go:build !windows

package fuse

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"

	"pigcloud/internal/mount/vfs"

	gofuse "github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func mapErr(err error) syscall.Errno {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, vfs.ErrNotFound):
		return syscall.ENOENT
	case errors.Is(err, vfs.ErrNotEmpty):
		return syscall.ENOTEMPTY
	case errors.Is(err, vfs.ErrExists):
		return syscall.EEXIST
	case errors.Is(err, vfs.ErrIsDir):
		return syscall.EISDIR
	case errors.Is(err, vfs.ErrReadOnly):
		return syscall.EROFS
	case errors.Is(err, vfs.ErrInvalidName):
		return syscall.EINVAL
	default:
		return syscall.EIO
	}
}

type Backend struct {
	server *fuse.Server
	vfs    *vfs.VFS
}

func New() *Backend {
	return &Backend{}
}

func (b *Backend) Mount(mountpoint string, v *vfs.VFS) error {
	b.vfs = v
	root := &fuseRoot{vfs: v, node: v.Root}

	opts := &gofuse.Options{
		MountOptions: fuse.MountOptions{
			FsName:        "pigcloud",
			Name:          "pigcloud",
			DisableXAttrs: true,
			MaxBackground: 32,
		},
		AttrTimeout:  &[]time.Duration{30 * time.Second}[0],
		EntryTimeout: &[]time.Duration{30 * time.Second}[0],
	}

	server, err := gofuse.Mount(mountpoint, root, opts)
	if err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	b.server = server

	server.Wait()
	return nil
}

func (b *Backend) Unmount() error {
	if b.server != nil {
		return b.server.Unmount()
	}
	return nil
}

type fuseRoot struct {
	gofuse.Inode
	vfs  *vfs.VFS
	node *vfs.Node
}

var _ = (gofuse.NodeLookuper)((*fuseRoot)(nil))
var _ = (gofuse.NodeReaddirer)((*fuseRoot)(nil))
var _ = (gofuse.NodeGetattrer)((*fuseRoot)(nil))
var _ = (gofuse.NodeMkdirer)((*fuseRoot)(nil))
var _ = (gofuse.NodeCreater)((*fuseRoot)(nil))
var _ = (gofuse.NodeUnlinker)((*fuseRoot)(nil))
var _ = (gofuse.NodeRmdirer)((*fuseRoot)(nil))
var _ = (gofuse.NodeRenamer)((*fuseRoot)(nil))
var _ = (gofuse.NodeStatfser)((*fuseRoot)(nil))

func (r *fuseRoot) Getattr(ctx context.Context, fh gofuse.FileHandle, out *fuse.AttrOut) syscall.Errno {
	fillAttr(r.node, &out.Attr)
	return 0
}

func (r *fuseRoot) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*gofuse.Inode, syscall.Errno) {
	child, err := r.vfs.Lookup(r.node, name)
	if err != nil {
		return nil, syscall.ENOENT
	}
	fillAttr(child, &out.Attr)
	childNode := &fuseNode{vfs: r.vfs, node: child}
	stable := gofuse.StableAttr{Mode: attrMode(child)}
	return r.NewInode(ctx, childNode, stable), 0
}

func (r *fuseRoot) Readdir(ctx context.Context) (gofuse.DirStream, syscall.Errno) {
	return readdir(r.vfs, r.node)
}

func (r *fuseRoot) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*gofuse.Inode, syscall.Errno) {
	child, err := r.vfs.Mkdir(r.node, name)
	if err != nil {
		return nil, mapErr(err)
	}
	fillAttr(child, &out.Attr)
	childNode := &fuseNode{vfs: r.vfs, node: child}
	stable := gofuse.StableAttr{Mode: syscall.S_IFDIR}
	return r.NewInode(ctx, childNode, stable), 0
}

func (r *fuseRoot) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *gofuse.Inode, fh gofuse.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	child, err := r.vfs.Create(r.node, name)
	if err != nil {
		return nil, nil, 0, mapErr(err)
	}
	if err := r.vfs.Open(child); err != nil {
		return nil, nil, 0, syscall.EIO
	}
	fillAttr(child, &out.Attr)
	childNode := &fuseNode{vfs: r.vfs, node: child}
	stable := gofuse.StableAttr{Mode: syscall.S_IFREG}
	return r.NewInode(ctx, childNode, stable), &fuseHandle{vfs: r.vfs, node: child}, 0, 0
}

func (r *fuseRoot) Unlink(ctx context.Context, name string) syscall.Errno {
	return mapErr(r.vfs.Unlink(r.node, name))
}

func (r *fuseRoot) Rmdir(ctx context.Context, name string) syscall.Errno {
	return mapErr(r.vfs.Rmdir(r.node, name))
}

func (r *fuseRoot) Rename(ctx context.Context, name string, newParent gofuse.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	newPN := resolveNode(newParent)
	if newPN == nil {
		return syscall.EIO
	}
	return mapErr(r.vfs.Rename(r.node, name, newPN, newName))
}

func (r *fuseRoot) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	used, limit, err := r.vfs.Statfs()
	if err != nil {
		return syscall.EIO
	}
	blockSize := uint64(4096)
	totalBlocks := uint64(limit) / blockSize
	usedBlocks := uint64(used) / blockSize
	freeBlocks := uint64(0)
	if totalBlocks > usedBlocks {
		freeBlocks = totalBlocks - usedBlocks
	}
	out.Blocks = totalBlocks
	out.Bfree = freeBlocks
	out.Bavail = freeBlocks
	out.Bsize = uint32(blockSize)
	out.NameLen = 255
	return 0
}

type fuseNode struct {
	gofuse.Inode
	vfs  *vfs.VFS
	node *vfs.Node
}

var _ = (gofuse.NodeLookuper)((*fuseNode)(nil))
var _ = (gofuse.NodeReaddirer)((*fuseNode)(nil))
var _ = (gofuse.NodeGetattrer)((*fuseNode)(nil))
var _ = (gofuse.NodeOpener)((*fuseNode)(nil))
var _ = (gofuse.NodeMkdirer)((*fuseNode)(nil))
var _ = (gofuse.NodeCreater)((*fuseNode)(nil))
var _ = (gofuse.NodeUnlinker)((*fuseNode)(nil))
var _ = (gofuse.NodeRmdirer)((*fuseNode)(nil))
var _ = (gofuse.NodeRenamer)((*fuseNode)(nil))
var _ = (gofuse.NodeSetattrer)((*fuseNode)(nil))

func (n *fuseNode) Getattr(ctx context.Context, fh gofuse.FileHandle, out *fuse.AttrOut) syscall.Errno {
	fillAttr(n.node, &out.Attr)
	return 0
}

func (n *fuseNode) Setattr(ctx context.Context, fh gofuse.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if sz, ok := in.GetSize(); ok {
		if err := n.vfs.Truncate(n.node, int64(sz)); err != nil {
			return mapErr(err)
		}
	}
	fillAttr(n.node, &out.Attr)
	return 0
}

func (n *fuseNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*gofuse.Inode, syscall.Errno) {
	child, err := n.vfs.Lookup(n.node, name)
	if err != nil {
		return nil, syscall.ENOENT
	}
	fillAttr(child, &out.Attr)
	childNode := &fuseNode{vfs: n.vfs, node: child}
	stable := gofuse.StableAttr{Mode: attrMode(child)}
	return n.NewInode(ctx, childNode, stable), 0
}

func (n *fuseNode) Readdir(ctx context.Context) (gofuse.DirStream, syscall.Errno) {
	return readdir(n.vfs, n.node)
}

func (n *fuseNode) Open(ctx context.Context, flags uint32) (gofuse.FileHandle, uint32, syscall.Errno) {
	if err := n.vfs.Open(n.node); err != nil {
		return nil, 0, syscall.EIO
	}
	return &fuseHandle{vfs: n.vfs, node: n.node}, 0, 0
}

func (n *fuseNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*gofuse.Inode, syscall.Errno) {
	child, err := n.vfs.Mkdir(n.node, name)
	if err != nil {
		return nil, mapErr(err)
	}
	fillAttr(child, &out.Attr)
	childNode := &fuseNode{vfs: n.vfs, node: child}
	stable := gofuse.StableAttr{Mode: syscall.S_IFDIR}
	return n.NewInode(ctx, childNode, stable), 0
}

func (n *fuseNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (inode *gofuse.Inode, fh gofuse.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	child, err := n.vfs.Create(n.node, name)
	if err != nil {
		return nil, nil, 0, mapErr(err)
	}
	if err := n.vfs.Open(child); err != nil {
		return nil, nil, 0, syscall.EIO
	}
	fillAttr(child, &out.Attr)
	childNode := &fuseNode{vfs: n.vfs, node: child}
	stable := gofuse.StableAttr{Mode: syscall.S_IFREG}
	return n.NewInode(ctx, childNode, stable), &fuseHandle{vfs: n.vfs, node: child}, 0, 0
}

func (n *fuseNode) Unlink(ctx context.Context, name string) syscall.Errno {
	return mapErr(n.vfs.Unlink(n.node, name))
}

func (n *fuseNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	return mapErr(n.vfs.Rmdir(n.node, name))
}

func (n *fuseNode) Rename(ctx context.Context, name string, newParent gofuse.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	newPN := resolveNode(newParent)
	if newPN == nil {
		return syscall.EIO
	}
	return mapErr(n.vfs.Rename(n.node, name, newPN, newName))
}

type fuseHandle struct {
	vfs  *vfs.VFS
	node *vfs.Node
}

var _ = (gofuse.FileReader)((*fuseHandle)(nil))
var _ = (gofuse.FileWriter)((*fuseHandle)(nil))
var _ = (gofuse.FileFlusher)((*fuseHandle)(nil))
var _ = (gofuse.FileReleaser)((*fuseHandle)(nil))

func (h *fuseHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	data, err := h.vfs.Read(h.node, off, len(dest))
	if err != nil {
		return nil, syscall.EIO
	}
	return fuse.ReadResultData(data), 0
}

func (h *fuseHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	n, err := h.vfs.Write(h.node, off, data)
	if err != nil {
		return 0, syscall.EIO
	}
	return uint32(n), 0
}

func (h *fuseHandle) Flush(ctx context.Context) syscall.Errno {
	if err := h.vfs.Flush(h.node); err != nil {
		return syscall.EIO
	}
	return 0
}

func (h *fuseHandle) Release(ctx context.Context) syscall.Errno {
	if err := h.vfs.Release(h.node); err != nil {
		return syscall.EIO
	}
	return 0
}

func fillAttr(node *vfs.Node, attr *fuse.Attr) {
	node.Mu.RLock()
	defer node.Mu.RUnlock()

	attr.Size = uint64(node.Size)
	attr.Mtime = uint64(node.Mtime.Unix())
	attr.Atime = uint64(node.Mtime.Unix())
	attr.Ctime = uint64(node.Mtime.Unix())

	if node.IsDir {
		attr.Mode = syscall.S_IFDIR | 0755
		attr.Nlink = 2
	} else {
		attr.Mode = syscall.S_IFREG | 0644
		attr.Nlink = 1
	}
}

func attrMode(node *vfs.Node) uint32 {
	if node.IsDir {
		return syscall.S_IFDIR
	}
	return syscall.S_IFREG
}

func readdir(v *vfs.VFS, parent *vfs.Node) (gofuse.DirStream, syscall.Errno) {
	children, err := v.Readdir(parent)
	if err != nil {
		return nil, syscall.EIO
	}

	entries := make([]fuse.DirEntry, 0, len(children))
	for _, child := range children {
		mode := uint32(syscall.S_IFREG)
		if child.IsDir {
			mode = syscall.S_IFDIR
		}
		entries = append(entries, fuse.DirEntry{
			Name: child.Name,
			Mode: mode,
		})
	}

	return gofuse.NewListDirStream(entries), 0
}

func resolveNode(inode gofuse.InodeEmbedder) *vfs.Node {
	switch n := inode.(type) {
	case *fuseRoot:
		return n.node
	case *fuseNode:
		return n.node
	}
	return nil
}
