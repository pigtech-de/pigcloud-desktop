package vfs

import (
	"sync"
	"time"

	"pigcloud/internal/mount/cache"
)

type Node struct {
	Mu sync.RWMutex

	ID         int64
	Name       string
	RemotePath string
	IsDir      bool

	Size  int64
	Mtime time.Time
	Mode  uint32

	SealedKey string
	EncMeta   string
	Etag      string

	Cached       bool
	Dirty        bool
	ContentHash  string
	SyncStatus   cache.SyncStatus
	StatusReason string

	Parent   *Node
	Children map[string]*Node
	Loaded   bool

	OpenCount int
	Data      []byte
	WriteGen  uint64

	lastAccessFlush time.Time

	Downloading bool
	DownloadCh  chan struct{}
	DownloadErr error
}

func NewRootNode(remotePath string) *Node {
	return &Node{
		Name:       "/",
		RemotePath: remotePath,
		IsDir:      true,
		Mode:       0755,
		Mtime:      time.Now(),
		Children:   make(map[string]*Node),
		SyncStatus: cache.StatusSynced,
	}
}

func NewDirNode(name, remotePath string, parent *Node) *Node {
	return &Node{
		Name:       name,
		RemotePath: remotePath,
		IsDir:      true,
		Mode:       0755,
		Mtime:      time.Now(),
		Parent:     parent,
		Children:   make(map[string]*Node),
		SyncStatus: cache.StatusSynced,
	}
}

func NewFileNode(name, remotePath string, size int64, mtime time.Time, parent *Node) *Node {
	return &Node{
		Name:       name,
		RemotePath: remotePath,
		IsDir:      false,
		Mode:       0644,
		Size:       size,
		Mtime:      mtime,
		Parent:     parent,
		SyncStatus: cache.StatusSynced,
	}
}

func (n *Node) AddChild(child *Node) {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	if n.Children == nil {
		n.Children = make(map[string]*Node)
	}
	n.Children[child.Name] = child
	child.Parent = n
}

func (n *Node) RemoveChild(name string) *Node {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	child := n.Children[name]
	delete(n.Children, name)
	return child
}

func (n *Node) GetChild(name string) *Node {
	n.Mu.RLock()
	defer n.Mu.RUnlock()
	return n.Children[name]
}

func (n *Node) ListChildren() []*Node {
	n.Mu.RLock()
	defer n.Mu.RUnlock()
	nodes := make([]*Node, 0, len(n.Children))
	for _, child := range n.Children {
		nodes = append(nodes, child)
	}
	return nodes
}

func (n *Node) ChildCount() int {
	n.Mu.RLock()
	defer n.Mu.RUnlock()
	return len(n.Children)
}

func (n *Node) FullPath() string {
	if n.RemotePath == "" || n.RemotePath == "/" {
		return "/"
	}
	return "/" + n.RemotePath
}
