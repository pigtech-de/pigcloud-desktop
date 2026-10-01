package tree

import (
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

type Node struct {
	ID         string
	Name       string
	ParentID   string
	IsDir      bool
	Size       int64
	CreatedAt  int64
	ModifiedAt int64
	Hidden     bool
	Trashed    bool
}

type Shell struct {
	NodeID          string `json:"node_id"`
	ItemType        string `json:"item_type"`
	FileSize        int64  `json:"file_size"`
	CreatedAt       int64  `json:"created_at"`
	ModifiedAt      int64  `json:"modified_at"`
	IsHidden        bool   `json:"is_hidden"`
	IsTrashed       bool   `json:"is_trashed"`
	DisplayName     string `json:"e2ee_display_name"`
	SealedParent    string `json:"e2ee_sealed_parent"`
	PlaintextParent string `json:"parent_id"`
}

type Tree struct {
	byID     map[string]*Node
	children map[string][]string
	Orphans []string
}

func New(nodes []*Node) *Tree {
	t := &Tree{byID: make(map[string]*Node, len(nodes)), children: map[string][]string{}}
	for _, n := range nodes {
		t.byID[n.ID] = n
	}
	for _, n := range nodes {
		parent := n.ParentID
		if parent != "" {
			if _, ok := t.byID[parent]; !ok {
				t.Orphans = append(t.Orphans, n.ID)
				parent = ""
			}
		}
		t.children[parent] = append(t.children[parent], n.ID)
	}
	t.detachCycles()
	for parent := range t.children {
		ids := t.children[parent]
		sort.Slice(ids, func(i, j int) bool {
			a, b := t.byID[ids[i]], t.byID[ids[j]]
			if a.IsDir != b.IsDir {
				return a.IsDir
			}
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		})
	}
	return t
}

func (t *Tree) detachCycles() {
	reachable := make(map[string]bool, len(t.byID))
	for id := range t.byID {
		if reachable[id] {
			continue
		}
		seen := map[string]bool{}
		chain := []string{}
		cur := id
		for {
			if cur == "" || reachable[cur] {
				for _, c := range chain {
					reachable[c] = true
				}
				break
			}
			if seen[cur] {
				t.reroot(id)
				break
			}
			seen[cur] = true
			chain = append(chain, cur)
			node, ok := t.byID[cur]
			if !ok {
				for _, c := range chain {
					reachable[c] = true
				}
				break
			}
			cur = node.ParentID
		}
	}
}

func (t *Tree) reroot(id string) {
	node, ok := t.byID[id]
	if !ok || node.ParentID == "" {
		return
	}
	siblings := t.children[node.ParentID]
	for i, sib := range siblings {
		if sib == id {
			t.children[node.ParentID] = append(siblings[:i:i], siblings[i+1:]...)
			break
		}
	}
	node.ParentID = ""
	t.children[""] = append(t.children[""], id)
	t.Orphans = append(t.Orphans, id)
}

func (t *Tree) Get(id string) (*Node, bool) {
	n, ok := t.byID[id]
	return n, ok
}

func (t *Tree) Children(parentID string) []*Node {
	ids := t.children[parentID]
	out := make([]*Node, 0, len(ids))
	for _, id := range ids {
		if n, ok := t.byID[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

func (t *Tree) Descendants(parentID string) []string {
	var out []string
	seen := map[string]bool{parentID: true}
	frontier := append([]string(nil), t.children[parentID]...)
	for len(frontier) > 0 {
		next := frontier[:0:0]
		for _, id := range frontier {
			if seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
			next = append(next, t.children[id]...)
		}
		frontier = next
	}
	return out
}

func (t *Tree) Subtree(parentID string, includeHidden bool) []string {
	var out []string
	seen := map[string]bool{parentID: true}
	var walk func(id string)
	walk = func(id string) {
		for _, child := range t.Children(id) {
			if seen[child.ID] || child.Trashed {
				continue
			}
			if !includeHidden && child.Hidden {
				continue
			}
			seen[child.ID] = true
			out = append(out, child.ID)
			if child.IsDir {
				walk(child.ID)
			}
		}
	}
	walk(parentID)
	return out
}

var ErrNotFound = errors.New("path not found")

func (t *Tree) Resolve(path string) (*Node, error) {
	trimmed := strings.Trim(strings.ReplaceAll(path, "\\", "/"), "/")
	if trimmed == "" {
		return nil, nil
	}
	parent := ""
	var node *Node
	for segment := range strings.SplitSeq(trimmed, "/") {
		if segment == "" || segment == "." {
			continue
		}
		found := false
		for _, child := range t.Children(parent) {
			if strings.EqualFold(child.Name, segment) && !child.Trashed {
				node, parent, found = child, child.ID, true
				break
			}
		}
		if !found {
			return nil, ErrNotFound
		}
	}
	if node == nil {
		return nil, ErrNotFound
	}
	return node, nil
}

func (t *Tree) PathOf(id string) string {
	var parts []string
	seen := map[string]bool{}
	for cur := id; cur != ""; {
		if seen[cur] {
			return ""
		}
		seen[cur] = true
		node, ok := t.byID[cur]
		if !ok {
			return ""
		}
		parts = append(parts, node.Name)
		cur = node.ParentID
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/")
}

func (t *Tree) Len() int { return len(t.byID) }

func IDBytes(hexID string) ([]byte, error) {
	raw, err := hex.DecodeString(hexID)
	if err != nil {
		return nil, err
	}
	if len(raw) != 16 {
		return nil, errors.New("node id must be 16 bytes")
	}
	return raw, nil
}
