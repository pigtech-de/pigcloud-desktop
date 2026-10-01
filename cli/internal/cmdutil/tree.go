package cmdutil

import (
	"strings"

	"pigcloud/internal/api"
)

func JoinRemotePath(root, rel string) string {
	if rel == "" {
		return root
	}
	trimmed := strings.TrimSuffix(root, "/")
	if trimmed == "" {
		return "/" + rel
	}
	return trimmed + "/" + rel
}

func WalkTreeFiles(entries []api.TreeEntry, root string, fn func(entry api.TreeEntry, remotePath, relPath string)) {
	var walk func([]api.TreeEntry, string)
	walk = func(level []api.TreeEntry, prefix string) {
		for _, e := range level {
			relPath := e.Name
			if prefix != "" {
				relPath = prefix + "/" + e.Name
			}
			if e.Type == "directory" {
				walk(e.Children, relPath)
				continue
			}
			fn(e, JoinRemotePath(root, relPath), relPath)
		}
	}
	walk(entries, "")
}
