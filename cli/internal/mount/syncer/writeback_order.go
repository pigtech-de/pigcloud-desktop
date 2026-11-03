package syncer

import (
	"strings"

	"pigcloud/internal/mount/cache"
)

func groupWriteback(entries []*cache.WritebackEntry) [][]*cache.WritebackEntry {
	parent := make([]int, len(entries))
	for i := range parent {
		parent[i] = i
	}
	find := func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	paths := make([][]string, len(entries))
	for i, e := range entries {
		paths[i] = []string{e.RemotePath}
		if e.Action == "rename" {
			if target := cache.ParseWritebackExtra(e.ExtraJSON).Target; target != "" {
				paths[i] = append(paths[i], target)
			}
		}
	}
	for i := range entries {
		for j := range i {
			if entries[i].InodeID == entries[j].InodeID || pathsOverlap(paths[i], paths[j]) {
				parent[find(i)] = find(j)
			}
		}
	}
	var groups [][]*cache.WritebackEntry
	index := map[int]int{}
	for i, e := range entries {
		root := find(i)
		g, ok := index[root]
		if !ok {
			g = len(groups)
			index[root] = g
			groups = append(groups, nil)
		}
		groups[g] = append(groups[g], e)
	}
	return groups
}

func pathsOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == "" || y == "" || x == y || strings.HasPrefix(y, x+"/") || strings.HasPrefix(x, y+"/") {
				return true
			}
		}
	}
	return false
}
