package syncer

import (
	"fmt"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func ReleaseHeldDeletes(db *cache.DB, v *vfs.VFS, choice string) (int, error) {
	if choice != "delete" && choice != "restore" {
		return 0, fmt.Errorf("unknown choice %q (want delete or restore)", choice)
	}
	if choice == "delete" && db.WritebackDisabled() {
		return 0, cache.ErrReadOnlyMount
	}
	acted := 0
	for _, id := range db.TakeMassDeleteHeld() {
		in, err := db.GetInode(id)
		if err != nil || in == nil {
			continue
		}
		if choice == "delete" {
			if db.EnqueueWriteback(id, "delete", in.RemotePath, "") == nil {
				acted++
			}
			continue
		}
		db.SetLocalContent(id, "", 0)
		db.SetLocalFileID(id, "")
		db.InvalidateCache(id)
		if v != nil {
			if node := v.NodeByID(id); node != nil {
				node.Mu.Lock()
				node.Cached = false
				node.Mu.Unlock()
			}
		}
		acted++
	}
	return acted, nil
}
