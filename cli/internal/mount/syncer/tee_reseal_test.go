package syncer

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func TestWritebackResealsAStaleUploadAtMostOnce(t *testing.T) {
	p, db, tree, _, _ := pollFixture(t)
	local := t.TempDir()
	writeFile(t, filepath.Join(local, "notes.txt"), "ONE")
	node := addExistingFile(t, p, db, "notes.txt", 3, time.Now(), true, true)
	tree.AttachChild(tree.Root, node)
	if err := db.EnqueueWriteback(node.ID, "upload", "notes.txt", ""); err != nil {
		t.Fatal(err)
	}
	entries, err := db.DequeueWriteback(1, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("claim upload: %+v, %v", entries, err)
	}
	writer := NewWritebackProcessor(tree, p.client, db, nil, local)
	attempts := 0
	writer.upload = func(context.Context, *cache.WritebackEntry) (uploadedContent, error) {
		attempts++
		return uploadedContent{}, fmt.Errorf("%w: upload: scanner unavailable", errTeeSealStale)
	}

	if writer.processEntry(context.Background(), entries[0]) {
		t.Fatal("an upload refused on both seals was reported as synced")
	}
	if attempts != 2 {
		t.Fatalf("upload attempts = %d, want the first plus exactly one reseal", attempts)
	}
}
