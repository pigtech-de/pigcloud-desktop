package cache

import (
	"strings"
	"testing"
)

func TestInodeRoundTripsEveryColumn(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	want := &Inode{
		RemotePath:   "docs/report.pdf",
		DisplayName:  "report.pdf",
		IsDir:        false,
		Size:         4242,
		Mtime:        1700000001,
		Cached:       true,
		Dirty:        true,
		LastAccess:   1700000002,
		ContentHash:  "content-hash-value",
		LocalHash:    "local-hash-value",
		LocalMtime:   1700000003,
		SealedKey:    "sealed-key-value",
		EncMeta:      "enc-meta-value",
		Etag:         "etag-value",
		SyncStatus:   StatusFailed,
		StatusReason: "status-reason-value",
	}
	id, err := db.UpsertInode(want)
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	db.SetPinned(want.RemotePath, true)
	db.SetSyncStatus(id, want.SyncStatus, want.StatusReason)

	got, err := db.GetInode(id)
	if err != nil || got == nil {
		t.Fatalf("get inode: %v", err)
	}

	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"RemotePath", got.RemotePath, want.RemotePath},
		{"DisplayName", got.DisplayName, want.DisplayName},
		{"IsDir", got.IsDir, want.IsDir},
		{"Size", got.Size, want.Size},
		{"Mtime", got.Mtime, want.Mtime},
		{"Cached", got.Cached, want.Cached},
		{"Dirty", got.Dirty, want.Dirty},
		{"Pinned", got.Pinned, true},
		{"LastAccess", got.LastAccess, want.LastAccess},
		{"ContentHash", got.ContentHash, want.ContentHash},
		{"LocalHash", got.LocalHash, want.LocalHash},
		{"LocalMtime", got.LocalMtime, want.LocalMtime},
		{"SealedKey", got.SealedKey, want.SealedKey},
		{"EncMeta", got.EncMeta, want.EncMeta},
		{"Etag", got.Etag, want.Etag},
		{"SyncStatus", got.SyncStatus, want.SyncStatus},
		{"StatusReason", got.StatusReason, want.StatusReason},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	byPath, err := db.GetInodeByPath(want.RemotePath)
	if err != nil || byPath == nil || byPath.ID != id {
		t.Fatalf("GetInodeByPath: %v", err)
	}
	for _, list := range []struct {
		name string
		fn   func() ([]*Inode, error)
	}{
		{"AllInodes", db.AllInodes},
		{"ListPinned", db.ListPinned},
		{"ListIssues", db.ListIssues},
		{"InodesWithFailures", db.InodesWithFailures},
	} {
		rows, err := list.fn()
		if err != nil {
			t.Errorf("%s: %v", list.name, err)
			continue
		}
		found := false
		for _, in := range rows {
			if in.ID == id {
				found = true
				if in.StatusReason != want.StatusReason || in.LocalHash != want.LocalHash {
					t.Errorf("%s returned a differently-scanned row: %+v", list.name, in)
				}
			}
		}
		if !found {
			t.Errorf("%s did not return the failed, pinned inode", list.name)
		}
	}
}

func TestInodeColumnsCountMatchesScanner(t *testing.T) {
	const wantColumns = 19
	if got := len(strings.Split(inodeColumns, ",")); got != wantColumns {
		t.Fatalf("inodeColumns names %d columns, scanInodeRow scans %d", got, wantColumns)
	}
}
