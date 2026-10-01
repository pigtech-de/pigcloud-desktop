package cache

import "testing"

func TestRemoteInvalidationKeepsBaselineWithoutClaimingCurrentVersion(t *testing.T) {
	db := openTestDB(t)
	id, err := db.UpsertInode(&Inode{RemotePath: "file.txt", DisplayName: "file.txt", Etag: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SetLocalContent(id, "first-hash", 11); err != nil {
		t.Fatal(err)
	}
	if err := db.InvalidateCache(id); err != nil {
		t.Fatal(err)
	}
	if err := db.SetRemoteVersion(id, "v2"); err != nil {
		t.Fatal(err)
	}
	current, baseline, version, err := db.LocalContentState(id)
	if err != nil || current != "" || baseline != "first-hash" || version != "v1" {
		t.Fatalf("invalidation erased baseline or claimed a new remote version: %q %q %q %v", current, baseline, version, err)
	}
	if err := db.SetLocalContentForVersion(id, "second-hash", 22, "v2"); err != nil {
		t.Fatal(err)
	}
	current, baseline, version, err = db.LocalContentState(id)
	if err != nil || current != "second-hash" || baseline != "second-hash" || version != "v2" {
		t.Fatalf("download did not replace content proof coherently: %q %q %q %v", current, baseline, version, err)
	}
	if err := db.SetLocalContent(id, "", 0); err != nil {
		t.Fatal(err)
	}
	current, baseline, version, err = db.LocalContentState(id)
	if err != nil || current != "" || baseline != "" || version != "" {
		t.Fatalf("explicit forget retained stale content proof: %q %q %q %v", current, baseline, version, err)
	}
}
