package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicGuardSeesCompletedTemporaryFileAndPreservesDestinationOnRefusal(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "file.txt")
	if err := os.WriteFile(target, []byte("local edit"), 0600); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("local file changed")
	err := WriteFileAtomicGuarded(target, []byte("remote bytes"), 0600, func() error {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, entry := range entries {
			if IsTempName(entry.Name()) {
				bytes, err := os.ReadFile(filepath.Join(directory, entry.Name()))
				if err != nil || string(bytes) != "remote bytes" {
					t.Fatalf("guard ran before the temporary body was complete: %q, %v", bytes, err)
				}
				found = true
			}
		}
		if !found {
			t.Fatal("guard did not run between temporary-file creation and publication")
		}
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("guard rejection lost: %v", err)
	}
	bytes, err := os.ReadFile(target)
	if err != nil || string(bytes) != "local edit" {
		t.Fatalf("guarded publication changed local data: %q, %v", bytes, err)
	}
	assertNoLeftovers(t, directory)
}
