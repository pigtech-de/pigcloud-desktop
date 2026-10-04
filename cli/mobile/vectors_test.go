package mobile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTheEmbeddedVectorsMatchTheSourceFixtures(t *testing.T) {
	entries, err := os.ReadDir("vectors")
	if err != nil {
		t.Fatalf("read the embedded vectors dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no vectors are committed; go:embed would not build and SelfTest would prove nothing")
	}

	for _, entry := range entries {
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			mirrored, err := os.ReadFile(filepath.Join("vectors", name))
			if err != nil {
				t.Fatalf("read the embedded copy: %v", err)
			}
			source, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", name))
			if err != nil {
				t.Fatalf("read the source fixture: %v", err)
			}
			if !bytes.Equal(mirrored, source) {
				t.Errorf("cli/mobile/vectors/%s has drifted from tests/vectors/%s; "+
					"run node scripts/sync-mobile-vectors.mjs and commit the result", name, name)
			}
		})
	}
}
