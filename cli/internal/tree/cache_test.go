package tree

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
)

type digestExec struct {
	digest     string
	shells     []Shell
	digestOK   bool
	digestCall int
	shellCall  int
}

func (d *digestExec) Execute(_ context.Context, command string, _ map[string]string) (*api.Response, error) {
	switch command {
	case "e2ee_shell_digest":
		d.digestCall++
		if !d.digestOK {
			return &api.Response{Success: false}, nil
		}
		raw, _ := json.Marshal(map[string]any{"digest": d.digest, "count": len(d.shells)})
		return &api.Response{Success: true, Raw: raw}, nil
	case "e2ee_list_shells":
		d.shellCall++
		raw, _ := json.Marshal(shellPage{Shells: d.shells, Done: true})
		return &api.Response{Success: true, Raw: raw}, nil
	}
	return nil, fmt.Errorf("unexpected command %q", command)
}

func cacheFixture(t *testing.T) (*crypto.PrivateKeySet, []byte, *digestExec) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	t.Cleanup(priv.Zero)
	parentKey, err := crypto.DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}
	sealedName, err := crypto.SealDisplayName("Quarterly Report.pdf", pub)
	if err != nil {
		t.Fatalf("SealDisplayName: %v", err)
	}
	client := &digestExec{
		digest:   "digest-one",
		digestOK: true,
		shells: []Shell{{
			NodeID: hexID(1), ItemType: "file",
			DisplayName: base64.StdEncoding.EncodeToString(sealedName),
		}},
	}
	return priv, parentKey, client
}

func TestLoadServesASecondCallFromTheSealedSnapshot(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	keys := Keys{Priv: priv, ParentKey: parentKey}

	first, err := Load(context.Background(), client, keys)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	second, err := Load(context.Background(), client, keys)
	if err != nil {
		t.Fatalf("Load (cached): %v", err)
	}

	if client.shellCall != 1 {
		t.Fatalf("walked shells %d times, want 1 (the second call must come from cache)", client.shellCall)
	}
	if first.Len() != second.Len() || second.Len() != 1 {
		t.Fatalf("cached tree lost nodes: %d vs %d", first.Len(), second.Len())
	}
	node, ok := second.Get(hexID(1))
	if !ok || node.Name != "Quarterly Report.pdf" {
		t.Fatalf("cached name = %q", node.Name)
	}
}

func TestASnapshotIsNeverPlaintextOnDisk(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	if _, err := Load(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	blob, err := os.ReadFile(cachePath())
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	if strings.Contains(string(blob), "Quarterly") {
		t.Fatal("the snapshot wrote a plaintext file name to disk")
	}
	info, err := os.Stat(cachePath())
	if err != nil {
		t.Fatalf("stat cache: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestAMovedDigestRefetches(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	keys := Keys{Priv: priv, ParentKey: parentKey}
	if _, err := Load(context.Background(), client, keys); err != nil {
		t.Fatalf("Load: %v", err)
	}

	client.digest = "digest-two"
	if _, err := Load(context.Background(), client, keys); err != nil {
		t.Fatalf("Load after change: %v", err)
	}
	if client.shellCall != 2 {
		t.Fatalf("walked shells %d times, want 2 (a moved digest must refetch)", client.shellCall)
	}
}

func TestARotatedKeyCannotReadTheOldSnapshot(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	if _, err := Load(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	_, rotated, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer rotated.Zero()
	rotatedParentKey, _ := crypto.DeriveParentKey(rotated)

	if _, err := Load(context.Background(), client, Keys{Priv: rotated, ParentKey: rotatedParentKey}); err != nil {
		t.Fatalf("Load under rotated keys: %v", err)
	}
	if client.shellCall != 2 {
		t.Fatal("a snapshot from before a rotation must not be readable after it")
	}
}

func TestACorruptSnapshotFallsBackToAFetch(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	keys := Keys{Priv: priv, ParentKey: parentKey}
	if _, err := Load(context.Background(), client, keys); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := os.WriteFile(cachePath(), []byte("not a sealed snapshot"), 0o600); err != nil {
		t.Fatalf("corrupt cache: %v", err)
	}

	built, err := Load(context.Background(), client, keys)
	if err != nil {
		t.Fatalf("a corrupt cache must degrade to a fetch, not fail: %v", err)
	}
	if built.Len() != 1 || client.shellCall != 2 {
		t.Fatal("corrupt cache did not fall through to a rebuild")
	}
}

func TestADeadDigestProbeStillBuildsTheTree(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	client.digestOK = false

	built, err := Load(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey})
	if err != nil {
		t.Fatalf("a refused digest probe must not fail the command: %v", err)
	}
	if built.Len() != 1 {
		t.Fatalf("built %d nodes, want 1", built.Len())
	}
}

func TestClearCacheRemovesTheSnapshot(t *testing.T) {
	priv, parentKey, client := cacheFixture(t)
	if _, err := Load(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ClearCache()
	if _, err := os.Stat(cachePath()); !os.IsNotExist(err) {
		t.Fatal("ClearCache left the snapshot behind")
	}
}
