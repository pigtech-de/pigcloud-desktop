package tree

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/chacha20poly1305"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/fsutil"
)

const cacheFileName = "tree-cache.bin"

type snapshot struct {
	Digest string  `json:"digest"`
	Nodes  []*Node `json:"nodes"`
}

func cachePath() string {
	return filepath.Join(config.Dir(), cacheFileName)
}

func serverDigest(ctx context.Context, client Executor) (string, error) {
	resp, err := client.Execute(ctx, "e2ee_shell_digest", map[string]string{})
	if err != nil {
		return "", err
	}
	if resp == nil || !resp.Success {
		return "", fmt.Errorf("tree: digest refused")
	}
	var body struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(resp.Raw, &body); err != nil {
		return "", err
	}
	if body.Digest == "" {
		return "", fmt.Errorf("tree: empty digest")
	}
	return body.Digest, nil
}

func readSnapshot(cacheKey []byte) (*snapshot, error) {
	blob, err := os.ReadFile(cachePath())
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(cacheKey)
	if err != nil {
		return nil, err
	}
	if len(blob) < chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("tree: cache truncated")
	}
	plain, err := aead.Open(nil, blob[:chacha20poly1305.NonceSizeX], blob[chacha20poly1305.NonceSizeX:], nil)
	if err != nil {
		return nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

func writeSnapshot(cacheKey []byte, snap *snapshot) error {
	plain, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(cacheKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := append(nonce, aead.Seal(nil, nonce, plain, nil)...)

	path := cachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, sealed, 0o600)
}

func Load(ctx context.Context, client Executor, keys Keys) (*Tree, error) {
	if keys.Priv == nil {
		return nil, fmt.Errorf("tree: private key set required")
	}
	cacheKey, keyErr := crypto.DeriveTreeCacheKey(keys.Priv)

	digest, digestErr := serverDigest(ctx, client)
	if digestErr == nil && keyErr == nil {
		if snap, err := readSnapshot(cacheKey); err == nil && snap.Digest == digest {
			return New(snap.Nodes), nil
		}
	}

	built, err := Fetch(ctx, client, keys)
	if err != nil {
		return nil, err
	}
	if digestErr == nil && keyErr == nil {
		nodes := make([]*Node, 0, built.Len())
		for _, node := range built.byID {
			nodes = append(nodes, node)
		}
		_ = writeSnapshot(cacheKey, &snapshot{Digest: digest, Nodes: nodes})
	}
	return built, nil
}

func ClearCache() {
	_ = os.Remove(cachePath())
}
