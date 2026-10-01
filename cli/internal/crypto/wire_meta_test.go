package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var marshalArgPattern = regexp.MustCompile(`json\.Marshal\(\s*(&?[A-Za-z_][A-Za-z0-9_]*)\s*\)`)

var metaVarNames = map[string]bool{
	"meta": true, "&meta": true,
	"encMeta": true, "&encMeta": true,
	"metadata": true, "&metadata": true,
	"encryptionMeta": true, "&encryptionMeta": true,
}

func sampleMeta() *EncryptionMetadata {
	return &EncryptionMetadata{
		Version:         2,
		Nonce:           make([]byte, NonceSize),
		ChunkSize:       ChunkSize,
		Chunks:          1,
		PlaintextSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		PlaintextSize:   11,
		MetadataMAC:     strings.Repeat("a", 64),
	}
}

func TestWireJSONOmitsThePlaintextDigest(t *testing.T) {
	wire, err := sampleMeta().WireJSON()
	if err != nil {
		t.Fatalf("WireJSON: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := decoded["plaintext_sha256"]; present {
		t.Fatal("the wire form carries a plaintext digest the host can match against a known-file set")
	}
	for _, key := range []string{"version", "nonce", "chunk_size", "chunks", "plaintext_size", "metadata_mac"} {
		if _, present := decoded[key]; !present {
			t.Fatalf("the wire form dropped %q, which the enclave and the sidecar both need", key)
		}
	}
}

func TestWireJSONLeavesTheCallersMetadataIntact(t *testing.T) {
	meta := sampleMeta()
	want := meta.PlaintextSHA256

	if _, err := meta.WireJSON(); err != nil {
		t.Fatalf("WireJSON: %v", err)
	}
	if meta.PlaintextSHA256 != want {
		t.Fatal("WireJSON cleared the caller's digest, which it still needs for the MAC and the dedup tag")
	}
}

func TestNoRequestSiteMarshalsEncryptionMetadataDirectly(t *testing.T) {
	root := filepath.Join("..", "..")
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, match := range marshalArgPattern.FindAllStringSubmatch(line, -1) {
				if metaVarNames[match[1]] {
					offenders = append(offenders, filepath.ToSlash(path)+":"+itoa(i+1))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("encryption metadata must reach a request through WireJSON, not json.Marshal: %s", strings.Join(offenders, ", "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
