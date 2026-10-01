package syncer

import (
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestUploadIdentityBindsBytesPathOperationAndSecretWithoutExposingTheDigest(t *testing.T) {
	valid := regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)
	for range 50 {
		secret, nonce := make([]byte, 32), make([]byte, 16)
		if _, err := rand.Read(secret); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		operation := hex.EncodeToString(nonce)
		digest := digestOf(operation)
		key, err := uploadIdentityKey(secret, operation, "Photos/a.txt", digest)
		if err != nil || !valid.MatchString(key) || len(key) != 64 || key == digest {
			t.Fatalf("invalid or exposed upload identity: %q, %v", key, err)
		}
		again, err := uploadIdentityKey(secret, operation, "Photos/a.txt", digest)
		if err != nil || again != key {
			t.Fatal("same plaintext retry changed identity")
		}
		otherSecret := append([]byte(nil), secret...)
		otherSecret[0] ^= 1
		for _, changed := range []struct {
			secret                  []byte
			operation, path, digest string
		}{
			{secret, operation, "Photos/b.txt", digest},
			{secret, operation + "-next", "Photos/a.txt", digest},
			{secret, operation, "Photos/a.txt", digestOf(operation + "changed")},
			{otherSecret, operation, "Photos/a.txt", digest},
		} {
			value, err := uploadIdentityKey(changed.secret, changed.operation, changed.path, changed.digest)
			if err != nil || value == key {
				t.Fatal("changed upload context reused another content identity")
			}
		}
	}
}
