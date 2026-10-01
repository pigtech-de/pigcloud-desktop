package syncer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func uploadIdentityKey(nameKey []byte, operationKey, remotePath, plaintextDigest string) (string, error) {
	digest, err := hex.DecodeString(plaintextDigest)
	if len(nameKey) != 32 || operationKey == "" || remotePath == "" || err != nil || len(digest) != sha256.Size {
		return "", fmt.Errorf("upload content identity is unavailable; retry this file after unlocking")
	}
	identity := hmac.New(sha256.New, nameKey)
	identity.Write([]byte("pigcloud-sync-upload-v1\x00"))
	identity.Write([]byte(operationKey))
	identity.Write([]byte{0})
	identity.Write([]byte(remotePath))
	identity.Write([]byte{0})
	identity.Write(digest)
	return hex.EncodeToString(identity.Sum(nil)), nil
}
