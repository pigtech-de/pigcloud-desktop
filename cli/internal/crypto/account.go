package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

func AccountFingerprint(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}
