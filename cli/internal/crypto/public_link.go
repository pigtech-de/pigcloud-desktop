package crypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/blake2b"
)

const publicLinkAccessInfo = "pigcloud-public-link-access-v1"

func DerivePublicLinkAccessProof(linkKey []byte) ([]byte, error) {
	h, err := blake2b.New256(linkKey)
	if err != nil {
		return nil, err
	}
	h.Write([]byte(publicLinkAccessInfo))
	return h.Sum(nil), nil
}

func PublicLinkAccessHash(linkKey []byte) ([]byte, error) {
	proof, err := DerivePublicLinkAccessProof(linkKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(proof)
	return sum[:], nil
}
