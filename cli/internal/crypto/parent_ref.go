package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const parentKeyContext = "pigcloud-e2ee-parent-key-v1"

const treeCacheKeyContext = "pigcloud-e2ee-tree-cache-key-v1"

const (
	parentRefVersionOwn     = 0x01
	parentRefVersionForeign = 0x02
	parentRefNonceSize      = 24
	parentRefIDSize         = 16
)

func DeriveParentKey(priv *PrivateKeySet) ([]byte, error) {
	h, err := blake2b.New256([]byte(parentKeyContext))
	if err != nil {
		return nil, err
	}
	h.Write(priv.X25519[:])
	h.Write(priv.Kyber)
	return h.Sum(nil), nil
}

func DeriveTreeCacheKey(priv *PrivateKeySet) ([]byte, error) {
	h, err := blake2b.New256([]byte(treeCacheKeyContext))
	if err != nil {
		return nil, err
	}
	h.Write(priv.X25519[:])
	h.Write(priv.Kyber)
	return h.Sum(nil), nil
}

func SealParentRef(parentID, nodeID, parentKey []byte) ([]byte, error) {
	payload, err := parentRefPayload(parentID)
	if err != nil {
		return nil, err
	}
	if len(nodeID) != parentRefIDSize {
		return nil, errors.New("parent ref node id must be 16 bytes")
	}
	aead, err := chacha20poly1305.NewX(parentKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, parentRefNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, payload, nodeID)
	out := make([]byte, 1+parentRefNonceSize+len(ct))
	out[0] = parentRefVersionOwn
	copy(out[1:], nonce)
	copy(out[1+parentRefNonceSize:], ct)
	return out, nil
}

func SealParentRefForRecipient(parentID, nodeID []byte, recipient *PublicKeySet) ([]byte, error) {
	payload, err := parentRefPayload(parentID)
	if err != nil {
		return nil, err
	}
	if len(nodeID) != parentRefIDSize {
		return nil, errors.New("parent ref node id must be 16 bytes")
	}
	combined := make([]byte, 2*parentRefIDSize)
	copy(combined, payload)
	copy(combined[parentRefIDSize:], nodeID)
	sealed, err := HybridSeal(combined, recipient)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(sealed))
	out[0] = parentRefVersionForeign
	copy(out[1:], sealed)
	return out, nil
}

func OpenParentRef(blob, nodeID []byte, parentKey []byte, priv *PrivateKeySet) ([]byte, error) {
	if len(blob) < 2 {
		return nil, errors.New("parent ref too short")
	}
	if len(nodeID) != parentRefIDSize {
		return nil, errors.New("parent ref node id must be 16 bytes")
	}
	switch blob[0] {
	case parentRefVersionOwn:
		if parentKey == nil {
			return nil, errors.New("parent key required")
		}
		if len(blob) < 1+parentRefNonceSize+parentRefIDSize+chacha20poly1305.Overhead {
			return nil, errors.New("parent ref too short")
		}
		aead, err := chacha20poly1305.NewX(parentKey)
		if err != nil {
			return nil, err
		}
		nonce := blob[1 : 1+parentRefNonceSize]
		payload, err := aead.Open(nil, nonce, blob[1+parentRefNonceSize:], nodeID)
		if err != nil {
			return nil, errors.New("parent ref decrypt failed")
		}
		if len(payload) != parentRefIDSize {
			return nil, errors.New("parent ref payload malformed")
		}
		return parentOrRoot(payload), nil
	case parentRefVersionForeign:
		if priv == nil {
			return nil, errors.New("private key set required")
		}
		payload, err := HybridUnseal(blob[1:], priv)
		if err != nil {
			return nil, err
		}
		if len(payload) != 2*parentRefIDSize {
			return nil, errors.New("parent ref payload malformed")
		}
		if subtle.ConstantTimeCompare(payload[parentRefIDSize:], nodeID) != 1 {
			return nil, errors.New("parent ref bound to another node")
		}
		return parentOrRoot(payload[:parentRefIDSize]), nil
	default:
		return nil, errors.New("unknown parent ref version")
	}
}

func parentRefPayload(parentID []byte) ([]byte, error) {
	if len(parentID) == 0 {
		return make([]byte, parentRefIDSize), nil
	}
	if len(parentID) != parentRefIDSize {
		return nil, errors.New("parent ref parent id must be 16 bytes")
	}
	out := make([]byte, parentRefIDSize)
	copy(out, parentID)
	return out, nil
}

func parentOrRoot(payload []byte) []byte {
	if bytes.Equal(payload, make([]byte, parentRefIDSize)) {
		return nil
	}
	out := make([]byte, parentRefIDSize)
	copy(out, payload)
	return out
}
