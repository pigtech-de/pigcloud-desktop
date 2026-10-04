package crypto

import (
	"crypto/ed25519"
	"fmt"
)

const (
	BackgroundKeyTransferVersion = 2
	BackgroundKeyTransferSize    = 1 + NameKeySize + NameKeySize + Ed25519SKSize + Mldsa44SKSize + 32 + KyberPublicKeySize
)

type BackgroundKeyMaterial struct {
	NameKey     []byte
	ParentKey   []byte
	SigningPriv *SigningPrivateKeySet
	SigningPub  *SigningPublicKeySet
	Pub         *PublicKeySet
}

func (m *BackgroundKeyMaterial) Zero() {
	if m == nil {
		return
	}
	for i := range m.NameKey {
		m.NameKey[i] = 0
	}
	for i := range m.ParentKey {
		m.ParentKey[i] = 0
	}
	m.SigningPriv.Zero()
}

func ParseBackgroundKeyTransfer(payload []byte) (*BackgroundKeyMaterial, error) {
	if len(payload) > 0 && payload[0] == DeviceKeyTransferVersion {
		return nil, fmt.Errorf("background transfer: refusing a device-login payload; the background set must not carry the X25519 secret or the ML-KEM seed")
	}
	if len(payload) != BackgroundKeyTransferSize {
		return nil, fmt.Errorf("background transfer: expected %d bytes, got %d", BackgroundKeyTransferSize, len(payload))
	}
	if payload[0] != BackgroundKeyTransferVersion {
		return nil, fmt.Errorf("background transfer: unsupported version %d", payload[0])
	}

	off := 1
	nameKey := make([]byte, NameKeySize)
	copy(nameKey, payload[off:off+NameKeySize])
	off += NameKeySize
	parentKey := make([]byte, NameKeySize)
	copy(parentKey, payload[off:off+NameKeySize])
	off += NameKeySize
	edSK := make([]byte, Ed25519SKSize)
	copy(edSK, payload[off:off+Ed25519SKSize])
	off += Ed25519SKSize
	mldsaSK := make([]byte, Mldsa44SKSize)
	copy(mldsaSK, payload[off:off+Mldsa44SKSize])
	off += Mldsa44SKSize
	var x25519Pub [32]byte
	copy(x25519Pub[:], payload[off:off+32])
	off += 32
	kyberPub := make([]byte, KyberPublicKeySize)
	copy(kyberPub, payload[off:off+KyberPublicKeySize])

	signPriv := &SigningPrivateKeySet{Ed25519: ed25519.PrivateKey(edSK), Mldsa: mldsaSK}
	signPub, err := DeriveSigningPublic(signPriv)
	if err != nil {
		signPriv.Zero()
		return nil, fmt.Errorf("background transfer: %w", err)
	}

	return &BackgroundKeyMaterial{
		NameKey:     nameKey,
		ParentKey:   parentKey,
		SigningPriv: signPriv,
		SigningPub:  signPub,
		Pub:         &PublicKeySet{X25519: x25519Pub, Kyber: kyberPub},
	}, nil
}
