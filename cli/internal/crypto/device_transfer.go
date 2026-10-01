package crypto

import (
	"crypto/ed25519"
	"crypto/mlkem"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/crypto/curve25519"
)

const (
	DeviceKeyTransferVersion = 1
	DeviceKeyTransferSize    = 1 + 32 + KyberSeedSize + Ed25519SKSize + Mldsa44SKSize
)

func ParseDeviceKeyTransfer(payload []byte) (*PrivateKeySet, *SigningPrivateKeySet, error) {
	if len(payload) != DeviceKeyTransferSize {
		return nil, nil, fmt.Errorf("device transfer: expected %d bytes, got %d", DeviceKeyTransferSize, len(payload))
	}
	if payload[0] != DeviceKeyTransferVersion {
		return nil, nil, fmt.Errorf("device transfer: unsupported version %d", payload[0])
	}
	off := 1
	var x [32]byte
	copy(x[:], payload[off:off+32])
	off += 32
	kyberSeed := make([]byte, KyberSeedSize)
	copy(kyberSeed, payload[off:off+KyberSeedSize])
	off += KyberSeedSize
	edSK := make([]byte, Ed25519SKSize)
	copy(edSK, payload[off:off+Ed25519SKSize])
	off += Ed25519SKSize
	mldsaSK := make([]byte, Mldsa44SKSize)
	copy(mldsaSK, payload[off:off+Mldsa44SKSize])

	priv := &PrivateKeySet{X25519: x, Kyber: kyberSeed}
	signPriv := &SigningPrivateKeySet{Ed25519: ed25519.PrivateKey(edSK), Mldsa: mldsaSK}
	return priv, signPriv, nil
}

func DeriveHybridPublic(priv *PrivateKeySet) (*PublicKeySet, error) {
	if priv == nil || len(priv.Kyber) != KyberSeedSize {
		return nil, fmt.Errorf("invalid private key set")
	}
	var x25519Pub [32]byte
	curve25519.ScalarBaseMult(&x25519Pub, &priv.X25519)
	dk, err := mlkem.NewDecapsulationKey768(priv.Kyber)
	if err != nil {
		return nil, fmt.Errorf("mlkem decapsulation key: %w", err)
	}
	ek := dk.EncapsulationKey().Bytes()
	if len(ek) != KyberPublicKeySize {
		return nil, fmt.Errorf("unexpected mlkem encapsulation key length: %d", len(ek))
	}
	return &PublicKeySet{X25519: x25519Pub, Kyber: ek}, nil
}

func DeriveSigningPublic(priv *SigningPrivateKeySet) (*SigningPublicKeySet, error) {
	if priv == nil || len(priv.Ed25519) != Ed25519SKSize || len(priv.Mldsa) != Mldsa44SKSize {
		return nil, fmt.Errorf("invalid signing private key set")
	}
	pub := &SigningPublicKeySet{}
	copy(pub.Ed25519[:], priv.Ed25519[32:])
	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(priv.Mldsa); err != nil {
		return nil, fmt.Errorf("mldsa44 priv unmarshal: %w", err)
	}
	mlPub, ok := mlPriv.Public().(*mldsa44.PublicKey)
	if !ok {
		return nil, fmt.Errorf("mldsa44 public type assertion failed")
	}
	mlPubBytes, err := mlPub.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("mldsa44 pub marshal: %w", err)
	}
	pub.Mldsa = mlPubBytes
	return pub, nil
}
