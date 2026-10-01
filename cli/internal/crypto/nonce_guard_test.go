package crypto

import (
	"strings"
	"testing"
)

func corruptNonceLengths() map[string]int {
	return map[string]int{
		"empty":              0,
		"one byte short":     NonceSize - 1,
		"one byte long":      NonceSize + 1,
		"single byte":        1,
		"half a nonce":       NonceSize / 2,
		"double length":      NonceSize * 2,
		"aead key sized":     KeySize,
		"far past the nonce": 128,
	}
}

func wrappedHybridFixture(t *testing.T) (*EncryptedHybridPrivateKey, []byte) {
	t.Helper()
	_, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pdk := make([]byte, KeySize)
	for i := range pdk {
		pdk[i] = byte(i)
	}
	wrapped, err := EncryptHybridPrivateKeyWithKey(priv, pdk)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	return &EncryptedHybridPrivateKey{
		X25519Ciphertext: wrapped.X25519Ciphertext,
		X25519Nonce:      wrapped.X25519Nonce,
		KyberCiphertext:  wrapped.KyberCiphertext,
		KyberNonce:       wrapped.KyberNonce,
		Salt:             make([]byte, SaltSize),
		OpsLimit:         KDFOpsLimit,
		MemLimit:         KDFMemLimitBytes,
	}, pdk
}

func TestHybridUnwrapRejectsWrongNonceLengthWithoutPanicking(t *testing.T) {
	for name, length := range corruptNonceLengths() {
		t.Run("x25519 nonce "+name, func(t *testing.T) {
			enc, pdk := wrappedHybridFixture(t)
			enc.X25519Nonce = make([]byte, length)

			priv, err := DecryptHybridPrivateKeyWithRawKey(enc, pdk)
			if err == nil {
				t.Fatalf("a %d-byte x25519 nonce unwrapped successfully", length)
			}
			if priv != nil {
				t.Error("key material returned alongside an error")
			}
			assertNamesTheNonce(t, err)
		})

		t.Run("kyber nonce "+name, func(t *testing.T) {
			enc, pdk := wrappedHybridFixture(t)
			enc.KyberNonce = make([]byte, length)

			priv, err := DecryptHybridPrivateKeyWithRawKey(enc, pdk)
			if err == nil {
				t.Fatalf("a %d-byte kyber nonce unwrapped successfully", length)
			}
			if priv != nil {
				t.Error("key material returned alongside an error")
			}
			assertNamesTheNonce(t, err)
		})
	}
}

func TestSigningUnwrapRejectsWrongNonceLengthWithoutPanicking(t *testing.T) {
	build := func(t *testing.T) (*EncryptedSigningPrivateKeySet, []byte) {
		t.Helper()
		_, priv, err := GenerateSigningKeyPair()
		if err != nil {
			t.Fatalf("signing keygen: %v", err)
		}
		pdk := make([]byte, KeySize)
		for i := range pdk {
			pdk[i] = byte(255 - i)
		}
		enc, err := EncryptSigningPrivateKeys(priv, pdk)
		if err != nil {
			t.Fatalf("wrap signing keys: %v", err)
		}
		return enc, pdk
	}

	for name, length := range corruptNonceLengths() {
		t.Run("ed25519 nonce "+name, func(t *testing.T) {
			enc, pdk := build(t)
			enc.Ed25519Nonce = make([]byte, length)

			priv, err := DecryptSigningPrivateKeys(enc, pdk)
			if err == nil {
				t.Fatalf("a %d-byte ed25519 nonce unwrapped successfully", length)
			}
			if priv != nil {
				t.Error("signing key material returned alongside an error")
			}
			assertNamesTheNonce(t, err)
		})

		t.Run("mldsa nonce "+name, func(t *testing.T) {
			enc, pdk := build(t)
			enc.MldsaNonce = make([]byte, length)

			priv, err := DecryptSigningPrivateKeys(enc, pdk)
			if err == nil {
				t.Fatalf("a %d-byte mldsa nonce unwrapped successfully", length)
			}
			if priv != nil {
				t.Error("signing key material returned alongside an error")
			}
			assertNamesTheNonce(t, err)
		})
	}
}

func assertNamesTheNonce(t *testing.T, err error) {
	t.Helper()
	if !strings.Contains(strings.ToLower(err.Error()), "nonce") {
		t.Errorf("error %q does not name the nonce as the corrupt field", err)
	}
}

func TestCorrectNonceLengthStillUnwraps(t *testing.T) {
	enc, pdk := wrappedHybridFixture(t)
	if _, err := DecryptHybridPrivateKeyWithRawKey(enc, pdk); err != nil {
		t.Fatalf("an intact %d-byte nonce failed to unwrap: %v", NonceSize, err)
	}
}
