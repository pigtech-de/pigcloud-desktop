package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateHybridKeyPair(t *testing.T) {
	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	if pub.X25519 == [32]byte{} {
		t.Error("x25519 public key is all zeros")
	}
	if priv.X25519 == [32]byte{} {
		t.Error("x25519 private key is all zeros")
	}
	if len(pub.Kyber) != KyberPublicKeySize {
		t.Errorf("kyber pk length = %d, want %d", len(pub.Kyber), KyberPublicKeySize)
	}
	if len(priv.Kyber) != KyberSeedSize {
		t.Errorf("kyber seed length = %d, want %d", len(priv.Kyber), KyberSeedSize)
	}

	pub2, _, _ := GenerateHybridKeyPair()
	if pub.X25519 == pub2.X25519 {
		t.Error("two key pairs have identical x25519 public keys")
	}
	if bytes.Equal(pub.Kyber, pub2.Kyber) {
		t.Error("two key pairs have identical kyber public keys")
	}
}

func TestGenerateDataKey(t *testing.T) {
	dk, err := GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dk) != KeySize {
		t.Errorf("data key length = %d, want %d", len(dk), KeySize)
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	password := []byte("test-password")
	salt := make([]byte, SaltSize)
	rand.Read(salt)

	k1 := DeriveKey(password, salt, KDFOpsLimit, KDFMemLimitBytes)
	k2 := DeriveKey(password, salt, KDFOpsLimit, KDFMemLimitBytes)

	if !bytes.Equal(k1, k2) {
		t.Error("DeriveKey is not deterministic with same inputs")
	}
	if len(k1) != KeySize {
		t.Errorf("derived key length = %d, want %d", len(k1), KeySize)
	}
}

func TestDeriveKeyDifferentPasswords(t *testing.T) {
	salt := make([]byte, SaltSize)
	rand.Read(salt)

	k1 := DeriveKey([]byte("password-a"), salt, KDFOpsLimit, KDFMemLimitBytes)
	k2 := DeriveKey([]byte("password-b"), salt, KDFOpsLimit, KDFMemLimitBytes)

	if bytes.Equal(k1, k2) {
		t.Error("different passwords produced same key")
	}
}

func TestEncryptDecryptHybridPrivateKey(t *testing.T) {
	_, priv, _ := GenerateHybridKeyPair()
	password := []byte("secure-password-123")

	encrypted, err := EncryptHybridPrivateKey(priv, password)
	if err != nil {
		t.Fatalf("EncryptHybridPrivateKey: %v", err)
	}
	if len(encrypted.X25519Ciphertext) == 0 || len(encrypted.KyberCiphertext) == 0 {
		t.Error("ciphertexts are empty")
	}
	if len(encrypted.X25519Nonce) != NonceSize || len(encrypted.KyberNonce) != NonceSize {
		t.Errorf("nonces wrong length: x=%d k=%d", len(encrypted.X25519Nonce), len(encrypted.KyberNonce))
	}
	if len(encrypted.Salt) != SaltSize {
		t.Errorf("salt length = %d, want %d", len(encrypted.Salt), SaltSize)
	}

	decrypted, err := DecryptHybridPrivateKey(encrypted, password)
	if err != nil {
		t.Fatalf("DecryptHybridPrivateKey: %v", err)
	}
	if decrypted.X25519 != priv.X25519 {
		t.Error("decrypted x25519 key does not match original")
	}
	if !bytes.Equal(decrypted.Kyber, priv.Kyber) {
		t.Error("decrypted kyber seed does not match original")
	}
}

func TestDecryptHybridPrivateKeyWrongPassword(t *testing.T) {
	_, priv, _ := GenerateHybridKeyPair()
	encrypted, _ := EncryptHybridPrivateKey(priv, []byte("correct"))

	_, err := DecryptHybridPrivateKey(encrypted, []byte("wrong"))
	if err == nil {
		t.Error("expected error for wrong password, got nil")
	}
}

func TestSealUnsealDataKey(t *testing.T) {
	pub, priv, _ := GenerateHybridKeyPair()
	dataKey, _ := GenerateDataKey()

	sealed, err := SealDataKey(dataKey, pub)
	if err != nil {
		t.Fatalf("SealDataKey: %v", err)
	}
	if len(sealed) < hybridMinSize {
		t.Errorf("sealed blob too short: %d", len(sealed))
	}

	unsealed, err := UnsealDataKey(sealed, priv)
	if err != nil {
		t.Fatalf("UnsealDataKey: %v", err)
	}
	if !bytes.Equal(unsealed, dataKey) {
		t.Error("unsealed key does not match original")
	}
}

func TestUnsealDataKeyWrongKey(t *testing.T) {
	pub1, _, _ := GenerateHybridKeyPair()
	_, priv2, _ := GenerateHybridKeyPair()
	dataKey, _ := GenerateDataKey()

	sealed, _ := SealDataKey(dataKey, pub1)

	_, err := UnsealDataKey(sealed, priv2)
	if err == nil {
		t.Error("expected error for wrong key pair, got nil")
	}
}

func TestUnsealDataKeyTooShort(t *testing.T) {
	_, priv, _ := GenerateHybridKeyPair()
	_, err := UnsealDataKey([]byte("short"), priv)
	if err == nil {
		t.Error("expected error for short sealed data, got nil")
	}
}

func TestSealUnsealDisplayName(t *testing.T) {
	pub, priv, _ := GenerateHybridKeyPair()
	name := "annual report 2026.pdf"

	sealed, err := SealDisplayName(name, pub)
	if err != nil {
		t.Fatalf("SealDisplayName: %v", err)
	}

	got, err := UnsealDisplayName(sealed, priv)
	if err != nil {
		t.Fatalf("UnsealDisplayName: %v", err)
	}
	if got != name {
		t.Errorf("got %q, want %q", got, name)
	}
}

func TestEncryptDecryptWithKey(t *testing.T) {
	key, _ := GenerateDataKey()
	plaintext := []byte("hello, encrypted world!")

	ciphertext, nonce, err := EncryptWithKey(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptWithKey: %v", err)
	}

	decrypted, err := DecryptWithKey(ciphertext, nonce, key)
	if err != nil {
		t.Fatalf("DecryptWithKey: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data does not match original")
	}
}

func TestDecryptWithKeyWrongKey(t *testing.T) {
	key1, _ := GenerateDataKey()
	key2, _ := GenerateDataKey()
	ciphertext, nonce, _ := EncryptWithKey([]byte("secret"), key1)

	_, err := DecryptWithKey(ciphertext, nonce, key2)
	if err == nil {
		t.Error("expected error for wrong key, got nil")
	}
}

func TestEncryptHybridPrivateKeyWithRecoveryKey(t *testing.T) {
	_, priv, _ := GenerateHybridKeyPair()
	recoveryKey, _ := GenerateRecoveryKey()

	wrapped, err := EncryptHybridPrivateKeyWithKey(priv, recoveryKey)
	if err != nil {
		t.Fatalf("EncryptHybridPrivateKeyWithKey: %v", err)
	}

	xPlain, err := DecryptWithKey(wrapped.X25519Ciphertext, wrapped.X25519Nonce, recoveryKey)
	if err != nil {
		t.Fatalf("DecryptWithKey x25519: %v", err)
	}
	var got [32]byte
	copy(got[:], xPlain)
	if got != priv.X25519 {
		t.Error("recovered x25519 sk does not match original")
	}

	kPlain, err := DecryptWithKey(wrapped.KyberCiphertext, wrapped.KyberNonce, recoveryKey)
	if err != nil {
		t.Fatalf("DecryptWithKey kyber: %v", err)
	}
	if !bytes.Equal(kPlain, priv.Kyber) {
		t.Error("recovered kyber seed does not match original")
	}
}

func TestFormatRecoveryKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	formatted := FormatRecoveryKey(key)
	if len(formatted) == 0 {
		t.Error("formatted recovery key is empty")
	}
	if !strings.Contains(formatted, "-") {
		t.Error("expected dashes in formatted recovery key")
	}
	for _, c := range strings.ReplaceAll(formatted, "-", "") {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			t.Errorf("unexpected character in recovery key: %c", c)
		}
	}
}

func TestIncrementNonce(t *testing.T) {
	nonce := make([]byte, NonceSize)
	incrementNonce(nonce)
	if nonce[0] != 1 {
		t.Errorf("nonce[0] = %d after first increment, want 1", nonce[0])
	}

	nonce[0] = 0xFF
	incrementNonce(nonce)
	if nonce[0] != 0 || nonce[1] != 1 {
		t.Errorf("nonce = %x after overflow, want [00 01 ...]", nonce[:3])
	}
}

func TestEncryptDecryptFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "plaintext.bin")
	encPath := filepath.Join(dir, "encrypted.bin")
	decPath := filepath.Join(dir, "decrypted.bin")

	plaintext := make([]byte, ChunkSize+500)
	rand.Read(plaintext)
	if err := os.WriteFile(inputPath, plaintext, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	dataKey, _ := GenerateDataKey()

	meta, err := EncryptFile(inputPath, encPath, dataKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	if meta.Version != 2 {
		t.Errorf("version = %d, want 2", meta.Version)
	}
	if meta.Chunks != 2 {
		t.Errorf("chunks = %d, want 2", meta.Chunks)
	}
	if meta.PlaintextSize != int64(len(plaintext)) {
		t.Errorf("plaintext size = %d, want %d", meta.PlaintextSize, len(plaintext))
	}

	h := sha256.Sum256(plaintext)
	expectedHash := fmt.Sprintf("%x", h[:])
	if meta.PlaintextSHA256 != expectedHash {
		t.Error("metadata SHA256 does not match computed hash")
	}

	err = DecryptFile(encPath, decPath, dataKey, meta)
	if err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	decrypted, _ := os.ReadFile(decPath)
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted file does not match original")
	}
}

func TestEncryptDecryptFileSmall(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "small.txt")
	encPath := filepath.Join(dir, "small.enc")
	decPath := filepath.Join(dir, "small.dec")

	content := []byte("hello world")
	os.WriteFile(inputPath, content, 0600)

	dataKey, _ := GenerateDataKey()

	meta, err := EncryptFile(inputPath, encPath, dataKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	if meta.Chunks != 1 {
		t.Errorf("chunks = %d, want 1", meta.Chunks)
	}

	err = DecryptFile(encPath, decPath, dataKey, meta)
	if err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	decrypted, _ := os.ReadFile(decPath)
	if !bytes.Equal(decrypted, content) {
		t.Errorf("got %q, want %q", decrypted, content)
	}
}

func TestDecryptFileWrongKey(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	encPath := filepath.Join(dir, "enc.bin")
	decPath := filepath.Join(dir, "dec.bin")

	os.WriteFile(inputPath, []byte("secret data"), 0600)
	key1, _ := GenerateDataKey()
	key2, _ := GenerateDataKey()

	meta, _ := EncryptFile(inputPath, encPath, key1)

	err := DecryptFile(encPath, decPath, key2, meta)
	if err == nil {
		t.Error("expected error decrypting with wrong key, got nil")
	}
}

func TestDecryptToMemory(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	encPath := filepath.Join(dir, "enc.bin")

	content := []byte("some text content for cat command")
	os.WriteFile(inputPath, content, 0600)

	dataKey, _ := GenerateDataKey()
	meta, _ := EncryptFile(inputPath, encPath, dataKey)

	result, err := DecryptToMemory(encPath, dataKey, meta)
	if err != nil {
		t.Fatalf("DecryptToMemory: %v", err)
	}
	if !bytes.Equal(result, content) {
		t.Errorf("got %q, want %q", result, content)
	}
}

func TestDecryptToMemoryIntegrityMismatch(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	encPath := filepath.Join(dir, "enc.bin")

	os.WriteFile(inputPath, []byte("integrity test"), 0600)
	dataKey, _ := GenerateDataKey()
	meta, _ := EncryptFile(inputPath, encPath, dataKey)

	meta.PlaintextSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	_, err := DecryptToMemory(encPath, dataKey, meta)
	if err == nil {
		t.Error("expected integrity error, got nil")
	}
	if !strings.Contains(err.Error(), "integrity") {
		t.Errorf("error should mention integrity, got: %v", err)
	}
}

func TestEncryptDecryptEmptyFile(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "empty.txt")
	encPath := filepath.Join(dir, "empty.enc")
	decPath := filepath.Join(dir, "empty.dec")

	os.WriteFile(inputPath, []byte{}, 0600)
	dataKey, _ := GenerateDataKey()

	meta, err := EncryptFile(inputPath, encPath, dataKey)
	if err != nil {
		t.Fatalf("EncryptFile (empty): %v", err)
	}
	if meta.Chunks != 0 {
		t.Errorf("chunks = %d for empty file, want 0", meta.Chunks)
	}

	err = DecryptFile(encPath, decPath, dataKey, meta)
	if err != nil {
		t.Fatalf("DecryptFile (empty): %v", err)
	}
	dec, _ := os.ReadFile(decPath)
	if len(dec) != 0 {
		t.Errorf("decrypted empty file has %d bytes", len(dec))
	}
}
