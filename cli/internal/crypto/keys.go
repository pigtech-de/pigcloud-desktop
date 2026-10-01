package crypto

import (
	"crypto/rand"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KDFOpsLimit      = 3
	KDFMemLimitMB    = 256
	KDFMemLimitBytes = KDFMemLimitMB * 1024 * 1024
	KeySize          = 32
	NonceSize        = 24
	SaltSize         = 16
)

func DeriveKey(password []byte, salt []byte, opsLimit uint32, memLimit uint32) []byte {
	memKB := memLimit / 1024
	return argon2.IDKey(password, salt, opsLimit, memKB, 1, KeySize)
}

func SealDataKey(dataKey []byte, recipient *PublicKeySet) ([]byte, error) {
	sealed, err := HybridSeal(dataKey, recipient)
	if err != nil {
		return nil, fmt.Errorf("failed to seal data key: %w", err)
	}
	return sealed, nil
}

func UnsealDataKey(sealed []byte, priv *PrivateKeySet) ([]byte, error) {
	plaintext, err := HybridUnseal(sealed, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal data key: %w", err)
	}
	return plaintext, nil
}

func GenerateDataKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}
	return key, nil
}

func GenerateRecoveryKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate recovery key: %w", err)
	}
	return key, nil
}

func EncryptWithKey(plaintext []byte, key []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AEAD: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func DecryptWithKey(ciphertext []byte, nonce []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return plaintext, nil
}

func FormatRecoveryKey(key []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	encoded := base32Encode(key, alphabet)
	var result strings.Builder
	for i := 0; i < len(encoded); i += 4 {
		end := min(i+4, len(encoded))
		if i > 0 {
			result.WriteString("-")
		}
		result.WriteString(encoded[i:end])
	}
	return result.String()
}

func base32Encode(data []byte, alphabet string) string {
	var result []byte
	buffer := 0
	bitsLeft := 0
	for _, b := range data {
		buffer = (buffer << 8) | int(b)
		bitsLeft += 8
		for bitsLeft >= 5 {
			bitsLeft -= 5
			result = append(result, alphabet[(buffer>>bitsLeft)&0x1f])
		}
	}
	if bitsLeft > 0 {
		result = append(result, alphabet[(buffer<<(5-bitsLeft))&0x1f])
	}
	return string(result)
}
