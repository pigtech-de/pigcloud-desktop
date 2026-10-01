package crypto

import (
	"fmt"
)

const MessageNonceSize = NonceSize

func EncryptMessage(plaintext []byte, dataKey []byte) ([]byte, []byte, error) {
	if len(dataKey) != KeySize {
		return nil, nil, fmt.Errorf("data key must be %d bytes", KeySize)
	}
	return EncryptWithKey(plaintext, dataKey)
}

func DecryptMessage(ciphertext []byte, nonce []byte, dataKey []byte) ([]byte, error) {
	if len(nonce) != MessageNonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", MessageNonceSize, len(nonce))
	}
	if len(dataKey) != KeySize {
		return nil, fmt.Errorf("data key must be %d bytes", KeySize)
	}
	return DecryptWithKey(ciphertext, nonce, dataKey)
}
