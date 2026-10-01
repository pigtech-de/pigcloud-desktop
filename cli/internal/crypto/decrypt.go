package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

const maxChunkLen = ChunkSize + chacha20poly1305.Overhead + 1024

func DecryptFile(inputPath, outputPath string, dataKey []byte, metadata *EncryptionMetadata) error {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return fmt.Errorf("failed to create AEAD: %w", err)
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input: %w", err)
	}
	defer input.Close()

	output, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output: %w", err)
	}
	defer output.Close()

	hasher := sha256.New()
	currentNonce := make([]byte, NonceSize)
	copy(currentNonce, metadata.Nonce)

	lenBuf := make([]byte, 4)
	chunkIndex := uint32(0)

	for {
		_, err := io.ReadFull(input, lenBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen > uint32(maxChunkLen) {
			return fmt.Errorf("chunk length %d exceeds maximum %d (corrupted file?)", chunkLen, maxChunkLen)
		}
		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}

		chunkAD := make([]byte, 4)
		binary.BigEndian.PutUint32(chunkAD, chunkIndex)
		plaintext, err := aead.Open(nil, currentNonce, ciphertext, chunkAD)
		if err != nil {
			if metadata.Version >= 2 {
				return fmt.Errorf("decryption failed (corrupted or wrong key): %w", err)
			}
			plaintext, err = aead.Open(nil, currentNonce, ciphertext, nil)
			if err != nil {
				return fmt.Errorf("decryption failed (corrupted or wrong key): %w", err)
			}
		}

		hasher.Write(plaintext)
		if _, err := output.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write plaintext: %w", err)
		}

		incrementNonce(currentNonce)
		chunkIndex++
	}

	recoveredHash := fmt.Sprintf("%x", hasher.Sum(nil))

	if metadata.PlaintextSHA256 != "" && recoveredHash != metadata.PlaintextSHA256 {
		return fmt.Errorf("integrity check failed: hash mismatch")
	}

	return verifyMetadataMACWithRecoveredHash(dataKey, metadata, recoveredHash)
}

func DecryptToMemory(inputPath string, dataKey []byte, metadata *EncryptionMetadata) ([]byte, error) {
	input, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input: %w", err)
	}
	defer input.Close()
	return decryptReader(input, dataKey, metadata)
}

func DecryptBytes(ciphertext []byte, dataKey []byte, metadata *EncryptionMetadata) ([]byte, error) {
	return decryptReader(bytes.NewReader(ciphertext), dataKey, metadata)
}

func decryptReader(input io.Reader, dataKey []byte, metadata *EncryptionMetadata) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	hasher := sha256.New()
	currentNonce := make([]byte, NonceSize)
	copy(currentNonce, metadata.Nonce)

	var result []byte
	lenBuf := make([]byte, 4)
	chunkIndex := uint32(0)

	for {
		_, err := io.ReadFull(input, lenBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk length: %w", err)
		}

		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen > uint32(maxChunkLen) {
			return nil, fmt.Errorf("chunk length %d exceeds maximum %d (corrupted file?)", chunkLen, maxChunkLen)
		}
		ciphertext := make([]byte, chunkLen)
		if _, err := io.ReadFull(input, ciphertext); err != nil {
			return nil, fmt.Errorf("failed to read ciphertext: %w", err)
		}

		chunkAD := make([]byte, 4)
		binary.BigEndian.PutUint32(chunkAD, chunkIndex)
		plaintext, err := aead.Open(nil, currentNonce, ciphertext, chunkAD)
		if err != nil {
			if metadata.Version >= 2 {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
			plaintext, err = aead.Open(nil, currentNonce, ciphertext, nil)
			if err != nil {
				return nil, fmt.Errorf("decryption failed: %w", err)
			}
		}

		hasher.Write(plaintext)
		result = append(result, plaintext...)
		incrementNonce(currentNonce)
		chunkIndex++
	}

	recoveredHash := fmt.Sprintf("%x", hasher.Sum(nil))

	if metadata.PlaintextSHA256 != "" && recoveredHash != metadata.PlaintextSHA256 {
		return nil, fmt.Errorf("integrity check failed: hash mismatch")
	}

	if err := verifyMetadataMACWithRecoveredHash(dataKey, metadata, recoveredHash); err != nil {
		return nil, err
	}
	return result, nil
}

func verifyMetadataMACWithRecoveredHash(dataKey []byte, metadata *EncryptionMetadata, recoveredHash string) error {
	if metadata.MetadataMAC == "" {
		return fmt.Errorf("metadata MAC missing: metadata integrity cannot be verified")
	}

	metaCopy := *metadata
	if metaCopy.PlaintextSHA256 == "" {
		metaCopy.PlaintextSHA256 = recoveredHash
	}

	expected, err := ComputeMetadataMAC(dataKey, &metaCopy)
	if err != nil {
		return fmt.Errorf("failed to compute metadata MAC for verification: %w", err)
	}

	if !hmac.Equal([]byte(metadata.MetadataMAC), []byte(expected)) {
		return fmt.Errorf("metadata MAC verification failed: metadata may have been tampered with")
	}

	return nil
}
