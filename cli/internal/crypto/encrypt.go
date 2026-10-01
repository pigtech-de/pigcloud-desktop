package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
)

const ChunkSize = 1024 * 1024

type EncryptionMetadata struct {
	Version         int    `json:"version"`
	Nonce           []byte `json:"nonce"`
	ChunkSize       int    `json:"chunk_size"`
	Chunks          int    `json:"chunks"`
	PlaintextSHA256 string `json:"plaintext_sha256,omitempty"`
	PlaintextSize   int64  `json:"plaintext_size"`
	MetadataMAC     string `json:"metadata_mac,omitempty"`
}

func (m *EncryptionMetadata) WireJSON() ([]byte, error) {
	wire := *m
	wire.PlaintextSHA256 = ""
	return json.Marshal(wire)
}

func EncryptFile(inputPath, outputPath string, dataKey []byte) (*EncryptionMetadata, error) {
	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	input, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open input: %w", err)
	}
	defer input.Close()

	output, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output: %w", err)
	}
	defer output.Close()

	hasher := sha256.New()
	buf := make([]byte, ChunkSize)
	currentNonce := make([]byte, NonceSize)
	copy(currentNonce, nonce)
	chunks := 0
	totalSize := int64(0)

	for {
		n, readErr := io.ReadFull(input, buf)
		if n > 0 {
			chunk := buf[:n]
			hasher.Write(chunk)
			totalSize += int64(n)

			chunkAD := make([]byte, 4)
			binary.BigEndian.PutUint32(chunkAD, uint32(chunks))
			ciphertext := aead.Seal(nil, currentNonce, chunk, chunkAD)

			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
			if _, err := output.Write(lenBuf); err != nil {
				return nil, fmt.Errorf("failed to write length: %w", err)
			}
			if _, err := output.Write(ciphertext); err != nil {
				return nil, fmt.Errorf("failed to write ciphertext: %w", err)
			}

			incrementNonce(currentNonce)
			chunks++
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("failed to read input: %w", readErr)
		}
	}

	meta := &EncryptionMetadata{
		Version:         2,
		Nonce:           nonce,
		ChunkSize:       ChunkSize,
		Chunks:          chunks,
		PlaintextSHA256: fmt.Sprintf("%x", hasher.Sum(nil)),
		PlaintextSize:   totalSize,
	}

	mac, err := ComputeMetadataMAC(dataKey, meta)
	if err != nil {
		return nil, fmt.Errorf("failed to compute metadata MAC: %w", err)
	}
	meta.MetadataMAC = mac

	return meta, nil
}

func ComputeMetadataMAC(dataKey []byte, meta *EncryptionMetadata) (string, error) {
	nonceB64 := base64.StdEncoding.EncodeToString(meta.Nonce)
	canonical := fmt.Sprintf(`[%d,"%s",%d,%d,"%s",%d]`,
		meta.Version, nonceB64, meta.ChunkSize, meta.Chunks,
		meta.PlaintextSHA256, meta.PlaintextSize)

	mac := hmac.New(sha256.New, dataKey)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			break
		}
	}
}

func ComputePlaintextHmac(plaintextSHA256Hex string, nameKey []byte) (string, error) {
	hashBytes, err := hex.DecodeString(plaintextSHA256Hex)
	if err != nil {
		return "", fmt.Errorf("invalid plaintext sha256 hex: %w", err)
	}
	mac := hmac.New(sha256.New, nameKey)
	mac.Write(hashBytes)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
