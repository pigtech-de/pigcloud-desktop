package transfer

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"pigcloud/internal/mount/cache"
)

func TestDiskFullDecryptStaysRetryable(t *testing.T) {
	if cache.IsPermanent(decryptFailure("big.bin", fmt.Errorf("failed to write plaintext: %w", syscall.ENOSPC))) {
		t.Fatal("a full disk latched the download as permanent")
	}
	if !cache.IsPermanent(decryptFailure("big.bin", errors.New("decryption failed (corrupted or wrong key)"))) {
		t.Fatal("a corrupt body is retried forever")
	}
}
