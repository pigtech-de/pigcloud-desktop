package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
)

const downloadAttempts = 4

const attemptTimeout = 5 * time.Minute

type Keys struct {
	NameKey    []byte
	PrivateKey *crypto.PrivateKeySet
	SigningKey *crypto.SigningPrivateKeySet
}

type Fetcher struct {
	Client *api.Client
	Keys   Keys
	Tag      string
	MaxBytes int64
}

func (f Fetcher) Fetch(ctx context.Context, remotePath string) ([]byte, *api.DownloadResult, error) {
	var encryptedData []byte
	dlResult, err := f.download(ctx, remotePath, func(dlCtx context.Context, opts map[string]string) (*api.DownloadResult, error) {
		data, result, err := f.Client.DownloadToMemory(dlCtx, "/"+remotePath, opts)
		encryptedData = data
		return result, err
	})
	if err != nil {
		return nil, nil, err
	}
	if encryptedData == nil {
		return nil, nil, fmt.Errorf("download %s: exhausted retries", remotePath)
	}
	dataKey, encMeta, err := f.openKey(remotePath, dlResult)
	if err != nil {
		return nil, nil, err
	}
	if err := e2ee.VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(encryptedData), dlResult, f.Keys.SigningKey); err != nil {
		return nil, nil, ClassifyVerifyError(remotePath, err)
	}
	plaintext, err := crypto.DecryptBytes(encryptedData, dataKey, &encMeta)
	if err != nil {
		return nil, nil, cache.Permanent(fmt.Errorf("decrypt %s: %w", remotePath, err))
	}
	return plaintext, dlResult, nil
}

const MaxDownloadSize = int64(5) * 1024 * 1024 * 1024

type Staged struct {
	Path   string
	Hash   string
	Size   int64
	Result *api.DownloadResult
}

func (f Fetcher) FetchToFile(ctx context.Context, remotePath, stagingDir string, expected int64) (*Staged, error) {
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return nil, fmt.Errorf("staging folder: %w", err)
	}
	if free := freeBytes(stagingDir); free >= 0 && free < 2*expected+stagingReserve {
		return nil, fmt.Errorf("download %s: not enough free disk space to stage it: %w", remotePath, syscall.ENOSPC)
	}
	encPath, err := stagingFile(stagingDir, "dl-*.enc")
	if err != nil {
		return nil, err
	}
	defer os.Remove(encPath)
	dlResult, err := f.download(ctx, remotePath, func(dlCtx context.Context, opts map[string]string) (*api.DownloadResult, error) {
		return f.Client.DownloadLimited(dlCtx, "/"+remotePath, encPath, f.bodyLimit(), opts)
	})
	if err != nil {
		return nil, err
	}
	dataKey, encMeta, err := f.openKey(remotePath, dlResult)
	if err != nil {
		return nil, err
	}
	enc, err := os.Open(encPath)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", remotePath, err)
	}
	verifyErr := e2ee.VerifyDownloadIntegrityWithSigningKey(enc, dlResult, f.Keys.SigningKey)
	enc.Close()
	if verifyErr != nil {
		return nil, ClassifyVerifyError(remotePath, verifyErr)
	}
	plainPath, err := stagingFile(stagingDir, "dl-*.part")
	if err != nil {
		return nil, err
	}
	if err := crypto.DecryptFile(encPath, plainPath, dataKey, &encMeta); err != nil {
		os.Remove(plainPath)
		return nil, decryptFailure(remotePath, err)
	}
	hash, size, err := digestFile(plainPath)
	if err != nil {
		os.Remove(plainPath)
		return nil, err
	}
	return &Staged{Path: plainPath, Hash: hash, Size: size, Result: dlResult}, nil
}

const stagingReserve = 64 << 20

func (f Fetcher) bodyLimit() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return MaxDownloadSize + MaxDownloadSize/16
}

func decryptFailure(remotePath string, err error) error {
	wrapped := fmt.Errorf("decrypt %s: %w", remotePath, err)
	if errors.Is(err, syscall.ENOSPC) {
		return wrapped
	}
	return cache.Permanent(wrapped)
}

func stagingFile(dir, pattern string) (string, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("staging file: %w", err)
	}
	name := f.Name()
	f.Close()
	return name, nil
}

func digestFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

func (f Fetcher) download(ctx context.Context, remotePath string, do func(context.Context, map[string]string) (*api.DownloadResult, error)) (*api.DownloadResult, error) {
	opts := map[string]string{}
	crypto.AddPathTokenOptions(opts, f.Keys.NameKey, crypto.PathTokenPaths(remotePath, crypto.PathTokenSelfAndAncestors))

	var dlResult *api.DownloadResult
	for attempt := range downloadAttempts {
		dlCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		var err error
		dlResult, err = do(dlCtx, opts)
		cancel()

		if err == nil {
			break
		}

		if api.IsRateLimited(err) {
			hint := api.RetryAfterHint(err)
			if api.RateLimitExceedsInlineWait(hint) {
				return nil, fmt.Errorf("download %s: %w", remotePath, err)
			}
			delay := api.RateLimitDelay(attempt, hint)
			mlog.Warnf("%s: rate limited, retrying in %v (attempt %d)", f.Tag, delay, attempt+1)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		if errors.Is(err, api.ErrInMemoryDownloadTooLarge) || errors.Is(err, api.ErrDownloadTooLarge) {
			return nil, cache.Permanent(fmt.Errorf("download %s: %w", remotePath, err))
		}
		return nil, fmt.Errorf("download %s: %w", remotePath, err)
	}
	if dlResult == nil {
		return nil, fmt.Errorf("download %s: exhausted retries", remotePath)
	}
	return dlResult, nil
}

func (f Fetcher) openKey(remotePath string, dlResult *api.DownloadResult) ([]byte, crypto.EncryptionMetadata, error) {
	var encMeta crypto.EncryptionMetadata
	if err := e2ee.RequireEncryptedDownload(dlResult); err != nil {
		return nil, encMeta, cache.Permanent(fmt.Errorf("download %s: %w", remotePath, err))
	}
	if dlResult.SealedKey == "" {
		return nil, encMeta, cache.Permanent(fmt.Errorf("download %s: sealed key missing", remotePath))
	}
	sealedKeyBytes, err := base64.StdEncoding.DecodeString(dlResult.SealedKey)
	if err != nil {
		return nil, encMeta, fmt.Errorf("decode sealed key: %w", err)
	}
	dataKey, err := crypto.UnsealDataKey(sealedKeyBytes, f.Keys.PrivateKey)
	if err != nil {
		return nil, encMeta, cache.Permanent(fmt.Errorf("unseal data key: %w", err))
	}
	if dlResult.EncryptionMeta != "" {
		metaBytes, err := base64.StdEncoding.DecodeString(dlResult.EncryptionMeta)
		if err != nil {
			return nil, encMeta, fmt.Errorf("decode encryption meta: %w", err)
		}
		if err := json.Unmarshal(metaBytes, &encMeta); err != nil {
			return nil, encMeta, fmt.Errorf("parse encryption meta: %w", err)
		}
	}
	return dataKey, encMeta, nil
}

func ClassifyVerifyError(remotePath string, err error) error {
	wrapped := fmt.Errorf("verify %s: %w", remotePath, err)
	if e2ee.IsPeerPinFailure(err) || e2ee.IsTeeAttestationUnavailable(err) {
		return wrapped
	}
	return cache.Permanent(wrapped)
}
