package transfer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
	Tag string
}

func (f Fetcher) Fetch(ctx context.Context, remotePath string) ([]byte, *api.DownloadResult, error) {
	opts := map[string]string{}
	crypto.AddPathTokenOptions(opts, f.Keys.NameKey, crypto.PathTokenPaths(remotePath, crypto.PathTokenSelfAndAncestors))

	var encryptedData []byte
	var dlResult *api.DownloadResult

	for attempt := range downloadAttempts {
		dlCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
		var err error
		encryptedData, dlResult, err = f.Client.DownloadToMemory(dlCtx, "/"+remotePath, opts)
		cancel()

		if err == nil {
			break
		}

		if api.IsRateLimited(err) {
			hint := api.RetryAfterHint(err)
			if api.RateLimitExceedsInlineWait(hint) {
				return nil, nil, fmt.Errorf("download %s: %w", remotePath, err)
			}
			delay := api.RateLimitDelay(attempt, hint)
			mlog.Warnf("%s: rate limited on %s, retrying in %v (attempt %d)", f.Tag, remotePath, delay, attempt+1)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
			continue
		}

		if errors.Is(err, api.ErrInMemoryDownloadTooLarge) {
			return nil, nil, cache.Permanent(fmt.Errorf("download %s: %w", remotePath, err))
		}
		return nil, nil, fmt.Errorf("download %s: %w", remotePath, err)
	}

	if encryptedData == nil || dlResult == nil {
		return nil, nil, fmt.Errorf("download %s: exhausted retries", remotePath)
	}

	if err := e2ee.RequireEncryptedDownload(dlResult); err != nil {
		return nil, nil, cache.Permanent(fmt.Errorf("download %s: %w", remotePath, err))
	}
	if dlResult.SealedKey == "" {
		return nil, nil, cache.Permanent(fmt.Errorf("download %s: sealed key missing", remotePath))
	}

	sealedKeyBytes, err := base64.StdEncoding.DecodeString(dlResult.SealedKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode sealed key: %w", err)
	}

	dataKey, err := crypto.UnsealDataKey(sealedKeyBytes, f.Keys.PrivateKey)
	if err != nil {
		return nil, nil, cache.Permanent(fmt.Errorf("unseal data key: %w", err))
	}

	var encMeta crypto.EncryptionMetadata
	if dlResult.EncryptionMeta != "" {
		metaBytes, err := base64.StdEncoding.DecodeString(dlResult.EncryptionMeta)
		if err != nil {
			return nil, nil, fmt.Errorf("decode encryption meta: %w", err)
		}
		if err := json.Unmarshal(metaBytes, &encMeta); err != nil {
			return nil, nil, fmt.Errorf("parse encryption meta: %w", err)
		}
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

func ClassifyVerifyError(remotePath string, err error) error {
	wrapped := fmt.Errorf("verify %s: %w", remotePath, err)
	if e2ee.IsPeerPinFailure(err) || e2ee.IsTeeAttestationUnavailable(err) {
		return wrapped
	}
	return cache.Permanent(wrapped)
}
