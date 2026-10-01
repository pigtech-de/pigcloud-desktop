package syncer

import (
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
)

const transferRetryCap = cache.TransferRetryCap

func transferBackoff(attempts int) time.Duration { return cache.TransferBackoff(attempts) }

func writebackRetryDelay(err error, attempts int) time.Duration {
	if api.IsRateLimited(err) {
		return api.RateLimitDelay(attempts-1, api.RetryAfterHint(err))
	}
	return transferBackoff(attempts)
}

func permanent(err error) error { return cache.Permanent(err) }

func isPermanent(err error) bool { return cache.IsPermanent(err) }
