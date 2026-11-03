package api

import (
	"context"
	"errors"
	"net/http"
	"time"
)

type Executor interface {
	Execute(ctx context.Context, command string, options map[string]string) (*Response, error)
}

const executeRateLimitRetries = 3

type rateLimitWaiter struct{ Executor }

func WaitOutRateLimits(e Executor) Executor { return rateLimitWaiter{e} }

func (w rateLimitWaiter) Execute(ctx context.Context, command string, options map[string]string) (*Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := w.Executor.Execute(ctx, command, options)
		if err != nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests || attempt >= executeRateLimitRetries {
			return resp, err
		}
		select {
		case <-time.After(rateLimitWait(attempt, 0)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func HasErrorCode(resp *Response, err error, code string) bool {
	if resp != nil && !resp.Success && resp.ErrorCode == code {
		return true
	}
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}
