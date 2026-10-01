package api

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

type ErrorKind int

const (
	KindPermanent ErrorKind = iota
	KindTransient
	KindRateLimited
)

type RequestError struct {
	Kind       ErrorKind
	StatusCode int
	RetryAfter time.Duration
	Err        error
}

func (e *RequestError) Error() string { return e.Err.Error() }

func (e *RequestError) Unwrap() error { return e.Err }

var ErrInMemoryDownloadTooLarge = errors.New("file exceeds in-memory download limit")

func IsRateLimited(err error) bool {
	var reqErr *RequestError
	return errors.As(err, &reqErr) && reqErr.Kind == KindRateLimited
}

func IsTransient(err error) bool {
	var reqErr *RequestError
	return errors.As(err, &reqErr) && reqErr.Kind == KindTransient
}

func IsPermanent(err error) bool {
	var reqErr *RequestError
	return errors.As(err, &reqErr) && reqErr.Kind == KindPermanent
}

func RetryAfterHint(err error) time.Duration {
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		return reqErr.RetryAfter
	}
	return 0
}

const MaxRateLimitDelay = 15 * time.Minute

func RateLimitDelay(attempt int, hint time.Duration) time.Duration {
	if hint > 0 {
		return min(hint, MaxRateLimitDelay)
	}
	return time.Duration(15*(attempt+1)) * time.Second
}

func RateLimitExceedsInlineWait(hint time.Duration) bool {
	return hint > MaxRateLimitDelay
}

func classifyStatus(statusCode int) ErrorKind {
	switch {
	case statusCode == http.StatusTooManyRequests:
		return KindRateLimited
	case statusCode >= 500 && statusCode != http.StatusNotImplemented:
		return KindTransient
	default:
		return KindPermanent
	}
}

func statusError(resp *http.Response, err error) *RequestError {
	return &RequestError{
		Kind:       classifyStatus(resp.StatusCode),
		StatusCode: resp.StatusCode,
		RetryAfter: retryAfterHeader(resp),
		Err:        err,
	}
}

func retryAfterHeader(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

func transportRetryable(err error) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET)
}
