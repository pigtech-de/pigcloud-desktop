package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"
)

func respWith(status int, retryAfter string) *http.Response {
	h := http.Header{}
	if retryAfter != "" {
		h.Set("Retry-After", retryAfter)
	}
	return &http.Response{StatusCode: status, Header: h}
}

func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		status int
		want   ErrorKind
	}{
		{429, KindRateLimited},
		{500, KindTransient},
		{502, KindTransient},
		{503, KindTransient},
		{501, KindPermanent},
		{400, KindPermanent},
		{401, KindPermanent},
		{403, KindPermanent},
		{404, KindPermanent},
		{200, KindPermanent},
	}
	for _, c := range cases {
		if got := classifyStatus(c.status); got != c.want {
			t.Errorf("classifyStatus(%d) = %v, want %v", c.status, got, c.want)
		}
	}
}

func TestStatusErrorKeepsMessageAndChain(t *testing.T) {
	inner := &APIError{Code: "rate_limited", Message: "Too many commands were submitted. Try again in 30 seconds."}
	err := statusError(respWith(429, "30"), inner)

	if err.Error() != inner.Message {
		t.Errorf("message changed: %q", err.Error())
	}
	if !IsRateLimited(err) {
		t.Error("429 not classified rate-limited")
	}
	if IsTransient(err) {
		t.Error("429 must not be short-backoff transient")
	}
	if got := RetryAfterHint(err); got != 30*time.Second {
		t.Errorf("RetryAfterHint = %v, want 30s", got)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "rate_limited" {
		t.Error("APIError no longer reachable through the classification wrapper")
	}

	wrapped := fmt.Errorf("download /x: %w", err)
	if !IsRateLimited(wrapped) {
		t.Error("classification lost through fmt.Errorf wrapping")
	}
}

func TestRetryAfterHeaderParsing(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"45", 45 * time.Second},
		{"0", 0},
		{"-3", 0},
		{"garbage", 0},
		{"Wed, 21 Oct 2026 07:28:00 GMT", 0},
	}
	for _, c := range cases {
		if got := retryAfterHeader(respWith(429, c.header)); got != c.want {
			t.Errorf("retryAfterHeader(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestRateLimitDelay(t *testing.T) {
	if got := RateLimitDelay(0, 20*time.Second); got != 20*time.Second {
		t.Errorf("hint ignored: %v", got)
	}
	if got := RateLimitDelay(0, 10*time.Minute); got != 10*time.Minute {
		t.Errorf("hint past the old two-minute cutoff discarded: %v", got)
	}
	if got := RateLimitDelay(0, 18*time.Hour); got != MaxRateLimitDelay {
		t.Errorf("hint not bounded: %v, want %v", got, MaxRateLimitDelay)
	}
	if got := RateLimitDelay(2, 0); got != 45*time.Second {
		t.Errorf("default ladder broken: %v", got)
	}
}

func TestRateLimitHintBeyondTheCapIsNotSleptThrough(t *testing.T) {
	if !RateLimitExceedsInlineWait(18 * time.Hour) {
		t.Error("an 18h window must not be waited out inline: a FUSE read would hang for it")
	}
	if RateLimitExceedsInlineWait(30 * time.Second) {
		t.Error("an ordinary bucket window is short enough to wait out")
	}
	if RateLimitExceedsInlineWait(0) {
		t.Error("no hint means the caller falls back to its own ladder, not an abort")
	}
}

type fakeTimeout struct{}

func (fakeTimeout) Error() string   { return "i/o timeout" }
func (fakeTimeout) Timeout() bool   { return true }
func (fakeTimeout) Temporary() bool { return true }

func TestTransportRetryable(t *testing.T) {
	var _ net.Error = fakeTimeout{}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"canceled", context.Canceled, false},
		{"wrapped canceled", fmt.Errorf("request failed: %w", context.Canceled), false},
		{"net timeout", fmt.Errorf("request failed: %w", fakeTimeout{}), true},
		{"eof", fmt.Errorf("failed to read response: %w", io.EOF), true},
		{"unexpected eof", io.ErrUnexpectedEOF, true},
		{"conn reset", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true},
		{"plain error", errors.New("no such host"), false},
	}
	for _, c := range cases {
		if got := transportRetryable(c.err); got != c.want {
			t.Errorf("%s: transportRetryable = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsTransientTypedAndFallback(t *testing.T) {
	if isTransient(statusError(respWith(503, ""), errors.New("bad gateway")), 503) != true {
		t.Error("typed 5xx not transient")
	}
	if isTransient(statusError(respWith(429, ""), errors.New("slow down")), 429) {
		t.Error("typed 429 must not retry on the short-backoff loop")
	}
	if isTransient(statusError(respWith(404, ""), errors.New("gone")), 404) {
		t.Error("typed 404 transient")
	}
	if !isTransient(errors.New("failed to parse response"), 502) {
		t.Error("unclassified error on a 502 should stay retryable")
	}
	if isTransient(errors.New("failed to parse response"), 501) {
		t.Error("501 retried")
	}
	if isTransient(nil, 500) {
		t.Error("nil error retried")
	}
}

func TestWithRetryHonorsClassification(t *testing.T) {
	saved := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { retryDelays = saved }()

	calls := 0
	_, err := withRetry(context.Background(), func() (int, int, error) {
		calls++
		return 0, 503, statusError(respWith(503, ""), errors.New("upstream down"))
	})
	if err == nil || calls != 3 {
		t.Errorf("transient: calls = %d (want 3), err = %v", calls, err)
	}

	calls = 0
	_, err = withRetry(context.Background(), func() (int, int, error) {
		calls++
		return 0, 429, statusError(respWith(429, "30"), errors.New("rate limited"))
	})
	if calls != 1 {
		t.Errorf("rate-limited: calls = %d, want 1 (outer callers own the long backoff)", calls)
	}
	if !IsRateLimited(err) {
		t.Error("rate-limit classification lost through withRetry")
	}

	calls = 0
	got, err := withRetry(context.Background(), func() (string, int, error) {
		calls++
		if calls == 1 {
			return "", 0, fmt.Errorf("read: %w", io.ErrUnexpectedEOF)
		}
		return "ok", 200, nil
	})
	if err != nil || got != "ok" || calls != 2 {
		t.Errorf("recovery: got %q calls %d err %v", got, calls, err)
	}
}
