package cache

import (
	"errors"
	"time"
)

const (
	TransferRetryBase = 30 * time.Second
	TransferRetryCap = time.Hour
)

func TransferBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := TransferRetryBase << uint(attempts-1)
	if d <= 0 || d > TransferRetryCap {
		return TransferRetryCap
	}
	return d
}

type permanentErr struct{ err error }

func (e *permanentErr) Error() string { return e.err.Error() }
func (e *permanentErr) Unwrap() error { return e.err }

func Permanent(err error) error { return &permanentErr{err} }

func IsPermanent(err error) bool {
	var p *permanentErr
	return errors.As(err, &p)
}
