package cache

import (
	"context"
	"errors"
	"time"

	"pigcloud/internal/mount/mlog"
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

func (d *DB) RecordTransferFailure(tag, path string, inodeID int64, kind string, err error) {
	if inodeID == 0 || errors.Is(err, context.Canceled) {
		return
	}
	attempts := 1
	if prev, gerr := d.GetSyncFailure(inodeID, kind); gerr == nil && prev != nil {
		attempts = prev.Attempts + 1
	}
	f := &SyncFailure{InodeID: inodeID, Kind: kind, Permanent: IsPermanent(err), Attempts: attempts, LastError: err.Error()}
	if f.Permanent {
		d.SetSyncStatus(inodeID, StatusFailed, err.Error())
		mlog.Errorf("%s: %s will not be retried: %v", tag, path, err)
	} else {
		wait := TransferBackoff(attempts)
		f.NextRetryAt = time.Now().Add(wait).Unix()
		mlog.Warnf("%s: %s: %v (attempt %d, next in %v)", tag, path, err, attempts, wait)
	}
	d.RecordSyncFailure(f)
}

func (d *DB) TransferWithheld(inodeID int64, kind string) *SyncFailure {
	if inodeID == 0 {
		return nil
	}
	f, err := d.GetSyncFailure(inodeID, kind)
	if err != nil || f == nil || (!f.Permanent && time.Now().Unix() >= f.NextRetryAt) {
		return nil
	}
	return f
}

type permanentErr struct{ err error }

func (e *permanentErr) Error() string { return e.err.Error() }
func (e *permanentErr) Unwrap() error { return e.err }

func Permanent(err error) error { return &permanentErr{err} }

func IsPermanent(err error) bool {
	var p *permanentErr
	return errors.As(err, &p)
}
