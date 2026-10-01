package syncer

import (
	"pigcloud/internal/mount/mlog"
	"time"
)

const stopWait = 10 * time.Second

func awaitLoopExit(done <-chan struct{}, name string) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(stopWait):
		mlog.Warnf("%s: still busy %v after stop; proceeding with shutdown", name, stopWait)
	}
}
