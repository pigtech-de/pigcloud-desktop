package daemon

import (
	"sync"

	"pigcloud/internal/mount"
)

const activityRingSize = 100

type activityRing struct {
	mu    sync.Mutex
	buf   [activityRingSize]mount.ActivityEvent
	next  int
	count int
}

func (r *activityRing) add(ev mount.ActivityEvent) {
	r.mu.Lock()
	r.buf[r.next] = ev
	r.next = (r.next + 1) % activityRingSize
	if r.count < activityRingSize {
		r.count++
	}
	r.mu.Unlock()
}

func (r *activityRing) snapshot() []mount.ActivityEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]mount.ActivityEvent, 0, r.count)
	for i := 0; i < r.count; i++ {
		idx := ((r.next-1-i)%activityRingSize + activityRingSize) % activityRingSize
		out = append(out, r.buf[idx])
	}
	return out
}
