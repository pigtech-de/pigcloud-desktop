package netutil

import "time"

const (
	LoopbackAny = "127.0.0.1:0"
	LoopbackHost = "127.0.0.1"
)

const LoopbackDialTimeout = 5 * time.Second

type AcceptBackoff struct{ d time.Duration }

func (b *AcceptBackoff) Next() time.Duration {
	if b.d == 0 {
		b.d = 5 * time.Millisecond
	} else {
		b.d *= 2
	}
	if b.d > time.Second {
		b.d = time.Second
	}
	return b.d
}

func (b *AcceptBackoff) Reset() { b.d = 0 }
