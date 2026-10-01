package daemon

import (
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

type stuckListener struct {
	calls atomic.Int64
	err   error
}

func (l *stuckListener) Accept() (net.Conn, error) {
	l.calls.Add(1)
	return nil, l.err
}

func (l *stuckListener) Close() error { return nil }

func (l *stuckListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

const maxAcceptCallsInWindow = 50

const acceptWindow = 200 * time.Millisecond

func transientAcceptErr() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: syscall.ECONNABORTED}
}

func TestSyncDaemonAcceptLoopBacksOffOnTransientErrors(t *testing.T) {
	sd := &SyncDaemon{shutdownCh: make(chan struct{})}
	ln := &stuckListener{err: transientAcceptErr()}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sd.acceptIPC(ln)
	}()

	time.Sleep(acceptWindow)
	got := ln.calls.Load()

	close(sd.shutdownCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptIPC ignored shutdown while retrying a failing listener")
	}

	if got > maxAcceptCallsInWindow {
		t.Errorf("acceptIPC called Accept %d times in %v (cap %d); a broken listener spins a core at 100%% instead of backing off",
			got, acceptWindow, maxAcceptCallsInWindow)
	}
	if got == 0 {
		t.Error("acceptIPC never called Accept; the backoff assertion would be vacuous")
	}
}

func TestVirtualDaemonAcceptLoopBacksOffOnTransientErrors(t *testing.T) {
	d := &Daemon{shutdownCh: make(chan struct{})}
	ln := &stuckListener{err: transientAcceptErr()}

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.acceptIPC(ln)
	}()

	time.Sleep(acceptWindow)
	got := ln.calls.Load()

	close(d.shutdownCh)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptIPC ignored shutdown while retrying a failing listener")
	}

	if got > maxAcceptCallsInWindow {
		t.Errorf("acceptIPC called Accept %d times in %v (cap %d); a broken listener spins a core at 100%% instead of backing off",
			got, acceptWindow, maxAcceptCallsInWindow)
	}
	if got == 0 {
		t.Error("acceptIPC never called Accept; the backoff assertion would be vacuous")
	}
}

func TestAcceptLoopsExitOnClosedListener(t *testing.T) {
	t.Run("sync", func(t *testing.T) {
		sd := &SyncDaemon{shutdownCh: make(chan struct{})}
		ln := &stuckListener{err: net.ErrClosed}
		done := make(chan struct{})
		go func() {
			defer close(done)
			sd.acceptIPC(ln)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("sync acceptIPC kept retrying a closed listener")
		}
	})

	t.Run("virtual", func(t *testing.T) {
		d := &Daemon{shutdownCh: make(chan struct{})}
		ln := &stuckListener{err: net.ErrClosed}
		done := make(chan struct{})
		go func() {
			defer close(done)
			d.acceptIPC(ln)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("virtual acceptIPC kept retrying a closed listener")
		}
	})
}
