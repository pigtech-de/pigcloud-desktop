package agent

import (
	"bytes"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

type flakyListener struct {
	net.Listener
	mu        sync.Mutex
	errs      []error
	once      sync.Once
	delegated chan struct{}
}

func newFlakyListener(t *testing.T, errs ...error) *flakyListener {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	return &flakyListener{Listener: base, errs: errs, delegated: make(chan struct{})}
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, err
	}
	l.mu.Unlock()
	l.once.Do(func() { close(l.delegated) })
	return l.Listener.Accept()
}

func transientAcceptErr() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: syscall.ECONNABORTED}
}

func TestServeSurvivesATransientAcceptError(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	wantPriv := keys.PrivateKey
	wantSeed := append([]byte(nil), keys.KyberSeed...)
	wantName := append([]byte(nil), keys.NameKey...)

	ln := newFlakyListener(t, transientAcceptErr())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = serveListener(ln, keys, 30*time.Second)
	}()
	t.Cleanup(func() {
		_ = Shutdown()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("agent goroutine outlived the test; listener leaked")
		}
	})

	select {
	case <-ln.delegated:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop never called Accept again after one ECONNABORTED; " +
			"it read a transient error as a closed listener and tore the agent down mid-TTL")
	}

	if info := ReadAgentFile(); info == nil {
		t.Fatal("agent.json was deleted after a transient accept error; every later command re-prompts for the passphrase")
	}

	live := RequestKeys()
	if live == nil {
		t.Fatal("agent stopped serving keys after a transient accept error")
	}
	if live.PrivateKey != wantPriv {
		t.Error("agent served the wrong private key after a transient accept error")
	}
	if !bytes.Equal(live.KyberSeed, wantSeed) {
		t.Error("agent served the wrong ML-KEM seed after a transient accept error")
	}
	if !bytes.Equal(live.NameKey, wantName) {
		t.Error("agent served the wrong name key after a transient accept error")
	}

	if keys.PrivateKey == ([32]byte{}) {
		t.Error("x25519 private key was wiped by a transient accept error")
	}
}

func TestServeSurvivesRepeatedTransientAcceptErrors(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	ln := newFlakyListener(t,
		transientAcceptErr(),
		&net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE},
		transientAcceptErr(),
	)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = serveListener(ln, keys, 30*time.Second)
	}()
	t.Cleanup(func() {
		_ = Shutdown()
		<-done
	})

	select {
	case <-ln.delegated:
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop gave up during a transient error burst instead of backing off and retrying")
	}

	if RequestKeys() == nil {
		t.Fatal("agent stopped serving keys after a transient error burst")
	}
}
