package daemon

import (
	"testing"
	"time"
)

func TestMutationGateRunHoldsTheLatchWhileItRuns(t *testing.T) {
	var g mutationGate
	closed := make(chan struct{})

	ran := g.run(func() {
		go func() {
			g.close()
			close(closed)
		}()
		select {
		case <-closed:
			t.Error("a shutdown closed the gate while services were still starting; it can then " +
				"stop a service that has not started yet and leave the rest running on a closed store")
		case <-time.After(50 * time.Millisecond):
		}
	})

	if !ran {
		t.Fatal("run refused an open gate")
	}
	<-closed
	if g.run(func() { t.Error("a closed gate still ran its callback") }) {
		t.Error("run reported success on a closed gate; the caller then treats a shut-down daemon " +
			"as one whose services are up")
	}
	if g.begin() {
		t.Error("a closed gate still admitted a mutating handler")
	}
}

func TestMutationGateDrainWaitsForHandlersThatGotIn(t *testing.T) {
	var g mutationGate
	if !g.begin() {
		t.Fatal("an open gate refused a handler")
	}

	drained := make(chan struct{})
	go func() {
		g.close()
		g.drain("test daemon")
		close(drained)
	}()

	select {
	case <-drained:
		t.Fatal("drain returned while a mutating handler was still in flight; teardown then closes " +
			"the DB under a resolve that has already moved the user's file")
	case <-time.After(50 * time.Millisecond):
	}

	g.end()
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("drain never returned after the last handler finished")
	}
}
