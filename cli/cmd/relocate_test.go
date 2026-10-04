package cmd

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestCopyAndMovePropagateNamesAtTheLandedPath(t *testing.T) {
	ts := httptest.NewServer(&recordingUploadServer{})
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	orig := propagateSubtreeNames
	t.Cleanup(func() { propagateSubtreeNames = orig })
	for name, run := range map[string]func(string, string){"cp": runCopy, "mv": runMv} {
		var got []string
		propagateSubtreeNames = func(_ context.Context, path string, _ func()) { got = append(got, path) }
		run("/Docs/report.pdf", "/Archive/")
		if len(got) != 1 || got[0] != "/Archive/report.pdf" {
			t.Errorf("%s propagated names at %v, want [/Archive/report.pdf]", name, got)
		}
	}
}
