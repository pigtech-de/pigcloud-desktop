package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestChunkFinalizerPreservesOnlyAValidCommittedETag(t *testing.T) {
	for _, etag := range []string{strings.Repeat("a", 64), "", "not-a-version"} {
		t.Run(etag, func(t *testing.T) {
			client, server := newEdgeCappedServer(t, 0)
			server.finalizeBody = `{"success":true,"nodeId":"abc123","etag":"` + etag + `","private_extra":"must-not-escape"}`
			session, err := client.uploadSession(context.Background(), false)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.finalizeChunkedUpload(context.Background(), session, "/Photos", "test-chunk", 1, 3, map[string]string{"source": "photo.jpg"})
			if err != nil || response == nil || !response.Success {
				t.Fatalf("actual chunk finalization failed: %+v, %v", response, err)
			}
			var payload UploadPayload
			if err := json.Unmarshal(response.Raw, &payload); err != nil {
				t.Fatal(err)
			}
			want := ""
			if len(etag) == 64 {
				want = etag
			}
			if payload.ETag != want {
				t.Fatalf("committed upload ETag was dropped between finalize JSON and api.Response.Raw: got %q want %q, raw=%s", payload.ETag, want, response.Raw)
			}
			server.mu.Lock()
			calls := server.finalizeCalls
			server.mu.Unlock()
			if payload.StoredPath != "/Photos/photo.jpg" || payload.NodeID != "abc123" || calls != 1 {
				t.Fatalf("finalization receipt was not exercised coherently: %+v, calls=%d", payload, calls)
			}
			if strings.Contains(string(response.Raw), "private_extra") || strings.Contains(string(response.Raw), "must-not-escape") {
				t.Fatal("unrecognized server metadata escaped the receipt projection")
			}
		})
	}
}
