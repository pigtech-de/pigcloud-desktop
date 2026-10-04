package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type capturedRequest struct {
	Method  string
	URL     *url.URL
	Header  http.Header
	Body    []byte
	CLIReq  CLIRequest
	CLIReqE error
}

func captureServer(t *testing.T) (*Client, *sync.Mutex, *[]capturedRequest, func(fn http.HandlerFunc)) {
	t.Helper()
	var mu sync.Mutex
	var reqs []capturedRequest
	respond := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":true}`)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cr := capturedRequest{Method: r.Method, URL: r.URL, Header: r.Header.Clone(), Body: body}
		cr.CLIReqE = json.Unmarshal(body, &cr.CLIReq)
		mu.Lock()
		reqs = append(reqs, cr)
		h := respond
		mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		h(w, r)
	}))
	t.Cleanup(srv.Close)

	set := func(fn http.HandlerFunc) {
		mu.Lock()
		defer mu.Unlock()
		respond = fn
		reqs = reqs[:0]
	}
	client := &Client{httpClient: srv.Client(), endpoint: srv.URL, apiKey: "test-key"}
	return client, &mu, &reqs, set
}

func jsonResponder(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}
}

func fastRetries(t *testing.T) {
	t.Helper()
	saved := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryDelays = saved })
}

func TestGetCliEndpointQueryJoining(t *testing.T) {
	c := &Client{endpoint: "https://x.test/actions.php"}
	if got := c.getCliEndpoint(); got != "https://x.test/actions.php?action=cli" {
		t.Errorf("plain endpoint: %q", got)
	}
	c.endpoint = "https://x.test/actions.php?env=dev"
	if got := c.getCliEndpoint(); got != "https://x.test/actions.php?env=dev&action=cli" {
		t.Errorf("endpoint with query: %q", got)
	}
}

func TestExecuteRequestShapingAndDecoding(t *testing.T) {
	client, mu, reqs, _ := captureServer(t)

	resp, err := client.Execute(context.Background(), "ls", map[string]string{"source": "/docs"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(*reqs))
	}
	r := (*reqs)[0]
	if r.Method != "POST" {
		t.Errorf("method = %s", r.Method)
	}
	if r.URL.Query().Get("action") != "cli" {
		t.Errorf("action query = %q", r.URL.RawQuery)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type = %q", got)
	}
	if got := r.Header.Get(HeaderAPIKey); got != "test-key" {
		t.Errorf("api key header = %q", got)
	}
	if got := r.Header.Get(HeaderCliClient); got != "pigcloud-cli/"+Version {
		t.Errorf("client header = %q", got)
	}
	if got := r.Header.Get(HeaderCliLang); got == "" {
		t.Error("language header missing")
	}
	if r.CLIReqE != nil || r.CLIReq.Command != "ls" || r.CLIReq.Options["source"] != "/docs" {
		t.Errorf("request body wrong: %+v (%v)", r.CLIReq, r.CLIReqE)
	}
	if !resp.Success || resp.StatusCode != 200 {
		t.Errorf("decoded resp: %+v", resp)
	}
	if len(resp.Raw) == 0 || !strings.Contains(string(resp.Raw), "success") {
		t.Error("Raw body not preserved")
	}
}

func TestExecuteDecodesTopLevelFields(t *testing.T) {
	client, _, _, set := captureServer(t)
	set(jsonResponder(200, `{"success":false,"message":"nope","messageKey":"cli.err","errorCode":"bad","cwd":"/x","extra":42}`))

	resp, err := client.Execute(context.Background(), "cd", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Success || resp.Message != "nope" || resp.MessageKey != "cli.err" || resp.ErrorCode != "bad" || resp.Cwd != "/x" {
		t.Errorf("fields lost in decode: %+v", resp)
	}
	var extra struct {
		Extra int `json:"extra"`
	}
	if json.Unmarshal(resp.Raw, &extra) != nil || extra.Extra != 42 {
		t.Error("command-specific field not reachable through Raw")
	}
}

func TestExecutePassesThroughParseableNon200(t *testing.T) {
	client, _, _, set := captureServer(t)
	set(jsonResponder(403, `{"success":false,"message":"forbidden"}`))

	resp, err := client.Execute(context.Background(), "ls", nil)
	if err != nil {
		t.Fatalf("parseable 403 should not error: %v", err)
	}
	if resp.StatusCode != 403 || resp.Success {
		t.Errorf("resp = %+v", resp)
	}
}

func TestExecuteEmptyAndMalformedBodies(t *testing.T) {
	fastRetries(t)
	client, mu, reqs, set := captureServer(t)

	set(jsonResponder(200, ``))
	if _, err := client.Execute(context.Background(), "ls", nil); err == nil || !strings.Contains(err.Error(), "empty response") {
		t.Errorf("empty body: %v", err)
	}
	mu.Lock()
	if len(*reqs) != 1 {
		t.Errorf("empty 200 body retried: %d requests", len(*reqs))
	}
	mu.Unlock()

	set(jsonResponder(200, `{"success":tru`))
	if _, err := client.Execute(context.Background(), "ls", nil); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("malformed body: %v", err)
	}

	set(jsonResponder(503, ``))
	if _, err := client.Execute(context.Background(), "ls", nil); err == nil {
		t.Error("empty 503 body should error")
	}
	mu.Lock()
	if len(*reqs) != 3 {
		t.Errorf("empty 503 body: %d attempts, want 3", len(*reqs))
	}
	mu.Unlock()
}

func TestExecuteRecoversAfterTransientFailure(t *testing.T) {
	fastRetries(t)
	client, mu, reqs, set := captureServer(t)

	set(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := len(*reqs)
		mu.Unlock()
		if n == 1 {
			w.WriteHeader(502)
			return
		}
		jsonResponder(200, `{"success":true,"cwd":"/after"}`)(w, r)
	})

	resp, err := client.Execute(context.Background(), "ls", nil)
	if err != nil || !resp.Success || resp.Cwd != "/after" {
		t.Fatalf("recovery failed: resp=%+v err=%v", resp, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 2 {
		t.Errorf("got %d attempts, want 2", len(*reqs))
	}
}

func TestDropAPIKeyOnHostChange(t *testing.T) {
	mk := func(host string) *http.Request {
		r, _ := http.NewRequest("GET", "https://"+host+"/p", nil)
		r.Header.Set(HeaderAPIKey, "secret")
		return r
	}

	next := mk("a.test")
	if err := dropAPIKeyOnHostChange(next, []*http.Request{mk("a.test")}); err != nil {
		t.Fatalf("same host: %v", err)
	}
	if next.Header.Get(HeaderAPIKey) != "secret" {
		t.Error("key dropped on same-host redirect")
	}

	next = mk("evil.test")
	if err := dropAPIKeyOnHostChange(next, []*http.Request{mk("a.test")}); err != nil {
		t.Fatalf("cross host: %v", err)
	}
	if next.Header.Get(HeaderAPIKey) != "" {
		t.Error("API key leaked across a host change")
	}

	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = mk("a.test")
	}
	if err := dropAPIKeyOnHostChange(mk("a.test"), via); err == nil {
		t.Error("10 redirects not refused")
	}
}

func TestRedirectStripsKeyCrossHostOnly(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}

	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got["cross"] = r.Header.Get(HeaderAPIKey)
		mu.Unlock()
		jsonResponder(200, `{"success":true}`)(w, r)
	}))
	t.Cleanup(inner.Close)

	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/hop"):
			http.Redirect(w, r, inner.URL+"/land", http.StatusTemporaryRedirect)
		case strings.HasPrefix(r.URL.Path, "/self"):
			http.Redirect(w, r, "/final?action=cli", http.StatusTemporaryRedirect)
		default:
			mu.Lock()
			got["same"] = r.Header.Get(HeaderAPIKey)
			mu.Unlock()
			jsonResponder(200, `{"success":true}`)(w, r)
		}
	}))
	t.Cleanup(outer.Close)

	mkClient := func(endpoint string) *Client {
		hc := outer.Client()
		hc.CheckRedirect = dropAPIKeyOnHostChange
		return &Client{httpClient: hc, endpoint: endpoint, apiKey: "secret"}
	}

	if _, err := mkClient(outer.URL+"/hop").Execute(context.Background(), "ls", nil); err != nil {
		t.Fatalf("cross-host redirect: %v", err)
	}
	if _, err := mkClient(outer.URL+"/self").Execute(context.Background(), "ls", nil); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got["cross"] != "" {
		t.Errorf("API key crossed hosts: %q", got["cross"])
	}
	if got["same"] != "secret" {
		t.Errorf("API key lost on same-host redirect: %q", got["same"])
	}
}

func TestParseDownloadMetadata(t *testing.T) {
	if r := parseDownloadMetadata(""); r == nil || r.E2EE {
		t.Errorf("empty header: %+v", r)
	}
	if r := parseDownloadMetadata("!!not-base64!!"); r == nil || r.SealedKey != "" {
		t.Errorf("bad base64: %+v", r)
	}
	if r := parseDownloadMetadata(base64.StdEncoding.EncodeToString([]byte("{broken"))); r == nil || r.SealedKey != "" {
		t.Errorf("bad json: %+v", r)
	}

	want := DownloadResult{
		E2EE: true, SealedKey: "sk", EncryptionMeta: "em",
		SignatureEd25519: "s1", SignatureMldsa: "s2",
		SigningPkEd25519: "p1", SigningPkMldsa: "p2",
		SignedBy:            "peer",
		TEESignatureEd25519: "t1", TEESignatureMldsa: "t2",
		TEESigningPkEd25519: "tp1", TEESigningPkMldsa: "tp2",
	}
	raw, _ := json.Marshal(DownloadPayload{DownloadResult: want})
	r := parseDownloadMetadata(base64.StdEncoding.EncodeToString(raw))
	if *r != want {
		t.Errorf("field mapping:\n got %+v\nwant %+v", r, want)
	}
}

func downloadMetaHeader(t *testing.T, p DownloadPayload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestDownloadWritesFileAndParsesMetadata(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	content := strings.Repeat("cipherbytes-", 4096)
	set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		w.Header().Set(HeaderCliMetadata, downloadMetaHeader(t, DownloadPayload{DownloadResult: DownloadResult{E2EE: true, SealedKey: "sk"}}))
		fmt.Fprint(w, content)
	})

	dir := t.TempDir()
	localPath := filepath.Join(dir, "out.bin")
	var lastReceived, lastTotal int64
	result, err := client.Download(context.Background(), "/f.bin", localPath, func(rec, tot int64) {
		lastReceived, lastTotal = rec, tot
	}, map[string]string{"version_hint": "7"})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !result.E2EE || result.SealedKey != "sk" {
		t.Errorf("metadata lost: %+v", result)
	}
	got, err := os.ReadFile(localPath)
	if err != nil || string(got) != content {
		t.Errorf("file content wrong (err=%v, %d bytes)", err, len(got))
	}
	if lastReceived != int64(len(content)) || lastTotal != int64(len(content)) {
		t.Errorf("progress: received=%d total=%d want %d", lastReceived, lastTotal, len(content))
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pigcloud-dl-") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	r := (*reqs)[0]
	if r.CLIReq.Command != "dl" || r.CLIReq.Options["source"] != "/f.bin" || r.CLIReq.Options["version_hint"] != "7" {
		t.Errorf("request shape: %+v", r.CLIReq)
	}
	if r.Header.Get("Accept") != "application/octet-stream" {
		t.Errorf("accept header = %q", r.Header.Get("Accept"))
	}
}

func TestDownloadMapsJSONRejectionToClassifiedAPIError(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(404, `{"success":false,"message":"no such file","errorCode":"not_found"}`))

	localPath := filepath.Join(t.TempDir(), "out.bin")
	_, err := client.Download(context.Background(), "/gone", localPath, nil)
	if err == nil {
		t.Fatal("404 download succeeded")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "not_found" || apiErr.Message != "no such file" {
		t.Errorf("APIError lost: %v", err)
	}
	if !IsPermanent(err) {
		t.Errorf("404 not permanent: %v", err)
	}
	if _, statErr := os.Stat(localPath); !os.IsNotExist(statErr) {
		t.Error("failed download left a file behind")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 {
		t.Errorf("permanent failure retried: %d requests", len(*reqs))
	}
}

func TestDownloadTreatsJSONBodyAt200AsRejection(t *testing.T) {
	client, _, _, set := captureServer(t)
	set(jsonResponder(200, `{"success":false,"message":"blocked"}`))

	_, err := client.Download(context.Background(), "/f", filepath.Join(t.TempDir(), "o"), nil)
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Errorf("in-band rejection not surfaced: %v", err)
	}
}

func TestDownloadRetriesTransient(t *testing.T) {
	fastRetries(t)
	client, mu, reqs, set := captureServer(t)
	set(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := len(*reqs)
		mu.Unlock()
		if n < 3 {
			jsonResponder(503, `{"success":false,"message":"busy"}`)(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, "data")
	})

	localPath := filepath.Join(t.TempDir(), "out.bin")
	if _, err := client.Download(context.Background(), "/f", localPath, nil); err != nil {
		t.Fatalf("download after transient failures: %v", err)
	}
	got, _ := os.ReadFile(localPath)
	if string(got) != "data" {
		t.Errorf("content = %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 3 {
		t.Errorf("attempts = %d, want 3", len(*reqs))
	}
}

func TestDownloadNonJSONErrorBody(t *testing.T) {
	client, _, _, set := captureServer(t)
	set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		fmt.Fprint(w, "<h1>Forbidden</h1>")
	})
	_, err := client.Download(context.Background(), "/f", filepath.Join(t.TempDir(), "o"), nil)
	if err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("non-JSON error body dropped: %v", err)
	}
}

func TestDownloadProxyRejectionIsLegible(t *testing.T) {
	fastRetries(t)
	client, _, _, set := captureServer(t)
	set(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(502)
		fmt.Fprint(w, "<html><head><title>502 Bad Gateway</title></head><body>"+
			"<center><h1>502 Bad Gateway</h1></center><hr><center>cloudflare</center></body></html>")
	})

	_, err := client.Download(context.Background(), "/f", filepath.Join(t.TempDir(), "o"), nil)
	if err == nil {
		t.Fatal("proxy 502 should fail the download")
	}
	msg := err.Error()
	if strings.Contains(msg, "<html") || strings.Contains(msg, "<center>") {
		t.Errorf("raw HTML reached the user: %q", msg)
	}
	if !strings.Contains(msg, "502") || !strings.Contains(msg, "Bad Gateway") {
		t.Errorf("error drops the status or the reason: %q", msg)
	}
	if !IsTransient(err) {
		t.Errorf("proxy 5xx should stay retryable: %v", err)
	}
}

func TestDownloadToMemory(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set(HeaderCliMetadata, downloadMetaHeader(t, DownloadPayload{DownloadResult: DownloadResult{E2EE: true, EncryptionMeta: "meta"}}))
		fmt.Fprint(w, "in-memory-bytes")
	})

	data, result, err := client.DownloadToMemory(context.Background(), "/f", map[string]string{"k": "v"})
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(data) != "in-memory-bytes" || !result.E2EE || result.EncryptionMeta != "meta" {
		t.Errorf("data=%q result=%+v", data, result)
	}
	mu.Lock()
	if (*reqs)[0].CLIReq.Options["k"] != "v" {
		t.Errorf("extra opts dropped: %+v", (*reqs)[0].CLIReq)
	}
	mu.Unlock()

	set(jsonResponder(404, `{"success":false,"message":"gone"}`))
	if _, _, err := client.DownloadToMemory(context.Background(), "/f"); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("404: %v", err)
	}
}

func TestDownloadCommandStreamsGenericCommand(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		fmt.Fprint(w, "version-42-bytes")
	})

	localPath := filepath.Join(t.TempDir(), "v42.bin")
	if _, err := client.DownloadCommand(context.Background(), "vh", map[string]string{"version_id": "42"}, localPath, nil); err != nil {
		t.Fatalf("download command: %v", err)
	}
	got, _ := os.ReadFile(localPath)
	if string(got) != "version-42-bytes" {
		t.Errorf("content = %q", got)
	}
	mu.Lock()
	r := (*reqs)[0]
	mu.Unlock()
	if r.CLIReq.Command != "vh" || r.CLIReq.Options["version_id"] != "42" {
		t.Errorf("request shape: %+v", r.CLIReq)
	}

	set(jsonResponder(500, `{"success":false,"message":"boom"}`))
	fastRetries(t)
	if _, err := client.DownloadCommand(context.Background(), "vh", nil, localPath, nil); err == nil {
		t.Error("500 download command succeeded")
	}
}

func TestValidateSendsRootListing(t *testing.T) {
	client, mu, reqs, _ := captureServer(t)
	if _, err := client.Validate(context.Background()); err != nil {
		t.Fatalf("validate: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	r := (*reqs)[0]
	if r.CLIReq.Command != "ls" || r.CLIReq.Options["source"] != "/" {
		t.Errorf("validate request: %+v", r.CLIReq)
	}
}

func TestShareRecipientsForNode(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(200, `{"success":true,"recipients":[{"user_id":7,"username":"anna","public_key":"pk","public_key_kyber":"pkk"}]}`))

	res, err := client.ShareRecipientsForNode(context.Background(), "ab12")
	if err != nil {
		t.Fatalf("share recipients: %v", err)
	}
	if !res.Success || len(res.Recipients) != 1 || res.Recipients[0].Username != "anna" || res.Recipients[0].UserID != 7 {
		t.Errorf("decoded: %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	r := (*reqs)[0]
	if r.URL.Query().Get("action") != "share-recipients-for-node" {
		t.Errorf("action = %q", r.URL.RawQuery)
	}
	var body map[string]string
	if json.Unmarshal(r.Body, &body) != nil || body["nodeId"] != "ab12" {
		t.Errorf("body = %s", r.Body)
	}
	if r.Header.Get(HeaderAPIKey) != "test-key" {
		t.Error("postAction lost the API key")
	}
}

func TestStoreShareDisplayNames(t *testing.T) {
	client, mu, reqs, set := captureServer(t)

	if err := client.StoreShareDisplayNames(context.Background(), "anna", "", nil); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	mu.Lock()
	if len(*reqs) != 0 {
		t.Errorf("empty list sent %d requests", len(*reqs))
	}
	mu.Unlock()

	names := []SealedNameEntry{{NodeID: "n1", SealedDisplayName: "sealed1"}}
	if err := client.StoreShareDisplayNames(context.Background(), "anna", "", names); err != nil {
		t.Fatalf("store: %v", err)
	}
	mu.Lock()
	r := (*reqs)[0]
	mu.Unlock()
	if r.URL.Query().Get("action") != "store-share-display-names" {
		t.Errorf("action = %q", r.URL.RawQuery)
	}
	var body struct {
		RecipientUsername string            `json:"recipientUsername"`
		SealedNames       []SealedNameEntry `json:"sealedNames"`
	}
	if json.Unmarshal(r.Body, &body) != nil || body.RecipientUsername != "anna" ||
		len(body.SealedNames) != 1 || body.SealedNames[0].NodeID != "n1" {
		t.Errorf("body = %s", r.Body)
	}

	set(jsonResponder(400, `{"success":false}`))
	if err := client.StoreShareDisplayNames(context.Background(), "anna", "", names); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("400 not surfaced: %v", err)
	}

	set(jsonResponder(200, `{"success":false,"error":"not_friends"}`))
	if err := client.StoreShareDisplayNames(context.Background(), "anna", "", names); err == nil || !strings.Contains(err.Error(), "not_friends") {
		t.Errorf("a 200 refusal must fail the store: %v", err)
	}
}

func TestStoreShareDisplayNamesAnchorsEveryChunk(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(200, `{"success":true,"stored":1}`))

	names := make([]SealedNameEntry, ShareRowBatchMax+1)
	for i := range names {
		names[i] = SealedNameEntry{NodeID: "n", SealedDisplayName: "s"}
	}
	if err := client.StoreShareDisplayNames(context.Background(), "anna", "ab12", names); err != nil {
		t.Fatalf("store: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 2 {
		t.Fatalf("sent %d requests, want 2", len(*reqs))
	}
	for i, r := range *reqs {
		var body struct {
			ShareAnchorID string `json:"shareAnchorId"`
		}
		if json.Unmarshal(r.Body, &body) != nil || body.ShareAnchorID != "ab12" {
			t.Errorf("chunk %d lost the share anchor: %s", i, r.Body)
		}
	}
}

func TestStoreShareContentKeysChunksToTheServerCap(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(200, `{"success":true,"stored":1}`))

	keys := make([]SealedKeyEntry, ShareRowBatchMax+1000)
	for i := range keys {
		keys[i] = SealedKeyEntry{NodeID: "n", SealedKey: "k"}
	}
	if err := client.StoreShareContentKeys(context.Background(), "anna", keys); err != nil {
		t.Fatalf("store: %v", err)
	}
	mu.Lock()
	var sizes []int
	for _, r := range *reqs {
		var body struct {
			SealedKeys []SealedKeyEntry `json:"sealedKeys"`
		}
		if r.URL.Query().Get("action") != "store-share-content-keys" || json.Unmarshal(r.Body, &body) != nil {
			t.Fatalf("request = %s %s", r.URL.RawQuery, r.Body)
		}
		sizes = append(sizes, len(body.SealedKeys))
	}
	*reqs = nil
	mu.Unlock()
	if len(sizes) != 2 || sizes[0] != ShareRowBatchMax || sizes[1] != 1000 {
		t.Errorf("chunk sizes = %v, want [%d 1000]", sizes, ShareRowBatchMax)
	}

	set(jsonResponder(413, `{"success":false,"error":"payload_too_large"}`))
	if err := client.StoreShareContentKeys(context.Background(), "anna", keys); err == nil {
		t.Fatal("a refused chunk must fail the store")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 {
		t.Errorf("sent %d requests after a refused chunk, want 1", len(*reqs))
	}
}

func TestDeviceAuthorize(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(200, `{"success":true,"device_code":"dc","user_code":"AAAA-1111","verification_uri":"https://x/activate","interval":5,"expires_in":600}`))

	res, err := client.DeviceAuthorize(context.Background(), "my-laptop", "ephkey-b64", false)
	if err != nil {
		t.Fatalf("device authorize: %v", err)
	}
	if !res.Success || res.DeviceCode != "dc" || res.UserCode != "AAAA-1111" || res.Interval != 5 {
		t.Errorf("decoded: %+v", res)
	}
	mu.Lock()
	r := (*reqs)[0]
	mu.Unlock()
	if r.URL.Query().Get("action") != "device-authorize" {
		t.Errorf("action = %q", r.URL.RawQuery)
	}
	var body map[string]string
	if json.Unmarshal(r.Body, &body) != nil || body["device_label"] != "my-laptop" || body["eph_pubkey"] != "ephkey-b64" {
		t.Errorf("body = %s", r.Body)
	}
	if _, present := body["background"]; present {
		t.Error("a CLI login must not claim the background scope")
	}

	set(jsonResponder(200, `{"success":true}`))
	if _, err := client.DeviceAuthorize(context.Background(), "lbl", "", false); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	r = (*reqs)[0]
	mu.Unlock()
	body = nil
	if json.Unmarshal(r.Body, &body) != nil {
		t.Fatalf("body = %s", r.Body)
	}
	if _, present := body["eph_pubkey"]; present {
		t.Error("empty eph_pubkey still sent")
	}

	set(jsonResponder(400, `{"success":false,"error":"invalid_request"}`))
	res, err = client.DeviceAuthorize(context.Background(), "lbl", "", false)
	if err != nil || res == nil || res.Success || res.Error != "invalid_request" {
		t.Errorf("parseable 400: res=%+v err=%v", res, err)
	}

	set(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	})
	if _, err := client.DeviceAuthorize(context.Background(), "lbl", "", false); err == nil {
		t.Error("empty 500 body should error")
	}

	set(jsonResponder(200, `{"success":true}`))
	if _, err := client.DeviceAuthorize(context.Background(), "phone", "eph", true); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	r = (*reqs)[0]
	mu.Unlock()
	body = nil
	if json.Unmarshal(r.Body, &body) != nil || body["background"] != "1" {
		t.Errorf("background flag missing: %s", r.Body)
	}
}

func TestDeviceTokenPollStates(t *testing.T) {
	client, mu, reqs, set := captureServer(t)

	set(jsonResponder(400, `{"success":false,"error":"authorization_pending"}`))
	res, err := client.DeviceToken(context.Background(), "dc-1")
	if err != nil || res == nil || res.Success || res.Error != "authorization_pending" {
		t.Errorf("pending poll: res=%+v err=%v", res, err)
	}
	mu.Lock()
	r := (*reqs)[0]
	mu.Unlock()
	if r.URL.Query().Get("action") != "device-token" {
		t.Errorf("action = %q", r.URL.RawQuery)
	}
	var body map[string]string
	if json.Unmarshal(r.Body, &body) != nil || body["device_code"] != "dc-1" {
		t.Errorf("body = %s", r.Body)
	}

	set(jsonResponder(200, `{"success":true,"api_key":"minted","sealed_key":"blob"}`))
	res, err = client.DeviceToken(context.Background(), "dc-1")
	if err != nil || !res.Success || res.APIKey != "minted" || res.SealedKey != "blob" {
		t.Errorf("approved poll: res=%+v err=%v", res, err)
	}
}

func fastAttestationRetries(t *testing.T) {
	t.Helper()
	saved := TeeAttestationRetryDelays
	TeeAttestationRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { TeeAttestationRetryDelays = saved })
}

func TestFetchTeeAttestationWaitsOutAVerifyBusy503(t *testing.T) {
	fastAttestationRetries(t)
	client, mu, reqs, set := captureServer(t)
	var calls atomic.Int32
	set(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"success":false,"error":"api_key_verify_busy"}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"enabled":true,"available":true,"attestation":{"enclave_public_key":"epk"}}`)
	})

	start := time.Now()
	res, err := client.FetchTeeAttestation(context.Background())
	if err != nil {
		t.Fatalf("a single verify-busy 503 was not retried: %v", err)
	}
	if res.Attestation.EnclavePublicKey != "epk" {
		t.Errorf("decoded the wrong reply: %+v", res)
	}
	if waited := time.Since(start); waited < 900*time.Millisecond {
		t.Errorf("retried after %s, before the served Retry-After of 1s", waited)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 2 {
		t.Errorf("requests = %d, want the refused one plus one retry", len(*reqs))
	}
}

func TestFetchTeeAttestationNeverReturnsAFailureBodyAsAnAnswer(t *testing.T) {
	fastAttestationRetries(t)
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"verify busy 503", 503, `{"success":false,"error":"api_key_verify_busy"}`},
		{"scanner unavailable 502", 502, `{"success":false,"message":"TEE scanner unavailable"}`},
		{"cloudflare html 520", 520, `<html>origin error</html>`},
		{"success false at 200", 200, `{"success":false}`},
		{"unreadable 200", 200, `not json`},
		{"daemon busy reply relayed at 200", 200, `{"success":true,"enabled":true,"available":true,"attestation":{"verdict":"error","reason":"scanner_busy","busy":true,"retry_after_ms":1}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, mu, reqs, set := captureServer(t)
			set(jsonResponder(tc.status, tc.body))
			res, err := client.FetchTeeAttestation(context.Background())
			if err == nil {
				t.Fatalf("a failure reply came back as an attestation: %+v", res)
			}
			if !IsTransient(err) {
				t.Errorf("error %v is not transient, so callers would not retry it", err)
			}
			if !strings.Contains(err.Error(), "tee_attestation_unanswered") {
				t.Errorf("error = %q, want it to say the probe went unanswered", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if want := len(TeeAttestationRetryDelays) + 1; len(*reqs) != want {
				t.Errorf("requests = %d, want %d (every transient failure retried)", len(*reqs), want)
			}
		})
	}
}

func TestFetchTeeAttestationDoesNotRetryAnAuthRefusal(t *testing.T) {
	fastAttestationRetries(t)
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(401, `{"success":false,"error":"invalid_api_key"}`))
	if _, err := client.FetchTeeAttestation(context.Background()); !IsPermanent(err) {
		t.Fatalf("a 401 should be permanent, got %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*reqs) != 1 {
		t.Errorf("requests = %d, a revoked key was re-sent", len(*reqs))
	}
}

func TestFetchTeeAttestation(t *testing.T) {
	fastAttestationRetries(t)
	client, mu, reqs, set := captureServer(t)
	set(jsonResponder(200, `{"success":true,"enabled":true,"available":true,"attestation":{"enclave_public_key":"epk","attestation_mode":"epid","verification_status":"trusted"}}`))

	res, err := client.FetchTeeAttestation(context.Background())
	if err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if !res.Success || !res.Available || res.Attestation.EnclavePublicKey != "epk" || res.Attestation.VerificationStatus != "trusted" {
		t.Errorf("decoded: %+v", res)
	}
	mu.Lock()
	r := (*reqs)[0]
	mu.Unlock()
	if r.Method != "GET" || r.URL.Query().Get("action") != "tee-attestation" {
		t.Errorf("request: %s %s", r.Method, r.URL)
	}
	if r.Header.Get(HeaderAPIKey) != "test-key" {
		t.Error("attestation request lost the API key")
	}

	set(jsonResponder(200, `not json`))
	if _, err := client.FetchTeeAttestation(context.Background()); err == nil {
		t.Error("malformed attestation body accepted")
	}
}

func TestProgressReader(t *testing.T) {
	var calls []int64
	pr := &progressReader{
		reader:   strings.NewReader("0123456789"),
		total:    10,
		progress: func(sent, total int64) { calls = append(calls, sent) },
	}
	buf := make([]byte, 4)
	var readTotal int
	for {
		n, err := pr.Read(buf)
		readTotal += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if readTotal != 10 {
		t.Errorf("read %d bytes", readTotal)
	}
	if len(calls) == 0 || calls[len(calls)-1] != 10 {
		t.Errorf("progress calls: %v", calls)
	}
	for i := 1; i < len(calls); i++ {
		if calls[i] <= calls[i-1] {
			t.Errorf("sent went backwards: %v", calls)
		}
	}
}

func TestEveryRequestBuilderCarriesTheClientHeaders(t *testing.T) {
	client, mu, reqs, set := captureServer(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(src, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}

	savedBody, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 3, 4
	t.Cleanup(func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedBody, savedChunk })

	set(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("action") == "auth-csrf":
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "s", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true,"csrfToken":"c"}`)
		case strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data"):
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true,"nodeId":"n"}`)
		case r.Header.Get("Accept") == "application/octet-stream":
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, "bytes")
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true}`)
		}
	})

	ctx := context.Background()
	builders := []struct {
		name string
		call func() error
	}{
		{"Execute", func() error { _, err := client.Execute(ctx, "ls", nil); return err }},
		{"uploadWholeBody", func() error {
			_, err := client.uploadWholeBody(ctx, src, nil, map[string]string{"source": "f.bin", "target": "/d"})
			return err
		}},
		{"streamDownload", func() error {
			_, err := client.Download(ctx, "/d/f.bin", filepath.Join(dir, "out.bin"), nil)
			return err
		}},
		{"postAction", func() error { _, err := client.ShareRecipientsForNode(ctx, "ab"); return err }},
		{"uploadSession+postUploadForm", func() error {
			_, err := client.uploadChunked(ctx, src, "/d", 7, nil, map[string]string{"source": "f.bin"})
			return err
		}},
		{"FetchTeeAttestation", func() error { _, err := client.FetchTeeAttestation(ctx); return err }},
	}

	for _, b := range builders {
		mu.Lock()
		before := len(*reqs)
		mu.Unlock()
		if err := b.call(); err != nil {
			t.Fatalf("%s: %v", b.name, err)
		}
		mu.Lock()
		sent := append([]capturedRequest(nil), (*reqs)[before:]...)
		mu.Unlock()
		if len(sent) == 0 {
			t.Fatalf("%s sent no request", b.name)
		}
		for i, r := range sent {
			if got := r.Header.Get(HeaderAPIKey); got != "test-key" {
				t.Errorf("%s request %d: %s = %q", b.name, i, HeaderAPIKey, got)
			}
			if got := r.Header.Get(HeaderCliClient); got != "pigcloud-cli/"+Version {
				t.Errorf("%s request %d: %s = %q", b.name, i, HeaderCliClient, got)
			}
			if r.Header.Get(HeaderCliLang) == "" {
				t.Errorf("%s request %d: %s missing", b.name, i, HeaderCliLang)
			}
		}
	}
}

func TestRequestWallBoundsJSONBuildersButNotStreams(t *testing.T) {
	fastRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "application/octet-stream" {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(200)
			for range 20 {
				io.WriteString(w, "x")
				w.(http.Flusher).Flush()
				time.Sleep(10 * time.Millisecond)
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true}`)
	}))
	t.Cleanup(srv.Close)

	saved := TransferStallTimeout
	TransferStallTimeout = 2 * time.Second
	t.Cleanup(func() { TransferStallTimeout = saved })

	client := &Client{httpClient: &http.Client{}, timeout: 40 * time.Millisecond, endpoint: srv.URL, apiKey: "k"}

	if _, err := client.Execute(context.Background(), "ls", nil); err == nil {
		t.Error("a JSON call past the wall must fail; the wall is what catches a dead server")
	}

	out := filepath.Join(t.TempDir(), "slow.bin")
	if _, err := client.Download(context.Background(), "/slow.bin", out, nil); err != nil {
		t.Fatalf("slow but healthy download killed by the wall: %v", err)
	}
	if data, _ := os.ReadFile(out); len(data) != 20 {
		t.Errorf("downloaded %d bytes, want 20", len(data))
	}
}

func TestStalledDownloadIsCutAndClassifiedTransient(t *testing.T) {
	fastRetries(t)
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		io.WriteString(w, "start")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-stop:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(stop) })

	saved := TransferStallTimeout
	TransferStallTimeout = 100 * time.Millisecond
	t.Cleanup(func() { TransferStallTimeout = saved })

	client := &Client{httpClient: &http.Client{}, endpoint: srv.URL, apiKey: "k"}

	done := make(chan error, 1)
	go func() {
		_, err := client.Download(context.Background(), "/dead.bin", filepath.Join(t.TempDir(), "dead.bin"), nil)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errTransferStalled) {
			t.Fatalf("stalled download error = %v, want a stall", err)
		}
		if !IsTransient(err) {
			t.Error("a stalled link must stay retryable, not read as caller cancellation")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled download never returned: nothing bounds inactivity")
	}
}

func TestNewClientPutsNoWallClockOnTheHTTPClient(t *testing.T) {
	for name, c := range map[string]*Client{"NewClient": NewClient(), "NewClientWithKey": NewClientWithKey("k")} {
		if c.httpClient.Timeout != 0 {
			t.Errorf("%s: http.Client.Timeout = %s, want 0 (the wall belongs on requestCtx)", name, c.httpClient.Timeout)
		}
		if c.timeout <= 0 {
			t.Errorf("%s: no per-attempt wall left for the JSON builders", name)
		}
	}
}

func TestProductionTransportsNegotiateHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"proto":%q}`, r.Proto)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	for name, tr := range map[string]*http.Transport{
		"default":    newTransport(10, 90*time.Second, ClientTimeout),
		"validation": newTransport(2, 30*time.Second, KeyValidationTimeout),
	} {
		tr.TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Proto != "HTTP/2.0" {
			t.Errorf("%s transport negotiated %s, want HTTP/2.0 (server saw %s)", name, resp.Proto, body)
		}
	}
}

func TestRefusedDownloadBodyIsBounded(t *testing.T) {
	fastRetries(t)
	saved := TransferStallTimeout
	TransferStallTimeout = 200 * time.Millisecond
	t.Cleanup(func() { TransferStallTimeout = saved })

	stop := make(chan struct{})
	for _, status := range []int{200, 502} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			io.WriteString(w, `{"suc`)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-stop:
			case <-time.After(30 * time.Second):
			}
		}))
		client := &Client{httpClient: &http.Client{}, endpoint: srv.URL, apiKey: "k"}

		done := make(chan error, 1)
		go func() {
			_, err := client.Download(context.Background(), "/x", filepath.Join(t.TempDir(), "x"), nil)
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("status %d: refusal accepted", status)
			} else if !errors.Is(err, errTransferStalled) {
				t.Errorf("status %d: want a stall, got %v", status, err)
			}
		case <-time.After(20 * time.Second):
			t.Errorf("status %d: a refusal body that never arrives never returned", status)
		}
		srv.Close()
	}
	close(stop)
}

func TestShareInboxEntryDeclaresNoFieldNothingFills(t *testing.T) {
	fillers := map[string]string{
		"owner":             "sr inbox payload",
		"node_id":           "sr inbox payload",
		"e2ee_display_name": "sr inbox payload",
		"permission":        "sr inbox payload",
		"name":              "runShareInbox, decrypted from e2ee_display_name",
	}

	var payload ShareInboxPayload
	body := `{"shares":[{"owner":"ada","node_id":"ab12cd","e2ee_display_name":"c2VhbGVk","permission":"read"}]}`
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("decode inbox payload: %v", err)
	}
	if len(payload.Shares) != 1 {
		t.Fatalf("shares = %d, want 1", len(payload.Shares))
	}
	entry := reflect.ValueOf(payload.Shares[0])

	declared := map[string]bool{}
	for i := 0; i < entry.NumField(); i++ {
		field := entry.Type().Field(i)
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		declared[tag] = true
		filler, known := fillers[tag]
		if !known {
			t.Errorf("ShareInboxEntry.%s (json %q) has no filler: SrCommand::executeInbox does not emit it and "+
				"no client step sets it, so it stays an empty string wherever it is rendered", field.Name, tag)
			continue
		}
		if filler == "sr inbox payload" && entry.Field(i).IsZero() {
			t.Errorf("ShareInboxEntry.%s is listed as server-sent but decoded empty", field.Name)
		}
	}
	for tag := range fillers {
		if !declared[tag] {
			t.Errorf("json field %q is listed here but gone from ShareInboxEntry", tag)
		}
	}
}
