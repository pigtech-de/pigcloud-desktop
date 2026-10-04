package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"pigcloud/internal/config"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type webUploadSession struct {
	client *http.Client
	csrf   string
}

const chunkUploadRetries = 3

var rateLimitWait = RateLimitDelay

type webUploadResult struct {
	Success      bool         `json:"success"`
	Error        string       `json:"error"`
	ErrorCode    string       `json:"errorCode"`
	NodeID       string       `json:"nodeId"`
	ETag         string       `json:"etag,omitempty"`
	Storage      StorageState `json:"storage"`
	RetryAfterMs int          `json:"retryAfterMs"`
	Raw          []byte       `json:"-"`
}

type scanPendingError struct {
	RetryAfter time.Duration
}

func (e *scanPendingError) Error() string {
	return "upload accepted, security scan still running"
}

var scanPendingMaxWait = 15 * time.Minute

var scanPendingDefaultWait = 2 * time.Second

const scanBudgetMaxWaits = 2

func scannerShedWait(err error) (time.Duration, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != UploadCodeScannerBusy {
		return 0, false
	}
	if wait := RetryAfterHint(err); wait > 0 {
		return wait, true
	}
	return scanPendingDefaultWait, true
}

func scanPendingWait(resp *http.Response, result *webUploadResult) time.Duration {
	if result.RetryAfterMs > 0 {
		return time.Duration(result.RetryAfterMs) * time.Millisecond
	}
	if wait := retryAfterHeader(resp); wait > 0 {
		return wait
	}
	return scanPendingDefaultWait
}

func (c *Client) setCommonHeaders(req *http.Request) {
	req.Header.Set(HeaderAPIKey, c.apiKey)
	req.Header.Set(HeaderCliClient, "pigcloud-cli/"+Version)
	req.Header.Set(HeaderCliLang, config.GetLanguage())
}

func (c *Client) actionEndpoint(action string) string {
	if strings.Contains(c.endpoint, "?") {
		return c.endpoint + "&action=" + action
	}
	return c.endpoint + "?action=" + action
}

func (c *Client) uploadSession(ctx context.Context, refresh bool) (*webUploadSession, error) {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	if c.session != nil && !refresh {
		return c.session, nil
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	httpClient := &http.Client{
		Timeout:       c.httpClient.Timeout,
		Transport:     c.httpClient.Transport,
		CheckRedirect: c.httpClient.CheckRedirect,
		Jar:           jar,
	}

	sessionCtx, cancel := c.requestCtx(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(sessionCtx, "GET", c.actionEndpoint("auth-csrf"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	c.setCommonHeaders(req)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to open an upload session: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, ResponseSizeLimit))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	var issued struct {
		Success   bool   `json:"success"`
		CsrfToken string `json:"csrfToken"`
	}
	if err := json.Unmarshal(body, &issued); err != nil {
		return nil, statusError(resp, rejectionError(resp.StatusCode, body))
	}
	if !issued.Success || issued.CsrfToken == "" {
		return nil, statusError(resp, fmt.Errorf("server issued no upload token (status %d)", resp.StatusCode))
	}
	c.session = &webUploadSession{client: httpClient, csrf: issued.CsrfToken}
	return c.session, nil
}

func newChunkSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to mint chunk upload id: %w", err)
	}
	return "cli-" + hex.EncodeToString(b[:]), nil
}

var webUploadFields = map[string]string{
	"sealed_key":             "e2ee_sealed_key",
	"encryption_meta":        "e2ee_encryption_meta",
	"tee_sealed_key":         "e2ee_tee_sealed_key",
	"plaintext_hmac":         "e2ee_plaintext_hmac",
	"e2ee_display_name":      "e2ee_display_name",
	"e2ee_path_token":        "e2ee_path_token",
	"path_tokens":            "path_tokens",
	"path_tokens_legacy":     "path_tokens_legacy",
	"signature_ed25519":      "signature_ed25519",
	"signature_mldsa":        "signature_mldsa",
	"signing_pk_ed25519":     "signing_pk_ed25519",
	"signing_pk_mldsa":       "signing_pk_mldsa",
	"source_mtime":           "source_mtime",
	"captured_at":            "captured_at",
	"upload_idempotency_key": "upload_idempotency_key",
}

func UploadIsChunked(size int64) bool {
	return size > uploadSingleBodyMaxBytes
}

func (c *Client) uploadChunked(ctx context.Context, localPath, remotePath string, size int64, progress func(sent, total int64), options map[string]string) (*Response, error) {
	session, err := c.uploadSession(ctx, false)
	if err != nil {
		return nil, err
	}
	chunkID, err := newChunkSessionID()
	if err != nil {
		return nil, err
	}

	chunkSize := max(uploadChunkSize, 1)
	totalChunks := max(int((size+chunkSize-1)/chunkSize), 1)
	var sent int64
	for index := range totalChunks {
		offset := int64(index) * chunkSize
		length := chunkSize
		if remaining := size - offset; remaining < length {
			length = remaining
		}
		base := sent
		part := uploadChunkRequest{
			localPath:   localPath,
			remotePath:  remotePath,
			chunkID:     chunkID,
			index:       index,
			totalChunks: totalChunks,
			offset:      offset,
			length:      length,
			totalSize:   size,
			options:     options,
		}
		put := func() (*webUploadResult, int, error) {
			return c.putUploadChunk(ctx, session, part, func(chunkSent int64) {
				if progress == nil {
					return
				}
				if chunkSent > length {
					chunkSent = length
				}
				progress(base+chunkSent, size)
			})
		}
		_, err := withUploadRetry(ctx, put)
		if err != nil && index == 0 && IsPermanent(err) {
			if session, err = c.uploadSession(ctx, true); err != nil {
				return nil, err
			}
			_, err = withUploadRetry(ctx, put)
		}
		if err != nil {
			return nil, fmt.Errorf("chunk %d/%d: %w", index+1, totalChunks, err)
		}
		sent += length
		if progress != nil {
			progress(sent, size)
		}
	}

	return c.finalizeChunkedUpload(ctx, session, remotePath, chunkID, totalChunks, size, options)
}

type uploadChunkRequest struct {
	localPath   string
	remotePath  string
	chunkID     string
	index       int
	totalChunks int
	offset      int64
	length      int64
	totalSize   int64
	options     map[string]string
}

func (c *Client) putUploadChunk(ctx context.Context, session *webUploadSession, part uploadChunkRequest, progress func(sent int64)) (*webUploadResult, int, error) {
	originalName := part.options["source"]
	if part.options["sealed_key"] != "" {
		originalName = uploadWireName(originalName)
	}
	fields := map[string]string{
		"action":        "upload",
		"csrf_token":    session.csrf,
		"path":          part.remotePath,
		"chunkUploadId": part.chunkID,
		"chunkIndex":    strconv.Itoa(part.index),
		"totalChunks":   strconv.Itoa(part.totalChunks),
		"originalName":  originalName,
		"totalSize":     strconv.FormatInt(part.totalSize, 10),
		"chunkSize":     strconv.FormatInt(part.length, 10),
	}
	for _, name := range []string{"path_tokens", "path_tokens_legacy"} {
		if value := part.options[name]; value != "" {
			fields[name] = value
		}
	}

	body, contentType, err := buildChunkForm(fields, part.localPath, part.offset, part.length)
	if err != nil {
		return nil, 0, err
	}
	return c.postUploadForm(ctx, session, body, contentType, progress)
}

func (c *Client) finalizeChunkedUpload(ctx context.Context, session *webUploadSession, remotePath, chunkID string, totalChunks int, size int64, options map[string]string) (*Response, error) {
	name := options["source"]
	wireName := name
	if options["sealed_key"] != "" {
		wireName = uploadWireName(name)
	}
	fields := map[string]string{
		"action":        "upload",
		"csrf_token":    session.csrf,
		"path":          remotePath,
		"chunkUploadId": chunkID,
		"finalize":      "1",
		"totalChunks":   strconv.Itoa(totalChunks),
		"originalName":  wireName,
		"totalSize":     strconv.FormatInt(size, 10),
		"conflict_strategy": "replace",
	}
	if options["force"] == "true" {
		fields["conflict_strategy"] = "block"
	}
	for option, field := range webUploadFields {
		if value := options[option]; value != "" {
			fields[field] = value
		}
	}

	body, contentType, err := buildChunkForm(fields, "", 0, 0)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(scanPendingMaxWait)
	budgetWaits := 0
	var result *webUploadResult
	var status int
	for {
		result, status, err = withUploadRetryStatus(ctx, func() (*webUploadResult, int, error) {
			return c.postUploadForm(ctx, session, body, contentType, nil)
		})
		wait, waiting := time.Duration(0), false
		var pending *scanPendingError
		if errors.As(err, &pending) {
			wait, waiting = pending.RetryAfter, true
		} else if budget, spent := ScanBudgetWait(err); spent && !c.parkScanBudget && budgetWaits < scanBudgetMaxWaits && (c.waitOutScanBudget || budget <= scanPendingMaxWait) {
			budgetWaits++
			wait, waiting = budget, true
			deadline = deadline.Add(budget)
		} else {
			wait, waiting = scannerShedWait(err)
		}
		if !waiting {
			break
		}
		if time.Now().After(deadline) {
			err = &RequestError{Kind: KindTransient, StatusCode: status, Err: fmt.Errorf("security scan did not finish within %s", scanPendingMaxWait)}
			break
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, duplicateUnderForce(err, options)
	}

	storedName := name
	receipt := map[string]any{
		"success":    true,
		"storedPath": joinRemotePath(remotePath, storedName),
		"name":       storedName,
		"size":       size,
		"storage":    result.Storage,
		"nodeId":     result.NodeID,
	}
	if stamp, decodeErr := hex.DecodeString(result.ETag); decodeErr == nil && len(stamp) == 32 {
		receipt["etag"] = result.ETag
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("failed to render upload result: %w", err)
	}
	return &Response{Success: true, StatusCode: status, Raw: payload}, nil
}

func duplicateUnderForce(err error, options map[string]string) error {
	if options["force"] != "true" {
		return err
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != UploadCodeDuplicate {
		return err
	}
	replaced := &APIError{
		Code:    apiErr.Code,
		Message: "a file with that name already exists, and --force cannot create a same-name copy for files this large. Re-run without --force to store this upload as a new version, or rename the file first.",
	}
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		return &RequestError{Kind: reqErr.Kind, StatusCode: reqErr.StatusCode, RetryAfter: reqErr.RetryAfter, Err: replaced}
	}
	return replaced
}

func (c *Client) postUploadForm(ctx context.Context, session *webUploadSession, body []byte, contentType string, progress func(sent int64)) (*webUploadResult, int, error) {
	var reader io.Reader = bytes.NewReader(body)
	if progress != nil {
		reader = &progressReader{
			reader:   bytes.NewReader(body),
			total:    int64(len(body)),
			progress: func(sent, _ int64) { progress(sent) },
		}
	}
	streamCtx, guard := newStallGuard(ctx)
	defer guard.stop()

	req, err := http.NewRequestWithContext(streamCtx, "POST", c.endpoint, guard.watch(reader))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	c.setCommonHeaders(req)
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }

	resp, err := session.client.Do(req)
	if err != nil {
		return nil, 0, guard.classify(fmt.Errorf("request failed: %w", err))
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(guard.watch(resp.Body), ResponseSizeLimit))
	if err != nil {
		return nil, resp.StatusCode, guard.classify(fmt.Errorf("failed to read response: %w", err))
	}
	if len(respBody) == 0 {
		return nil, resp.StatusCode, statusError(resp, fmt.Errorf("empty response from server (status %d)", resp.StatusCode))
	}

	var result webUploadResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, resp.StatusCode, statusError(resp, rejectionError(resp.StatusCode, respBody))
	}
	if resp.StatusCode == http.StatusAccepted && result.ErrorCode == UploadCodeScanPending {
		return nil, resp.StatusCode, &scanPendingError{RetryAfter: scanPendingWait(resp, &result)}
	}
	if !result.Success {
		message := result.Error
		if message == "" {
			message = fmt.Sprintf("upload rejected with status %d", resp.StatusCode)
		}
		return nil, resp.StatusCode, &RequestError{
			Kind:       uploadRejectionKind(resp.StatusCode, result.ErrorCode),
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfterHeader(resp),
			Err:        &APIError{Code: result.ErrorCode, Message: message},
		}
	}
	result.Raw = respBody
	return &result, resp.StatusCode, nil
}

var permanentUploadCodes = map[string]bool{UploadCodeDuplicate: true}

func uploadRejectionKind(status int, errorCode string) ErrorKind {
	if status != http.StatusOK {
		return classifyStatus(status)
	}
	if permanentUploadCodes[errorCode] {
		return KindPermanent
	}
	return KindTransient
}

func buildChunkForm(fields map[string]string, localPath string, offset, length int64) ([]byte, string, error) {
	var buf bytes.Buffer
	buf.Grow(int(length) + 4096)
	writer := multipart.NewWriter(&buf)
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return nil, "", fmt.Errorf("failed to build upload form: %w", err)
		}
	}
	if localPath != "" {
		part, err := writer.CreateFormFile("file", "chunk")
		if err != nil {
			return nil, "", fmt.Errorf("failed to build upload form: %w", err)
		}
		file, err := os.Open(localPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return nil, "", fmt.Errorf("failed to seek file: %w", err)
		}
		if _, err := io.CopyN(part, file, length); err != nil {
			return nil, "", fmt.Errorf("failed to read chunk: %w", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to build upload form: %w", err)
	}
	return buf.Bytes(), writer.FormDataContentType(), nil
}

func withUploadRetry(ctx context.Context, fn func() (*webUploadResult, int, error)) (*webUploadResult, error) {
	result, _, err := withUploadRetryStatus(ctx, fn)
	return result, err
}

func withUploadRetryStatus(ctx context.Context, fn func() (*webUploadResult, int, error)) (*webUploadResult, int, error) {
	for attempt := 0; ; attempt++ {
		result, status, err := fn()
		if err == nil {
			return result, status, nil
		}
		if attempt >= chunkUploadRetries-1 {
			return nil, status, err
		}
		if _, shed := scannerShedWait(err); shed {
			return nil, status, err
		}
		if _, spent := ScanBudgetWait(err); spent {
			return nil, status, err
		}
		var wait time.Duration
		switch {
		case IsRateLimited(err):
			wait = rateLimitWait(attempt, RetryAfterHint(err))
		case bodyRejection(err):
			return nil, status, err
		case IsTransient(err) || transportRetryable(err):
			wait = retryDelays[min(attempt, len(retryDelays)-1)]
		default:
			return nil, status, err
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, status, ctx.Err()
		}
	}
}

func bodyRejection(err error) bool {
	var reqErr *RequestError
	return errors.As(err, &reqErr) && reqErr.StatusCode == http.StatusOK
}

func joinRemotePath(dir, name string) string {
	trimmed := strings.TrimRight(dir, "/")
	if trimmed == "" {
		return "/" + name
	}
	return trimmed + "/" + name
}

var htmlTagPattern = regexp.MustCompile(`(?s)<[^>]*>`)

type proxyRejection struct {
	status int
	detail string
}

func (e *proxyRejection) Error() string {
	if e.status == http.StatusRequestEntityTooLarge {
		return fmt.Sprintf("rejected with HTTP 413: the request body is too large for a proxy in front of the server, which refused it before the origin saw it (%s)", e.detail)
	}
	return fmt.Sprintf("server returned HTTP %d with a non-JSON body: %s", e.status, e.detail)
}

func rejectionError(status int, body []byte) error {
	return &proxyRejection{status: status, detail: condenseBody(body)}
}

func condenseBody(body []byte) string {
	text := strings.Join(strings.Fields(htmlTagPattern.ReplaceAllString(string(body), " ")), " ")
	if text == "" {
		return "empty body"
	}
	runes := []rune(text)
	if len(runes) > 160 {
		return string(runes[:160]) + "..."
	}
	return text
}
