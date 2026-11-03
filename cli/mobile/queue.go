package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/e2ee"
)

const (
	ErrorClassShed         = "shed"
	ErrorClassRateLimited  = "rate_limited"
	ErrorClassQuota        = "quota"
	ErrorClassDailyLimit   = "daily_limit"
	ErrorClassTransient    = "transient"
	ErrorClassPermanent    = "permanent"
	ErrorClassLocal        = "local"
	ErrorClassCancelled    = "cancelled"
	ErrorClassUnauthorized = "unauthorized"
)

type badInputError struct{ error }

func (e badInputError) Unwrap() error { return e.error }

type classified struct {
	class      string
	code       string
	retryAfter time.Duration
}

func (c classified) retryable() bool {
	return c.class == ErrorClassShed || c.class == ErrorClassRateLimited || c.class == ErrorClassTransient
}

func scanBudgetRetryAfter(err error, hint time.Duration) time.Duration {
	if wait, spent := api.ScanBudgetWait(err); spent {
		return wait
	}
	if hint <= 0 {
		return time.Minute
	}
	return min(hint, api.MaxScanBudgetDelay)
}

func classifyUpload(err error) classified {
	if err == nil {
		return classified{}
	}
	result := classified{retryAfter: api.RetryAfterHint(err)}
	var serverClass string
	var apiErr *api.APIError
	if errors.As(err, &apiErr) {
		result.code = apiErr.Code
		serverClass = apiErr.Class
	}
	var reqErr *api.RequestError
	hasReq := errors.As(err, &reqErr)
	var badInput badInputError

	switch {
	case errors.Is(err, context.Canceled):
		result.class = ErrorClassCancelled
	case errors.As(err, &badInput):
		result.class = ErrorClassPermanent
	case serverClass == ErrorClassRateLimited:
		result.class = serverClass
		result.retryAfter = scanBudgetRetryAfter(err, result.retryAfter)
	case serverClass != "":
		result.class = serverClass
	case hasReq && (reqErr.StatusCode == http.StatusUnauthorized || reqErr.StatusCode == http.StatusForbidden):
		result.class = ErrorClassUnauthorized
	case hasReq && (reqErr.Kind == api.KindRateLimited || reqErr.StatusCode == http.StatusServiceUnavailable):
		result.class = ErrorClassShed
	case hasReq && reqErr.Kind == api.KindTransient:
		result.class = ErrorClassTransient
	case hasReq && reqErr.Kind == api.KindPermanent:
		result.class = ErrorClassPermanent
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission):
		result.class = ErrorClassLocal
	default:
		result.class = ErrorClassTransient
	}
	return result
}

func refusalError(resp *api.Response, message string) error {
	return &api.RequestError{
		Kind:       api.KindPermanent,
		StatusCode: resp.StatusCode,
		Err:        &api.APIError{Code: resp.ErrorCode, Class: resp.ErrorClass, Message: message},
	}
}

func uploadedNodeID(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var ids struct {
		NodeID     string `json:"nodeId"`
		NodeIDWire string `json:"node_id"`
	}
	if json.Unmarshal(raw, &ids) != nil {
		return ""
	}
	id := ids.NodeID
	if id == "" {
		id = ids.NodeIDWire
	}
	if !e2ee.IsNodeIDHex(id) {
		return ""
	}
	return strings.ToLower(id)
}

const folderTimeout = 60 * time.Second

type folderResult struct {
	OK         bool   `json:"ok"`
	Message    string `json:"message,omitempty"`
	ErrorClass string `json:"error_class,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}

func (s *Session) EnsureFolder(remoteDir string) (out string, err error) {
	defer recovered("EnsureFolder", &err)

	dir, err := cleanRemoteDir(remoteDir)
	if err != nil {
		return "", err
	}
	if dir == "/" {
		return encodeJSON(folderResult{OK: true})
	}
	for _, segment := range strings.Split(strings.Trim(dir, "/"), "/") {
		if err := validFileName(segment); err != nil {
			return "", err
		}
	}

	parentKey, err := s.keys.ParentKey()
	if err != nil {
		return encodeJSON(folderResult{Message: err.Error(), ErrorClass: classifyUpload(err).class})
	}
	ctx, cancel := context.WithTimeout(context.Background(), folderTimeout)
	defer cancel()
	chain, callErr := s.keys.EnsureFolderChain(ctx, api.NewClient(), dir, parentKey)
	return encodeJSON(decideFolder(chain.Resp, callErr))
}

func decideFolder(resp *api.Response, callErr error) folderResult {
	if callErr != nil || resp == nil {
		message := "folder request failed"
		if callErr != nil {
			message = callErr.Error()
		}
		return folderResult{Message: message, ErrorClass: ErrorClassTransient}
	}
	if resp.Success {
		return folderResult{OK: true}
	}
	result := folderResult{Message: resp.Message, ErrorCode: resp.ErrorCode}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable:
		result.ErrorClass = ErrorClassShed
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		result.ErrorClass = ErrorClassUnauthorized
	case resp.StatusCode >= 500 || resp.StatusCode == 0:
		result.ErrorClass = ErrorClassTransient
	default:
		result.ErrorClass = ErrorClassPermanent
	}
	return result
}
