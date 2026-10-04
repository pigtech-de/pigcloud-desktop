package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"pigcloud/internal/config"
	"strings"
	"sync"
	"time"
)

const (
	ResponseSizeLimit = 10 * 1024 * 1024

	MaxInMemoryDownloadSize = 600 * 1024 * 1024

	DownloadBufferSize = 32 * 1024

	ClientTimeout = 5 * time.Minute

	KeyValidationTimeout = 30 * time.Second

	HeaderAPIKey      = "X-Api-Key"
	HeaderCliClient   = "X-Cli-Client"
	HeaderCliMetadata = "X-CLI-Metadata"
	HeaderCliLang     = "X-Cli-Lang"
)

var Version = "dev"

var TransferStallTimeout = 2 * time.Minute

var errTransferStalled = errors.New("transfer stalled")

func dialer() func(context.Context, string, string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext
}

type stallGuard struct {
	cancel context.CancelFunc
	mu     sync.Mutex
	timer  stallTimer
	fired  bool
	done   bool
}

type stallTimer interface {
	Reset(time.Duration) bool
	Stop() bool
}

var newStallTimer = func(d time.Duration, fire func()) stallTimer { return time.AfterFunc(d, fire) }

func newStallGuard(parent context.Context) (context.Context, *stallGuard) {
	ctx, cancel := context.WithCancel(parent)
	g := &stallGuard{cancel: cancel}
	g.timer = newStallTimer(TransferStallTimeout, g.trip)
	g.timer.Stop()
	return ctx, g
}

func (g *stallGuard) trip() {
	g.mu.Lock()
	if g.done {
		g.mu.Unlock()
		return
	}
	g.fired = true
	g.mu.Unlock()
	g.cancel()
}

func (g *stallGuard) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.done {
		g.timer.Reset(TransferStallTimeout)
	}
}

func (g *stallGuard) pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.timer.Stop()
}

func (g *stallGuard) stop() {
	g.mu.Lock()
	g.done = true
	g.timer.Stop()
	g.mu.Unlock()
	g.cancel()
}

func (g *stallGuard) tripped() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fired
}

func (g *stallGuard) classify(err error) error {
	if err == nil || !g.tripped() {
		return err
	}
	return &RequestError{
		Kind: KindTransient,
		Err:  fmt.Errorf("%w: no bytes moved for %s", errTransferStalled, TransferStallTimeout),
	}
}

func (g *stallGuard) watch(r io.Reader) io.Reader { return &stallReader{g: g, r: r} }

type stallReader struct {
	g *stallGuard
	r io.Reader
}

func (s *stallReader) Read(p []byte) (int, error) {
	s.g.arm()
	n, err := s.r.Read(p)
	if err != nil {
		s.g.pause()
	}
	return n, err
}

func newTransport(maxIdle int, idleTimeout, responseHeaderTimeout time.Duration) *http.Transport {
	return &http.Transport{
		MaxIdleConns:        maxIdle,
		IdleConnTimeout:     idleTimeout,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         dialer(),
		ForceAttemptHTTP2:   true,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
}

var (
	defaultTransport    = newTransport(10, 90*time.Second, ClientTimeout)
	validationTransport = newTransport(2, 30*time.Second, KeyValidationTimeout)
	wrapTransport       = func(rt http.RoundTripper) http.RoundTripper { return rt }
)

func SetTransportWrapper(wrap func(http.RoundTripper) http.RoundTripper) {
	wrapTransport = wrap
}

type Client struct {
	httpClient *http.Client
	timeout    time.Duration
	endpoint   string
	apiKey     string

	sessionMu sync.Mutex
	session   *webUploadSession

	waitOutScanBudget bool
	parkScanBudget    bool
}

func (c *Client) WaitOutScanBudget() *Client {
	c.waitOutScanBudget = true
	return c
}

func (c *Client) ParkScanBudget() *Client {
	c.parkScanBudget = true
	return c
}

type Response struct {
	Success    bool            `json:"success"`
	MessageKey string          `json:"messageKey"`
	Message    string          `json:"message"`
	ErrorCode  string          `json:"errorCode,omitempty"`
	Cwd        string          `json:"cwd"`
	StatusCode int             `json:"-"`
	Raw        json.RawMessage `json:"-"`
}

type APIError struct {
	Code    string
	Message string
}

func (e *APIError) Error() string { return e.Message }

type ListEntry struct {
	ID              string  `json:"id,omitempty"`
	Name            string  `json:"name"`
	Path            string  `json:"path"`
	Type            string  `json:"type"`
	Size            *int64  `json:"size"`
	PlaintextSize   *int64  `json:"plaintext_size,omitempty"`
	Modified        *string `json:"modified"`
	Shared          bool    `json:"shared"`
	Direct          bool    `json:"direct"`
	Permission      *string `json:"permission"`
	E2EEDisplayName string  `json:"e2ee_display_name,omitempty"`
	SignedBy        string  `json:"signed_by,omitempty"`
	ETag            string  `json:"etag,omitempty"`
}

type ListPayload struct {
	Path    string      `json:"path"`
	Entries []ListEntry `json:"entries"`
	Total   int         `json:"total,omitempty"`
	Offset  int         `json:"offset,omitempty"`
}

type InfoDetails struct {
	NodeID          string           `json:"nodeId,omitempty"`
	Path            string           `json:"path"`
	Name            string           `json:"name"`
	Type            string           `json:"type"`
	Size            *int64           `json:"size"`
	Entries         *int             `json:"entries,omitempty"`
	Modified        *string          `json:"modified"`
	Created         *string          `json:"created"`
	Extension       string           `json:"extension,omitempty"`
	Owner           string           `json:"owner"`
	Favorited       bool             `json:"favorited"`
	Hidden          bool             `json:"hidden"`
	Shared          bool             `json:"shared"`
	Direct          bool             `json:"direct"`
	Permission      *string          `json:"permission"`
	Recipients      []ShareRecipient `json:"recipients,omitempty"`
	E2EEDisplayName string           `json:"e2ee_display_name,omitempty"`
	PlaintextSize   *int64           `json:"plaintext_size,omitempty"`
}

type InfoPayload struct {
	Details InfoDetails `json:"details"`
}

type UploadPayload struct {
	StoredPath string       `json:"storedPath"`
	Name       string       `json:"name"`
	Size       *int64       `json:"size"`
	Storage    StorageState `json:"storage"`
	NodeID     string       `json:"nodeId,omitempty"`
	ETag       string       `json:"etag,omitempty"`
}

type StorageState struct {
	UsedBytes   int64  `json:"usedBytes"`
	LimitBytes  int64  `json:"limitBytes"`
	UsedDisplay string `json:"usedDisplay"`
}

type DownloadPayload struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Encoding  string `json:"encoding"`
	Size      int64  `json:"size"`
	Bytes     *int64 `json:"bytes"`
	Directory bool   `json:"directory"`
	Target    string `json:"target,omitempty"`
	DownloadResult
}

type SharePayload struct {
	Path       string `json:"path"`
	Username   string `json:"username"`
	Permission string `json:"permission,omitempty"`
	Status     string `json:"status"`
	NodeID     string `json:"nodeId,omitempty"`
}

type ShareListPayload struct {
	Path        string           `json:"path"`
	Recipients  []ShareRecipient `json:"recipients"`
	HasPassword bool             `json:"hasPassword"`
	ExpiresAt   *string          `json:"expiresAt"`
}

type ShareRecipient struct {
	Username   string `json:"username"`
	Permission string `json:"permission"`
	Expired    bool   `json:"expired"`
}

type ShareUpdatePayload struct {
	Path    string   `json:"path"`
	Changes []string `json:"changes"`
}

type ShareInboxPayload struct {
	Shares []ShareInboxEntry `json:"shares"`
}

type ShareInboxEntry struct {
	Owner           string `json:"owner"`
	Name            string `json:"name"`
	NodeID          string `json:"node_id,omitempty"`
	Permission      string `json:"permission"`
	E2EEDisplayName string `json:"e2ee_display_name,omitempty"`
}

type MovePayload struct {
	Source  string   `json:"source"`
	Target  string   `json:"target"`
	Noop    bool     `json:"noop,omitempty"`
	Dry     bool     `json:"dry,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Count   int      `json:"count,omitempty"`
	Files   []string `json:"files,omitempty"`
}

type CopyPayload struct {
	Path   string `json:"source"`
	Target string `json:"target"`
	Count  int    `json:"count,omitempty"`
	Dry    bool   `json:"dry,omitempty"`
}

type RemovePayload struct {
	Path      string   `json:"path"`
	Pattern   string   `json:"pattern,omitempty"`
	Permanent bool     `json:"permanent"`
	Dry       bool     `json:"dry,omitempty"`
	Count     int      `json:"count,omitempty"`
	Files     []string `json:"files,omitempty"`
}

type EmptyTrashPayload struct {
	Count int `json:"count"`
}

type CdPayload struct {
	Path string `json:"path"`
}

type TreePayload struct {
	Path    string      `json:"path"`
	Entries []TreeEntry `json:"entries"`
}

type TreeEntry struct {
	Name            string      `json:"name"`
	Path            string      `json:"path"`
	Type            string      `json:"type"`
	Children        []TreeEntry `json:"children,omitempty"`
	E2EEDisplayName string      `json:"e2ee_display_name,omitempty"`
}

type FindPayload struct {
	Pattern string      `json:"pattern"`
	Path    string      `json:"path"`
	Results []FindEntry `json:"results"`
	Total   int         `json:"total"`
	Limited bool        `json:"limited"`
}

type FindEntry struct {
	ID              string  `json:"id"`
	ParentID        string  `json:"parent_id"`
	Name            string  `json:"name"`
	Path            string  `json:"path"`
	Type            string  `json:"type"`
	Size            *int64  `json:"size"`
	PlaintextSize   *int64  `json:"plaintext_size,omitempty"`
	Modified        *string `json:"modified"`
	Filtered        bool    `json:"filtered,omitempty"`
	E2EEDisplayName string  `json:"e2ee_display_name,omitempty"`
}

type CatPayload struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
	DownloadResult
}

func (p *CatPayload) AsDownloadResult() *DownloadResult {
	result := p.DownloadResult
	return &result
}

type RestorePayload struct {
	Restored bool   `json:"restored"`
	NodeID   string `json:"node_id,omitempty"`
}

type HelpCommand struct {
	Command     string       `json:"command"`
	Aliases     []string     `json:"aliases"`
	Description string       `json:"description"`
	Options     []HelpOption `json:"options"`
}

type HelpOption struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Required    bool     `json:"required"`
	Description string   `json:"description"`
}

type GrIndexPayload struct {
	Items      []GrIndexEntry `json:"items"`
	NextCursor *string        `json:"nextCursor"`
	Done       bool           `json:"done"`
}

type GrIndexEntry struct {
	NodeID          string `json:"nodeId"`
	Payload         string `json:"payload"`
	Version         int    `json:"version"`
	E2EEDisplayName string `json:"e2eeDisplayName"`
}

type HelpDetailPayload struct {
	Command  *HelpCommandDetail `json:"command,omitempty"`
	Commands []HelpCommand      `json:"commands,omitempty"`
}

type HelpCommandDetail struct {
	Command         string             `json:"command"`
	Aliases         []string           `json:"aliases"`
	Description     string             `json:"description"`
	Group           string             `json:"group"`
	Options         []HelpDetailOption `json:"options"`
	Examples        []HelpExample      `json:"examples"`
	RelatedCommands []string           `json:"relatedCommands,omitempty"`
	WebEnabled      bool               `json:"webEnabled,omitempty"`
}

type HelpDetailOption struct {
	Name           string   `json:"name"`
	Aliases        []string `json:"aliases"`
	Required       bool     `json:"required"`
	Type           string   `json:"type"`
	Description    string   `json:"description"`
	Values         []string `json:"values,omitempty"`
	Default        *string  `json:"default,omitempty"`
	CompletionType *string  `json:"completionType,omitempty"`
}

type HelpExample struct {
	Cmd         string `json:"cmd"`
	Description string `json:"description"`
}

type WhoamiPayload struct {
	Username         string `json:"username"`
	Tier             string `json:"tier,omitempty"`
	Email            string `json:"email,omitempty"`
	MemberSince      string `json:"memberSince,omitempty"`
	TwoFactorEnabled bool   `json:"twoFactorEnabled"`
	TotpEnabled      bool   `json:"totpEnabled"`
	Fido2Enabled     bool   `json:"fido2Enabled"`
	StorageUsed      string `json:"storageUsed,omitempty"`
	StorageLimit     string `json:"storageLimit,omitempty"`
}

type APIKeyStatusPayload struct {
	Active     bool   `json:"active"`
	Allowed    bool   `json:"allowed"`
	Identifier string `json:"identifier"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt"`
}

type APIKeyRevokePayload struct {
	Revoked bool `json:"revoked"`
}

type StatPayload struct {
	UsedBytes         int64  `json:"usedBytes"`
	LimitBytes        int64  `json:"limitBytes"`
	UsedDisplay       string `json:"usedDisplay"`
	LimitDisplay      string `json:"limitDisplay"`
	UsedPercent       int    `json:"usedPercent"`
	FileCount         int    `json:"fileCount"`
	FolderCount       int    `json:"folderCount"`
	DailyUploadBytes  int64  `json:"dailyUploadBytes,omitempty"`
	DailyUploadLimit  int64  `json:"dailyUploadLimit,omitempty"`
	VersionLimit      *int   `json:"versionLimit,omitempty"`
	UploadRateLimit   *int64 `json:"uploadRateLimit,omitempty"`
	DownloadRateLimit *int64 `json:"downloadRateLimit,omitempty"`
	ConcurrentUploads *int   `json:"concurrentUploads,omitempty"`
}

type ActivityPayload struct {
	Events      []ActivityEvent `json:"events"`
	UnreadCount int             `json:"unreadCount"`
	TotalCount  int             `json:"totalCount"`
	MarkedRead  int             `json:"markedRead,omitempty"`
}

type ActivityEvent struct {
	ID        int     `json:"id"`
	EventType string  `json:"eventType"`
	Detail    string  `json:"detail"`
	CreatedAt string  `json:"createdAt"`
	ReadAt    *string `json:"readAt"`
}

type DiskUsagePayload struct {
	Files      []BreakdownFile `json:"files"`
	TrashSize  int64           `json:"trashSize"`
	TrashCount int             `json:"trashCount,omitempty"`
}

type BreakdownFile struct {
	E2EEDisplayName string `json:"e2ee_display_name"`
	Size            int64  `json:"size"`
}

type StorageCategory struct {
	Type  string `json:"type"`
	Size  int64  `json:"size"`
	Count int    `json:"count"`
}

type VersionListPayload struct {
	Path     string         `json:"path"`
	Versions []VersionEntry `json:"versions"`
}

type VersionEntry struct {
	ID            int    `json:"id"`
	VersionNumber int    `json:"versionNumber"`
	Size          int64  `json:"size"`
	CreatedAt     string `json:"createdAt"`
}

type VersionActionPayload struct {
	Path          string `json:"path,omitempty"`
	VersionID     int    `json:"versionId,omitempty"`
	VersionNumber int    `json:"versionNumber"`
}

type VersionPrunePayload struct {
	Path   string `json:"path"`
	Pruned int    `json:"pruned"`
	Kept   int    `json:"kept"`
}

type LinkCreatePayload struct {
	Path            string          `json:"path"`
	Token           string          `json:"token"`
	URL             string          `json:"url"`
	LinkID          int             `json:"linkId"`
	E2EEDisplayName string          `json:"e2eeDisplayName,omitempty"`
	ChildNames      []ChildNameItem `json:"childNames,omitempty"`
}

type ChildNameItem struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type LinkGetPayload struct {
	Path string    `json:"path"`
	Link *LinkInfo `json:"link"`
}

type LinkInfo struct {
	ID            int     `json:"id"`
	Token         string  `json:"token"`
	URL           string  `json:"url"`
	HasPassword   bool    `json:"hasPassword"`
	ExpiresAt     *string `json:"expiresAt"`
	DownloadCount int     `json:"downloadCount"`
	MaxDownloads  *int    `json:"maxDownloads"`
	CreatedAt     string  `json:"createdAt"`
}

type LinkListPayload struct {
	Links []LinkListItem `json:"links"`
}

type LinkListItem struct {
	ID              int     `json:"id"`
	NodeID          string  `json:"nodeId"`
	Type            string  `json:"type"`
	Token           string  `json:"token"`
	URL             string  `json:"url"`
	HasPassword     bool    `json:"hasPassword"`
	ExpiresAt       *string `json:"expiresAt"`
	DownloadCount   int     `json:"downloadCount"`
	MaxDownloads    *int    `json:"maxDownloads"`
	CreatedAt       string  `json:"createdAt"`
	E2EEDisplayName string  `json:"e2ee_display_name,omitempty"`
}

type LinkActionPayload struct {
	Path   string `json:"path,omitempty"`
	LinkID int    `json:"linkId,omitempty"`
}

type SessionsPayload struct {
	Sessions []SessionInfo `json:"sessions,omitempty"`
	Devices  []DeviceInfo  `json:"devices,omitempty"`
}

type SessionInfo struct {
	SessionID  string `json:"sessionId"`
	UserAgent  string `json:"userAgent"`
	Location   string `json:"location"`
	CreatedAt  string `json:"createdAt"`
	LastActive string `json:"lastActive"`
	IsCurrent  bool   `json:"isCurrent"`
	Label      string `json:"label,omitempty"`
}

type DeviceInfo struct {
	ID         int    `json:"id"`
	UserAgent  string `json:"userAgent"`
	Location   string `json:"location"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt"`
	IsCurrent  bool   `json:"isCurrent"`
}

type ExportPayload struct {
	Export json.RawMessage `json:"export"`
}

type TrashListPayload struct {
	Items []TrashItem `json:"items"`
	Count int         `json:"count"`
}

type TrashItem struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Size             int64  `json:"size"`
	FileSize         int64  `json:"file_size,omitempty"`
	DeletedAt        string `json:"deleted_at"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	NodeID           string `json:"node_id,omitempty"`
	OriginalParentID string `json:"original_parent_id,omitempty"`
	E2EEDisplayName  string `json:"e2ee_display_name,omitempty"`
	ItemType         string `json:"item_type,omitempty"`
}

type TouchPayload struct {
	Path string `json:"path"`
	Name string `json:"name"`
	Size *int64 `json:"size"`
}

type HidePayload struct {
	Path   string `json:"path"`
	Hidden bool   `json:"hidden"`
}

type HideListPayload struct {
	Items []HideListItem `json:"items"`
}

type HideListItem struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	E2EEDisplayName string `json:"e2ee_display_name,omitempty"`
}

type RecentListPayload struct {
	Recents []RecentItem `json:"recents"`
}

type RecentItem struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	AccessedAt      string `json:"accessedAt"`
	E2EEDisplayName string `json:"e2ee_display_name,omitempty"`
}

type FavoritePayload struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	Status string `json:"status"`
}

type FavoriteListPayload struct {
	Favorites []FavoriteItem `json:"favorites"`
}

type FavoriteItem struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	Type            string `json:"type"`
	Owner           string `json:"owner,omitempty"`
	E2EEDisplayName string `json:"e2ee_display_name,omitempty"`
}

type FriendListPayload struct {
	Friends []FriendEntry `json:"friends"`
}

type FriendEntry struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at,omitempty"`
}

type FriendActionPayload struct {
	Result string `json:"result,omitempty"`
	Action string `json:"action,omitempty"`
}

type FriendPendingPayload struct {
	Pending []FriendPendingEntry `json:"pending"`
}

type FriendPendingEntry struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
}

type FriendBlockedPayload struct {
	Blocked []FriendPendingEntry `json:"blocked"`
}

type ChatListPayload struct {
	Conversations []ChatConversation `json:"conversations"`
}

type ChatConversation struct {
	Username           string `json:"username"`
	Unread             int    `json:"unread"`
	LastDirection      string `json:"lastDirection"`
	LastAt             string `json:"lastAt"`
	LastMessageID      int    `json:"lastMessageId"`
	EncryptedBody      string `json:"encryptedBody"`
	BodyNonce          string `json:"bodyNonce"`
	SenderSealedKey    string `json:"senderSealedKey"`
	RecipientSealedKey string `json:"recipientSealedKey"`
}

type ChatHistoryPayload struct {
	Messages []ChatMessage `json:"messages"`
	Peer     string        `json:"peer"`
	UserID   int           `json:"userId"`
}

type ChatMessage struct {
	ID                 int     `json:"id"`
	SenderID           int     `json:"senderId"`
	RecipientID        int     `json:"recipientId"`
	EncryptedBody      string  `json:"encryptedBody"`
	BodyNonce          string  `json:"bodyNonce"`
	SenderSealedKey    string  `json:"senderSealedKey"`
	RecipientSealedKey string  `json:"recipientSealedKey"`
	ReadAt             *string `json:"readAt"`
	CreatedAt          string  `json:"createdAt"`
	Deleted            bool    `json:"deleted"`
	Blocked            bool    `json:"blocked"`
	SenderBlocked      bool    `json:"senderBlocked"`
	ShareID            *int    `json:"shareId"`
	ShareStatus        *string `json:"shareStatus"`
}

type ChatSendPayload struct {
	MessageID int    `json:"messageId"`
	Peer      string `json:"peer"`
	ShareID   *int   `json:"shareId,omitempty"`
	Path      string `json:"path,omitempty"`
}

type ChatDeletePayload struct {
	MessageID int `json:"messageId"`
}

type ChatMarkReadPayload struct {
	Peer   string `json:"peer"`
	Marked int    `json:"marked"`
}

type ChatUnreadPayload struct {
	Unread []ChatUnreadEntry `json:"unread"`
	Total  int               `json:"total"`
}

type ChatUnreadEntry struct {
	Username string `json:"username"`
	Count    int    `json:"count"`
}

type CLIRequest struct {
	Command string            `json:"command"`
	Options map[string]string `json:"options"`
}

func dropAPIKeyOnHostChange(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && req.URL.Host != via[0].URL.Host {
		req.Header.Del(HeaderAPIKey)
	}
	return nil
}

func NewClient() *Client {
	endpoint := config.GetEndpoint()
	if endpoint != "" && !strings.HasPrefix(endpoint, "https://") {
		fmt.Fprintf(os.Stderr, "Warning: endpoint %q does not use HTTPS. Your data may be transmitted insecurely.\n", endpoint)
	}
	return &Client{
		httpClient: &http.Client{
			Transport:     wrapTransport(defaultTransport),
			CheckRedirect: dropAPIKeyOnHostChange,
		},
		timeout:  ClientTimeout,
		endpoint: endpoint,
		apiKey:   config.GetAPIKey(),
	}
}

func NewClientWithKey(apiKey string) *Client {
	return &Client{
		httpClient: &http.Client{
			Transport:     wrapTransport(validationTransport),
			CheckRedirect: dropAPIKeyOnHostChange,
		},
		timeout:  KeyValidationTimeout,
		endpoint: config.GetEndpoint(),
		apiKey:   apiKey,
	}
}

func (c *Client) requestCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, c.timeout)
}

func (c *Client) getCliEndpoint() string {
	return c.actionEndpoint("cli")
}

var retryDelays = []time.Duration{1 * time.Second, 2 * time.Second}

var (
	uploadSingleBodyMaxBytes int64 = 90 * 1024 * 1024
	uploadChunkSize          int64 = 16 * 1024 * 1024
)

func isTransient(err error, statusCode int) bool {
	if err == nil {
		return false
	}
	var reqErr *RequestError
	if errors.As(err, &reqErr) {
		return reqErr.Kind == KindTransient
	}
	if transportRetryable(err) {
		return true
	}
	return classifyStatus(statusCode) == KindTransient
}

func withRetry[T any](ctx context.Context, fn func() (T, int, error)) (T, error) {
	maxAttempts := len(retryDelays) + 1
	var zero T
	for attempt := range maxAttempts {
		result, statusCode, err := fn()
		if err == nil {
			return result, nil
		}
		if !isTransient(err, statusCode) || attempt == maxAttempts-1 {
			return zero, err
		}
		select {
		case <-time.After(retryDelays[attempt]):
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	}
	return zero, nil
}

func (c *Client) Execute(ctx context.Context, command string, options map[string]string) (*Response, error) {
	jsonBody, err := json.Marshal(CLIRequest{Command: command, Options: options})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	return withRetry(ctx, func() (*Response, int, error) {
		attemptCtx, cancel := c.requestCtx(ctx)
		defer cancel()
		req, err := http.NewRequestWithContext(attemptCtx, "POST", c.getCliEndpoint(), bytes.NewReader(jsonBody))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		c.setCommonHeaders(req)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, ResponseSizeLimit))
		if err != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
		}

		if len(respBody) == 0 {
			return nil, resp.StatusCode, fmt.Errorf("empty response from server (status %d)", resp.StatusCode)
		}

		var apiResp Response
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
		}

		apiResp.StatusCode = resp.StatusCode
		apiResp.Raw = respBody
		return &apiResp, resp.StatusCode, nil
	})
}

func NewUploadIdempotencyKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("ul-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (c *Client) Upload(ctx context.Context, localPath string, remotePath string, progress func(sent, total int64), e2eeOpts ...map[string]string) (*Response, error) {
	options := map[string]string{
		"source": filepath.Base(localPath),
		"target": remotePath,
	}
	if len(e2eeOpts) > 0 {
		if name, ok := e2eeOpts[0]["_original_name"]; ok {
			options["source"] = name
			delete(e2eeOpts[0], "_original_name")
		}
	}
	if len(e2eeOpts) > 0 && e2eeOpts[0] != nil {
		maps.Copy(options, e2eeOpts[0])
	}
	if options["upload_idempotency_key"] == "" {
		options["upload_idempotency_key"] = NewUploadIdempotencyKey()
	}

	stat, err := os.Stat(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}
	if stat.Size() > uploadSingleBodyMaxBytes {
		return c.uploadChunked(ctx, localPath, remotePath, stat.Size(), progress, options)
	}

	resp, err := c.uploadWholeBody(ctx, localPath, progress, options)
	if err != nil && bodyTooLarge(err) {
		return c.uploadChunked(ctx, localPath, remotePath, stat.Size(), progress, options)
	}
	return resp, err
}

func bodyTooLarge(err error) bool {
	var rejection *proxyRejection
	return errors.As(err, &rejection) && rejection.status == http.StatusRequestEntityTooLarge
}

func uploadWireName(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return "f"
	}
	return "f" + strings.ToLower(name[dot:])
}

func (c *Client) uploadWholeBody(ctx context.Context, localPath string, progress func(sent, total int64), options map[string]string) (*Response, error) {
	wireOptions := options
	realName := options["source"]
	stubbed := options["sealed_key"] != ""
	if stubbed {
		wireOptions = make(map[string]string, len(options))
		maps.Copy(wireOptions, options)
		wireOptions["source"] = uploadWireName(realName)
	}
	metadataJSON, err := json.Marshal(CLIRequest{Command: "ul", Options: wireOptions})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}
	metadataB64 := base64.StdEncoding.EncodeToString(metadataJSON)

	resp, err := withRetry(ctx, func() (*Response, int, error) {
		file, err := os.Open(localPath)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()

		stat, err := file.Stat()
		if err != nil {
			return nil, 0, fmt.Errorf("failed to stat file: %w", err)
		}
		fileSize := stat.Size()

		pr := &progressReader{reader: file, total: fileSize, progress: progress}

		streamCtx, guard := newStallGuard(ctx)
		defer guard.stop()

		req, err := http.NewRequestWithContext(streamCtx, "POST", c.getCliEndpoint(), guard.watch(pr))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Length", fmt.Sprintf("%d", fileSize))
		c.setCommonHeaders(req)
		req.Header.Set(HeaderCliMetadata, metadataB64)
		req.ContentLength = fileSize

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, 0, guard.classify(fmt.Errorf("request failed: %w", err))
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(io.LimitReader(guard.watch(resp.Body), ResponseSizeLimit))
		if err != nil {
			return nil, resp.StatusCode, guard.classify(fmt.Errorf("failed to read response: %w", err))
		}

		if len(respBody) == 0 {
			if resp.StatusCode != 200 {
				return nil, resp.StatusCode, statusError(resp, rejectionError(resp.StatusCode, nil))
			}
			return nil, resp.StatusCode, fmt.Errorf("empty response from server (status %d)", resp.StatusCode)
		}

		var apiResp Response
		if err := json.Unmarshal(respBody, &apiResp); err != nil {
			if resp.StatusCode != 200 {
				return nil, resp.StatusCode, statusError(resp, rejectionError(resp.StatusCode, respBody))
			}
			return nil, resp.StatusCode, fmt.Errorf("failed to parse response (status %d): %w", resp.StatusCode, err)
		}

		if resp.StatusCode != 200 && !apiResp.Success {
			msg := apiResp.Message
			if msg == "" {
				msg = fmt.Sprintf("upload failed with status %d", resp.StatusCode)
			}
			return nil, resp.StatusCode, statusError(resp, &APIError{Code: apiResp.ErrorCode, Message: msg})
		}

		apiResp.StatusCode = resp.StatusCode
		apiResp.Raw = respBody
		return &apiResp, resp.StatusCode, nil
	})
	if err != nil || resp == nil || !stubbed || !resp.Success || len(resp.Raw) == 0 {
		return resp, err
	}
	var payload map[string]any
	if json.Unmarshal(resp.Raw, &payload) == nil {
		payload["name"] = realName
		payload["storedPath"] = joinRemotePath(options["target"], realName)
		if raw, marshalErr := json.Marshal(payload); marshalErr == nil {
			resp.Raw = raw
		}
	}
	return resp, nil
}

type DownloadResult struct {
	E2EE           bool   `json:"e2ee,omitempty"`
	SealedKey      string `json:"sealed_key,omitempty"`
	EncryptionMeta string `json:"encryption_meta,omitempty"`

	SignatureEd25519 string `json:"signature_ed25519,omitempty"`
	SignatureMldsa   string `json:"signature_mldsa,omitempty"`
	SigningPkEd25519 string `json:"signing_pk_ed25519,omitempty"`
	SigningPkMldsa   string `json:"signing_pk_mldsa,omitempty"`

	SignedBy string `json:"signed_by,omitempty"`

	TEESignatureEd25519 string `json:"tee_signature_ed25519,omitempty"`
	TEESignatureMldsa   string `json:"tee_signature_mldsa,omitempty"`
	TEESigningPkEd25519 string `json:"tee_signing_pk_ed25519,omitempty"`
	TEESigningPkMldsa   string `json:"tee_signing_pk_mldsa,omitempty"`
}

func parseDownloadMetadata(metaHeader string) *DownloadResult {
	result := &DownloadResult{}
	if metaHeader == "" {
		return result
	}
	metaBytes, err := base64.StdEncoding.DecodeString(metaHeader)
	if err != nil {
		return result
	}
	var dlPayload DownloadPayload
	if err := json.Unmarshal(metaBytes, &dlPayload); err != nil {
		return result
	}
	return &dlPayload.DownloadResult
}

func downloadRejection(resp *http.Response, body []byte) error {
	if len(body) == 0 {
		return statusError(resp, fmt.Errorf("download failed with status %d", resp.StatusCode))
	}
	var apiResp Response
	if json.Unmarshal(body, &apiResp) == nil {
		message := apiResp.Message
		if message == "" {
			message = fmt.Sprintf("download failed with status %d", resp.StatusCode)
		}
		return statusError(resp, &APIError{Code: apiResp.ErrorCode, Message: message})
	}
	return statusError(resp, rejectionError(resp.StatusCode, body))
}

func (c *Client) streamDownload(ctx context.Context, jsonBody []byte, sink func(body io.Reader, total int64) (int, error)) (*DownloadResult, error) {
	return withRetry(ctx, func() (*DownloadResult, int, error) {
		streamCtx, guard := newStallGuard(ctx)
		defer guard.stop()

		req, err := http.NewRequestWithContext(streamCtx, "POST", c.getCliEndpoint(), bytes.NewReader(jsonBody))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		c.setCommonHeaders(req)
		req.Header.Set("Accept", "application/octet-stream")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, 0, guard.classify(fmt.Errorf("request failed: %w", err))
		}
		defer resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		if resp.StatusCode != 200 || strings.Contains(contentType, "application/json") {
			respBody, _ := io.ReadAll(io.LimitReader(guard.watch(resp.Body), ResponseSizeLimit))
			return nil, resp.StatusCode, guard.classify(downloadRejection(resp, respBody))
		}

		result := parseDownloadMetadata(resp.Header.Get(HeaderCliMetadata))
		if status, err := sink(guard.watch(resp.Body), resp.ContentLength); err != nil {
			return nil, status, guard.classify(err)
		}
		return result, 200, nil
	})
}

func fileSink(ctx context.Context, localPath string, progress func(received, total int64)) func(io.Reader, int64) (int, error) {
	return func(body io.Reader, total int64) (int, error) {
		tmpFile, err := os.CreateTemp(filepath.Dir(localPath), ".pigcloud-dl-*")
		if err != nil {
			return 0, fmt.Errorf("failed to create temp file: %w", err)
		}
		tmpPath := tmpFile.Name()
		defer func() {
			tmpFile.Close()
			os.Remove(tmpPath)
		}()

		buf := make([]byte, DownloadBufferSize)
		var received int64
		for {
			if err := ctx.Err(); err != nil {
				return 0, fmt.Errorf("download cancelled: %w", err)
			}
			n, readErr := body.Read(buf)
			if n > 0 {
				if _, writeErr := tmpFile.Write(buf[:n]); writeErr != nil {
					return 0, fmt.Errorf("failed to write file: %w", writeErr)
				}
				received += int64(n)
				if progress != nil {
					progress(received, total)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return 0, fmt.Errorf("failed to read response: %w", readErr)
			}
		}

		if err := tmpFile.Close(); err != nil {
			return 0, fmt.Errorf("failed to finalize download: %w", err)
		}
		if err := os.Rename(tmpPath, localPath); err != nil {
			return 0, fmt.Errorf("failed to move downloaded file: %w", err)
		}
		return 200, nil
	}
}

func (c *Client) Download(ctx context.Context, remotePath string, localPath string, progress func(received, total int64), extraOpts ...map[string]string) (*DownloadResult, error) {
	jsonBody, err := downloadRequestBody("dl", remotePath, extraOpts...)
	if err != nil {
		return nil, err
	}
	return c.streamDownload(ctx, jsonBody, fileSink(ctx, localPath, progress))
}

func (c *Client) DownloadToMemory(ctx context.Context, remotePath string, extraOpts ...map[string]string) ([]byte, *DownloadResult, error) {
	jsonBody, err := downloadRequestBody("dl", remotePath, extraOpts...)
	if err != nil {
		return nil, nil, err
	}

	var data []byte
	result, err := c.streamDownload(ctx, jsonBody, func(body io.Reader, _ int64) (int, error) {
		got, err := io.ReadAll(io.LimitReader(body, int64(MaxInMemoryDownloadSize)+1))
		if err != nil {
			return 0, fmt.Errorf("failed to read response body: %w", err)
		}
		if int64(len(got)) > int64(MaxInMemoryDownloadSize) {
			return 200, fmt.Errorf("file exceeds %d MB in-memory download limit: %w",
				MaxInMemoryDownloadSize/(1024*1024), ErrInMemoryDownloadTooLarge)
		}
		data = got
		return 200, nil
	})
	if err != nil {
		return nil, nil, err
	}
	return data, result, nil
}

func (c *Client) DownloadCommand(ctx context.Context, command string, options map[string]string, localPath string, progress func(received, total int64)) (*DownloadResult, error) {
	jsonBody, err := json.Marshal(CLIRequest{Command: command, Options: options})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	return c.streamDownload(ctx, jsonBody, fileSink(ctx, localPath, progress))
}

func downloadRequestBody(command, remotePath string, extraOpts ...map[string]string) ([]byte, error) {
	options := map[string]string{"source": remotePath}
	if len(extraOpts) > 0 {
		maps.Copy(options, extraOpts[0])
	}
	jsonBody, err := json.Marshal(CLIRequest{Command: command, Options: options})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	return jsonBody, nil
}

func (c *Client) Validate(ctx context.Context) (*Response, error) {
	return c.Execute(ctx, "ls", map[string]string{"source": "/"})
}

func (c *Client) SetupEncryptionKeys(ctx context.Context, params map[string]string) (*Response, error) {
	return c.Execute(ctx, "e2ee_setup", params)
}

func (c *Client) FetchEncryptionKeys(ctx context.Context) (*Response, error) {
	return c.Execute(ctx, "e2ee_keys", nil)
}

func (c *Client) FetchPublicKey(ctx context.Context, username string) (*Response, error) {
	return c.Execute(ctx, "e2ee_pubkey", map[string]string{"username": username})
}

type ShareRecipientWithKey struct {
	UserID         int    `json:"user_id"`
	Username       string `json:"username"`
	PublicKey      string `json:"public_key"`
	PublicKeyKyber string `json:"public_key_kyber"`
}

type ShareRecipientsResponse struct {
	Success    bool                    `json:"success"`
	Recipients []ShareRecipientWithKey `json:"recipients"`
}

func (c *Client) ShareRecipientsForNode(ctx context.Context, nodeIDHex string) (*ShareRecipientsResponse, error) {
	body, err := json.Marshal(map[string]string{"nodeId": nodeIDHex})
	if err != nil {
		return nil, err
	}
	resp, err := c.postAction(ctx, "share-recipients-for-node", body)
	if err != nil {
		return nil, err
	}
	var result ShareRecipientsResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

type SealedNameEntry struct {
	NodeID            string `json:"node_id"`
	SealedDisplayName string `json:"sealed_display_name"`
}

type SealedKeyEntry struct {
	NodeID    string `json:"node_id"`
	SealedKey string `json:"sealed_key"`
}

const ShareRowBatchMax = 5000

func (c *Client) StoreShareDisplayNames(ctx context.Context, recipientUsername, anchorHex string, names []SealedNameEntry) error {
	return storeShareRows(ctx, c, "store-share-display-names", recipientUsername, anchorHex, "sealedNames", names)
}

func (c *Client) StoreShareContentKeys(ctx context.Context, recipientUsername string, keys []SealedKeyEntry) error {
	return storeShareRows(ctx, c, "store-share-content-keys", recipientUsername, "", "sealedKeys", keys)
}

func storeShareRows[T any](ctx context.Context, c *Client, action, recipientUsername, anchorHex, field string, rows []T) error {
	for len(rows) > 0 {
		n := min(len(rows), ShareRowBatchMax)
		payload := map[string]any{"recipientUsername": recipientUsername, field: rows[:n]}
		if anchorHex != "" {
			payload["shareAnchorId"] = anchorHex
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		resp, err := c.postAction(ctx, action, body)
		if err != nil {
			return err
		}
		var result struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		if err := json.Unmarshal(resp, &result); err != nil || !result.Success {
			return fmt.Errorf("action %s refused: %s", action, string(resp))
		}
		rows = rows[n:]
	}
	return nil
}

func (c *Client) postAction(ctx context.Context, action string, body []byte) ([]byte, error) {
	endpoint := c.actionEndpoint(action)
	ctx, cancel := c.requestCtx(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setCommonHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, ResponseSizeLimit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return respBody, fmt.Errorf("action %s returned %d: %s", action, resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

type DeviceAuthorizeResult struct {
	Success                 bool   `json:"success"`
	Error                   string `json:"error"`
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expires_in"`
}

type DeviceTokenResult struct {
	Success       bool   `json:"success"`
	Error         string `json:"error"`
	APIKey        string `json:"api_key"`
	KeyIdentifier string `json:"key_identifier"`
	SealedKey     string `json:"sealed_key"`
	KeyEpoch      int64  `json:"key_epoch"`
}

func (c *Client) DeviceAuthorize(ctx context.Context, deviceLabel, ephPubkey string, background bool) (*DeviceAuthorizeResult, error) {
	reqBody := map[string]string{"device_label": deviceLabel}
	if ephPubkey != "" {
		reqBody["eph_pubkey"] = ephPubkey
	}
	if background {
		reqBody["background"] = "1"
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	raw, postErr := c.postAction(ctx, "device-authorize", body)
	var result DeviceAuthorizeResult
	if len(raw) > 0 && json.Unmarshal(raw, &result) == nil {
		return &result, nil
	}
	if postErr != nil {
		return nil, postErr
	}
	return nil, fmt.Errorf("empty device-authorize response")
}

func (c *Client) RevokeDeviceKey(ctx context.Context, identifier string) error {
	body, err := json.Marshal(map[string]string{"identifier": identifier})
	if err != nil {
		return err
	}
	raw, postErr := c.postAction(ctx, "account-revoke-cli-device", body)
	if postErr != nil {
		return postErr
	}
	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return err
	}
	if !result.Success {
		return fmt.Errorf("device key revoke refused")
	}
	return nil
}

func (c *Client) DeviceToken(ctx context.Context, deviceCode string) (*DeviceTokenResult, error) {
	body, err := json.Marshal(map[string]string{"device_code": deviceCode})
	if err != nil {
		return nil, err
	}
	raw, postErr := c.postAction(ctx, "device-token", body)
	var result DeviceTokenResult
	if len(raw) > 0 && json.Unmarshal(raw, &result) == nil {
		return &result, nil
	}
	if postErr != nil {
		return nil, postErr
	}
	return nil, fmt.Errorf("empty device-token response")
}

type E2EEKeysPayload struct {
	PublicKey                string `json:"public_key"`
	EncryptedPrivateKey      string `json:"encrypted_private_key"`
	PrivateKeyNonce          string `json:"private_key_nonce"`
	PublicKeyKyber           string `json:"public_key_kyber"`
	EncryptedPrivateKeyKyber string `json:"encrypted_private_key_kyber"`
	PrivateKeyKyberNonce     string `json:"private_key_kyber_nonce"`
	KDFSalt                  string `json:"kdf_salt"`
	KDFOpsLimit              uint32 `json:"kdf_ops_limit"`
	KDFMemLimit              uint32 `json:"kdf_mem_limit"`

	SigningPublicKeyEd25519           string `json:"signing_public_key_ed25519,omitempty"`
	EncryptedSigningPrivateKeyEd25519 string `json:"encrypted_signing_private_key_ed25519,omitempty"`
	SigningPrivateKeyEd25519Nonce     string `json:"signing_private_key_ed25519_nonce,omitempty"`
	SigningPublicKeyMldsa             string `json:"signing_public_key_mldsa,omitempty"`
	EncryptedSigningPrivateKeyMldsa   string `json:"encrypted_signing_private_key_mldsa,omitempty"`
	SigningPrivateKeyMldsaNonce       string `json:"signing_private_key_mldsa_nonce,omitempty"`

	SigningPkHistory string `json:"signing_pk_history,omitempty"`
}

type E2EEPubkeyPayload struct {
	PublicKey      string `json:"public_key"`
	PublicKeyKyber string `json:"public_key_kyber"`
	Username       string `json:"username"`

	SigningPublicKeyEd25519 string `json:"signing_public_key_ed25519,omitempty"`
	SigningPublicKeyMldsa   string `json:"signing_public_key_mldsa,omitempty"`
	KeyBundleSig            string `json:"key_bundle_sig,omitempty"`
}

type E2EEListKeysPayload struct {
	Keys []E2EEKeyEntry `json:"keys"`
}

type E2EEKeyEntry struct {
	NodeID          string `json:"node_id"`
	SealedKey       string `json:"sealed_key,omitempty"`
	IsDir           bool   `json:"is_dir,omitempty"`
	IsTrashed       bool   `json:"is_trashed,omitempty"`
	E2EEDisplayName string `json:"e2ee_display_name,omitempty"`
	E2EEPathToken   string `json:"e2ee_path_token,omitempty"`
}

type progressReader struct {
	reader   io.Reader
	total    int64
	sent     int64
	progress func(sent, total int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.sent += int64(n)
		if pr.progress != nil {
			pr.progress(pr.sent, pr.total)
		}
	}
	return n, err
}

type TeeAttestationResponse struct {
	Success     bool `json:"success"`
	Enabled     bool `json:"enabled"`
	Available   bool `json:"available"`
	Attestation struct {
		EnclavePublicKey        string `json:"enclave_public_key"`
		EnclavePublicKeyKyber   string `json:"enclave_public_key_kyber"`
		EnclaveSigningPkEd25519 string `json:"enclave_signing_pk_ed25519"`
		EnclaveSigningPkMldsa   string `json:"enclave_signing_pk_mldsa"`
		AttestationMode         string `json:"attestation_mode"`
		SgxQuote                string `json:"sgx_quote"`
		Mrenclave               string `json:"mrenclave"`
		VerificationStatus      string `json:"verification_status"`
		Busy         bool  `json:"busy"`
		RetryAfterMs int64 `json:"retry_after_ms"`
	} `json:"attestation"`
}

var TeeAttestationRetryDelays = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second}

const maxTeeAttestationWait = 30 * time.Second

func (c *Client) FetchTeeAttestation(ctx context.Context) (*TeeAttestationResponse, error) {
	for attempt := 0; ; attempt++ {
		result, err := c.fetchTeeAttestationOnce(ctx)
		if err == nil {
			return result, nil
		}
		if attempt >= len(TeeAttestationRetryDelays) || !(IsTransient(err) || IsRateLimited(err)) || ctx.Err() != nil {
			return nil, err
		}
		delay := max(TeeAttestationRetryDelays[attempt], min(RetryAfterHint(err), maxTeeAttestationWait))
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *Client) fetchTeeAttestationOnce(ctx context.Context) (*TeeAttestationResponse, error) {
	endpoint := c.actionEndpoint("tee-attestation")
	ctx, cancel := c.requestCtx(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	c.setCommonHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if transportRetryable(err) {
			return nil, &RequestError{Kind: KindTransient, Err: fmt.Errorf("tee attestation request failed: %w", err)}
		}
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, ResponseSizeLimit))
	if err != nil {
		return nil, &RequestError{Kind: KindTransient, StatusCode: resp.StatusCode, Err: fmt.Errorf("tee attestation read failed: %w", err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, statusError(resp, fmt.Errorf("tee_attestation_unanswered: the server answered the attestation probe with HTTP %d%s", resp.StatusCode, attestationFailureDetail(body)))
	}
	var result TeeAttestationResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, &RequestError{Kind: KindTransient, StatusCode: resp.StatusCode, Err: fmt.Errorf("tee_attestation_unanswered: the attestation reply is not JSON: %w", err)}
	}
	if !result.Success {
		return nil, &RequestError{Kind: KindTransient, StatusCode: resp.StatusCode, Err: fmt.Errorf("tee_attestation_unanswered: the server did not answer the attestation probe%s", attestationFailureDetail(body))}
	}
	if result.Available && result.Attestation.Busy {
		return nil, &RequestError{
			Kind:       KindTransient,
			StatusCode: resp.StatusCode,
			RetryAfter: time.Duration(max(result.Attestation.RetryAfterMs, 0)) * time.Millisecond,
			Err:        errors.New("tee_attestation_unanswered: the scanner shed the attestation probe as busy"),
		}
	}
	return &result, nil
}

func attestationFailureDetail(body []byte) string {
	var reply struct {
		Error     string `json:"error"`
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return ""
	}
	code := reply.ErrorCode
	if code == "" {
		code = reply.Error
	}
	if code == "" || len(code) > 64 || strings.ContainsAny(code, " \n\r\t") {
		return ""
	}
	return " (" + code + ")"
}

const StaleTeeSealCode = "scanner_unavailable"

func MayBeStaleTeeSeal(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == StaleTeeSealCode
}
