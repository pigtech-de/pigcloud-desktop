package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
)

const (
	minKDFOpsLimit uint32 = 1
	minKDFMemLimit uint32 = 8 * 1024 * 1024
	maxKDFMemLimit uint32 = 512 * 1024 * 1024
)

type ProgressSink interface {
	OnProgress(sent int64, total int64)
}

var (
	liveMu      sync.Mutex
	liveSession *Session
)

type Session struct {
	mu        sync.Mutex
	keys      *e2ee.Session
	cacheDir  string
	cancel    context.CancelFunc
	uploading bool
}

const stagingPrefix = "pigcloud-e2ee-"

type sessionConfig struct {
	Endpoint  string `json:"endpoint"`
	APIKey    string `json:"api_key"`
	ConfigDir string `json:"config_dir"`
	CacheDir  string `json:"cache_dir"`
	Language  string `json:"language"`
}

func recovered(call string, err *error) {
	r := recover()
	if r == nil {
		return
	}
	*err = fmt.Errorf("%s: recovered from panic: %v", call, r)
}

func NewSession(configJSON string) (s *Session, err error) {
	defer recovered("NewSession", &err)

	var cfg sessionConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, fmt.Errorf("parse session config: %w", err)
	}
	if cfg.ConfigDir == "" {
		return nil, errors.New("session config needs a writable config_dir")
	}
	if cfg.CacheDir == "" {
		return nil, errors.New("session config needs a writable cache_dir for upload staging")
	}
	for _, dir := range []string{cfg.ConfigDir, cfg.CacheDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	cacheDir, err := filepath.Abs(cfg.CacheDir)
	if err != nil {
		return nil, fmt.Errorf("resolve cache_dir: %w", err)
	}

	enrolMu.Lock()
	enrolOpen := enrolLive != nil
	enrolMu.Unlock()
	if enrolOpen {
		return nil, errors.New("an enrolment is running in this process; close it before creating a Session")
	}

	liveMu.Lock()
	defer liveMu.Unlock()
	if liveSession != nil {
		return nil, errors.New("a Session already exists in this process; close it before creating another")
	}

	config.SetSecretStore(config.NewMemorySecretStore())
	config.SetConfigFile(filepath.Join(cfg.ConfigDir, "config.json"))
	config.Load()

	c := config.Get()
	if cfg.Endpoint != "" {
		c.Endpoint = cfg.Endpoint
	}
	if cfg.APIKey != "" {
		c.APIKey = cfg.APIKey
	}
	if cfg.Language != "" {
		c.Language = cfg.Language
	}

	keys := e2ee.NewSession(nil, nil)
	keys.SetStagingDir(cacheDir)
	liveSession = &Session{keys: keys, cacheDir: cacheDir}
	return liveSession, nil
}

func (s *Session) Close() {
	s.Cancel()
	s.Lock()
	liveMu.Lock()
	defer liveMu.Unlock()
	if liveSession == s {
		liveSession = nil
	}
}

type keyBlob struct {
	PublicKey                string `json:"public_key"`
	EncryptedPrivateKey      string `json:"encrypted_private_key"`
	PrivateKeyNonce          string `json:"private_key_nonce"`
	PublicKeyKyber           string `json:"public_key_kyber"`
	EncryptedPrivateKeyKyber string `json:"encrypted_private_key_kyber"`
	PrivateKeyKyberNonce     string `json:"private_key_kyber_nonce"`

	SigningPublicKeyEd25519           string `json:"signing_public_key_ed25519"`
	EncryptedSigningPrivateKeyEd25519 string `json:"encrypted_signing_private_key_ed25519"`
	SigningPrivateKeyEd25519Nonce     string `json:"signing_private_key_ed25519_nonce"`
	SigningPublicKeyMldsa             string `json:"signing_public_key_mldsa"`
	EncryptedSigningPrivateKeyMldsa   string `json:"encrypted_signing_private_key_mldsa"`
	SigningPrivateKeyMldsaNonce       string `json:"signing_private_key_mldsa_nonce"`

	KDFSalt     string `json:"kdf_salt"`
	KDFOpsLimit uint32 `json:"kdf_ops_limit"`
	KDFMemLimit uint32 `json:"kdf_mem_limit"`

	Password string `json:"password"`
}

func (b *keyBlob) validate() error {
	if b.Password == "" {
		return errors.New("key blob needs the account password to unwrap")
	}
	if b.KDFOpsLimit < minKDFOpsLimit {
		return fmt.Errorf("kdf_ops_limit is %d, want at least %d", b.KDFOpsLimit, minKDFOpsLimit)
	}
	if b.KDFMemLimit < minKDFMemLimit || b.KDFMemLimit > maxKDFMemLimit {
		return fmt.Errorf("kdf_mem_limit is %d, want %d to %d", b.KDFMemLimit, minKDFMemLimit, maxKDFMemLimit)
	}
	salt, err := base64.StdEncoding.DecodeString(b.KDFSalt)
	if err != nil {
		return fmt.Errorf("kdf_salt is not base64: %w", err)
	}
	if len(salt) != crypto.SaltSize {
		return fmt.Errorf("kdf_salt is %d bytes, want %d", len(salt), crypto.SaltSize)
	}
	required := map[string]string{
		"public_key":                  b.PublicKey,
		"encrypted_private_key":       b.EncryptedPrivateKey,
		"private_key_nonce":           b.PrivateKeyNonce,
		"public_key_kyber":            b.PublicKeyKyber,
		"encrypted_private_key_kyber": b.EncryptedPrivateKeyKyber,
		"private_key_kyber_nonce":     b.PrivateKeyKyberNonce,
	}
	for name, value := range required {
		if value == "" {
			return fmt.Errorf("key blob is missing %s", name)
		}
		if _, err := base64.StdEncoding.DecodeString(value); err != nil {
			return fmt.Errorf("%s is not base64: %w", name, err)
		}
	}
	return nil
}

func (s *Session) Unlock(keyBlobJSON string) (err error) {
	defer recovered("Unlock", &err)

	var blob keyBlob
	if err := json.Unmarshal([]byte(keyBlobJSON), &blob); err != nil {
		return fmt.Errorf("parse key blob: %w", err)
	}
	if err := blob.validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c := config.Get()
	c.PublicKey = blob.PublicKey
	c.EncryptedPrivateKey = blob.EncryptedPrivateKey
	c.PrivateKeyNonce = blob.PrivateKeyNonce
	c.PublicKeyKyber = blob.PublicKeyKyber
	c.EncryptedPrivateKeyKyber = blob.EncryptedPrivateKeyKyber
	c.PrivateKeyKyberNonce = blob.PrivateKeyKyberNonce
	c.SigningPublicKeyEd25519 = blob.SigningPublicKeyEd25519
	c.EncryptedSigningPrivateKeyEd25519 = blob.EncryptedSigningPrivateKeyEd25519
	c.SigningPrivateKeyEd25519Nonce = blob.SigningPrivateKeyEd25519Nonce
	c.SigningPublicKeyMldsa = blob.SigningPublicKeyMldsa
	c.EncryptedSigningPrivateKeyMldsa = blob.EncryptedSigningPrivateKeyMldsa
	c.SigningPrivateKeyMldsaNonce = blob.SigningPrivateKeyMldsaNonce
	c.KDFSalt = blob.KDFSalt
	c.KDFOpsLimit = blob.KDFOpsLimit
	c.KDFMemLimit = blob.KDFMemLimit
	c.E2EEStorageMode = ""

	s.keys.ClearCachedKey()
	s.keys.SetSuppliedPassword([]byte(blob.Password))
	_, _, err = s.keys.KeyPair()
	return err
}

func (s *Session) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys.ClearCachedKey()
}

func (s *Session) Cancel() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Session) SweepStaging() (removed int, err error) {
	defer recovered("SweepStaging", &err)
	return s.sweep(nil)
}

func (s *Session) SweepStagingExcept(keepCursorsJSON string) (removed int, err error) {
	defer recovered("SweepStagingExcept", &err)

	var cursors []string
	if err := json.Unmarshal([]byte(keepCursorsJSON), &cursors); err != nil {
		return 0, fmt.Errorf("parse kept cursors: %w", err)
	}
	keep := map[string]bool{}
	for _, raw := range cursors {
		var cursor uploadCursor
		if json.Unmarshal([]byte(raw), &cursor) != nil || s.underCacheDir(cursor.EncryptedPath) != nil {
			continue
		}
		keep[filepath.Base(cursor.EncryptedPath)] = true
	}
	return s.sweep(keep)
}

func (s *Session) sweep(keep map[string]bool) (removed int, err error) {
	entries, err := os.ReadDir(s.cacheDir)
	if err != nil {
		return 0, fmt.Errorf("read the session cache dir: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), stagingPrefix) || keep[entry.Name()] {
			continue
		}
		if rmErr := os.Remove(filepath.Join(s.cacheDir, entry.Name())); rmErr == nil {
			removed++
		}
	}
	return removed, nil
}

func (s *Session) Unlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys.IsBackground() || s.keys.EnsureKeysFromAgent()
}

type sealNameRequest struct {
	FileName string `json:"file_name"`
	FullPath string `json:"full_path"`
}

func (s *Session) SealName(requestJSON string) (out string, err error) {
	defer recovered("SealName", &err)

	var req sealNameRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return "", fmt.Errorf("parse seal-name request: %w", err)
	}
	if err := validFileName(req.FileName); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	fields := map[string]string{}
	if err := s.keys.AddE2eeNameFields(fields, req.FileName, strings.TrimLeft(req.FullPath, "/")); err != nil {
		return "", err
	}
	return encodeJSON(fields)
}

func (s *Session) PathTokens(remotePath string, depth int) (out string, err error) {
	defer recovered("PathTokens", &err)

	scope := e2ee.SelfOnly
	switch depth {
	case 1:
		scope = e2ee.SelfAndParent
	case 2:
		scope = e2ee.SelfAndAncestors
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	options := map[string]string{}
	if err := s.keys.AddPathTokensFor(options, remotePath, scope); err != nil {
		return "", err
	}
	return encodeJSON(options)
}

type uploadRequest struct {
	LocalPath string `json:"local_path"`
	RemoteDir string `json:"remote_dir"`
	FileName  string `json:"file_name"`
	Cursor    string `json:"cursor"`
}

type uploadCursor struct {
	EncryptedPath string            `json:"encrypted_path"`
	RemoteDir     string            `json:"remote_dir"`
	FileName      string            `json:"file_name"`
	TotalBytes    int64             `json:"total_bytes"`
	Options       map[string]string `json:"options"`
}

type uploadResult struct {
	OK                bool   `json:"ok"`
	Message           string `json:"message"`
	Cursor            string `json:"cursor"`
	Bytes             int64  `json:"bytes"`
	Retryable         bool   `json:"retryable"`
	NodeID            string `json:"node_id,omitempty"`
	ErrorClass        string `json:"error_class,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
	RetryAfterSeconds int64  `json:"retry_after_seconds,omitempty"`
}

func validFileName(name string) error {
	if name == "" {
		return errors.New("file_name is empty")
	}
	if name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("file_name %q must be a bare name, not a path", name)
	}
	return nil
}

func (s *Session) Upload(requestJSON string, sink ProgressSink) (out string, err error) {
	var cursor *uploadCursor
	defer func() {
		if r := recover(); r != nil {
			out, err = failedUpload(fmt.Errorf("Upload: recovered from panic: %v", r), cursor)
		}
	}()

	var req uploadRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return "", fmt.Errorf("parse upload request: %w", err)
	}
	if req.FileName == "" {
		req.FileName = filepath.Base(req.LocalPath)
	}
	if err := validFileName(req.FileName); err != nil {
		return failedUpload(badInputError{err}, nil)
	}
	remoteDir, err := cleanRemoteDir(req.RemoteDir)
	if err != nil {
		return failedUpload(badInputError{err}, nil)
	}
	req.RemoteDir = remoteDir

	ctx, cancel, err := s.beginUpload()
	if err != nil {
		return failedUpload(err, nil)
	}
	defer s.endUpload(cancel)

	cursor, err = s.resumeOrPrepare(ctx, &req)
	if err != nil {
		return failedUpload(err, cursor)
	}

	guard := &sinkGuard{cancel: cancel}
	report := guard.report(sink)

	options := make(map[string]string, len(cursor.Options))
	for k, v := range cursor.Options {
		options[k] = v
	}

	client := api.NewClient().ParkScanBudget()
	resp, err := client.Upload(ctx, cursor.EncryptedPath, cursor.RemoteDir, report, options)
	if blown := guard.failure(); blown != nil {
		return failedUpload(blown, cursor)
	}
	if err != nil {
		return failedUpload(err, cursor)
	}
	if resp == nil || !resp.Success {
		message := "upload refused"
		if resp != nil && resp.Message != "" {
			message = resp.Message
		}
		if resp == nil {
			return failedUpload(errors.New(message), cursor)
		}
		return failedUpload(refusalError(resp, message), cursor)
	}

	os.Remove(cursor.EncryptedPath)
	return encodeJSON(uploadResult{OK: true, Message: resp.Message, Bytes: cursor.TotalBytes, NodeID: uploadedNodeID(resp.Raw)})
}

type sinkGuard struct {
	mu       sync.Mutex
	panicked any
	cancel   context.CancelFunc
}

func (g *sinkGuard) report(sink ProgressSink) func(sent, total int64) {
	if sink == nil {
		return nil
	}
	return func(sent, total int64) {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			g.mu.Lock()
			if g.panicked == nil {
				g.panicked = r
			}
			g.mu.Unlock()
			g.cancel()
		}()
		sink.OnProgress(sent, total)
	}
}

func (g *sinkGuard) failure() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.panicked == nil {
		return nil
	}
	return fmt.Errorf("the progress callback panicked: %v", g.panicked)
}

func (s *Session) beginUpload() (context.Context, context.CancelFunc, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.uploading {
		return nil, nil, errors.New("an upload is already running on this Session; wait for it or call Cancel")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.uploading = true
	s.cancel = cancel
	return ctx, cancel, nil
}

func (s *Session) endUpload(cancel context.CancelFunc) {
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.uploading = false
	s.cancel = nil
}

func cleanRemoteDir(dir string) (string, error) {
	if dir == "" {
		return "/", nil
	}
	if strings.Contains(dir, `\`) {
		return "", fmt.Errorf("remote_dir %q must use forward slashes", dir)
	}
	if !strings.HasPrefix(dir, "/") {
		return "", fmt.Errorf("remote_dir %q must be absolute", dir)
	}
	for _, segment := range strings.Split(dir, "/") {
		if segment == ".." {
			return "", fmt.Errorf("remote_dir %q must not contain a parent segment", dir)
		}
	}
	cleaned := path.Clean(dir)
	if !strings.HasPrefix(cleaned, "/") {
		return "", fmt.Errorf("remote_dir %q does not stay absolute once cleaned", dir)
	}
	return cleaned, nil
}

func (s *Session) resumeOrPrepare(ctx context.Context, req *uploadRequest) (*uploadCursor, error) {
	if req.Cursor != "" {
		var cursor uploadCursor
		if err := json.Unmarshal([]byte(req.Cursor), &cursor); err != nil {
			return nil, fmt.Errorf("parse upload cursor: %w", err)
		}
		if err := s.underCacheDir(cursor.EncryptedPath); err != nil {
			return nil, err
		}
		if _, err := os.Stat(cursor.EncryptedPath); err == nil {
			return &cursor, nil
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	artifacts, err := s.keys.EncryptForUpload(ctx, req.LocalPath)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		os.Remove(artifacts.EncryptedPath)
		return nil, err
	}

	options := map[string]string{
		"sealed_key":             artifacts.SealedKeyB64,
		"encryption_meta":        artifacts.EncMetaB64,
		"_original_name":         req.FileName,
		"upload_idempotency_key": api.NewUploadIdempotencyKey(),
	}
	if artifacts.TeeSealedKeyB64 != "" {
		options["tee_sealed_key"] = artifacts.TeeSealedKeyB64
	}
	if artifacts.PlaintextHmacHex != "" {
		options["plaintext_hmac"] = artifacts.PlaintextHmacHex
	}

	sigs, err := s.keys.SignEncryptedFile(artifacts.EncryptedPath)
	if err != nil {
		os.Remove(artifacts.EncryptedPath)
		return nil, err
	}
	options["signature_ed25519"] = sigs.SignatureEd25519B64
	options["signature_mldsa"] = sigs.SignatureMldsaB64
	options["signing_pk_ed25519"] = sigs.SigningPkEd25519B64
	options["signing_pk_mldsa"] = sigs.SigningPkMldsaB64

	if err := ctx.Err(); err != nil {
		os.Remove(artifacts.EncryptedPath)
		return nil, err
	}

	fullPath := strings.TrimLeft(path.Join(req.RemoteDir, req.FileName), "/")
	if err := s.keys.AddE2eeNameFields(options, req.FileName, fullPath); err != nil {
		os.Remove(artifacts.EncryptedPath)
		return nil, err
	}
	if err := s.keys.AddPathTokensFor(options, req.RemoteDir, e2ee.SelfAndParent); err != nil {
		os.Remove(artifacts.EncryptedPath)
		return nil, err
	}

	var total int64
	if stat, statErr := os.Stat(artifacts.EncryptedPath); statErr == nil {
		total = stat.Size()
	}

	return &uploadCursor{
		EncryptedPath: artifacts.EncryptedPath,
		RemoteDir:     req.RemoteDir,
		FileName:      req.FileName,
		TotalBytes:    total,
		Options:       options,
	}, nil
}

func (s *Session) underCacheDir(p string) error {
	if p == "" {
		return errors.New("cursor names no ciphertext")
	}
	root, err := filepath.EvalSymlinks(s.cacheDir)
	if err != nil {
		return fmt.Errorf("resolve the session cache dir: %w", err)
	}
	candidate, err := resolveThroughLinks(p)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("cursor path %q is outside the session cache dir", p)
	}
	return nil
}

func resolveThroughLinks(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve cursor path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", fmt.Errorf("resolve the cursor path's directory: %w", err)
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

func failedUpload(cause error, cursor *uploadCursor) (string, error) {
	verdict := classifyUpload(cause)
	result := uploadResult{
		Message:           cause.Error(),
		Retryable:         verdict.retryable(),
		ErrorClass:        verdict.class,
		ErrorCode:         verdict.code,
		RetryAfterSeconds: int64((verdict.retryAfter + time.Second - 1) / time.Second),
	}
	if cursor != nil {
		result.Bytes = cursor.TotalBytes
		if encoded, err := json.Marshal(cursor); err == nil {
			result.Cursor = string(encoded)
		}
	}
	return encodeJSON(result)
}

func (s *Session) DiscardCursor(cursorJSON string) (err error) {
	defer recovered("DiscardCursor", &err)

	var cursor uploadCursor
	if err := json.Unmarshal([]byte(cursorJSON), &cursor); err != nil {
		return fmt.Errorf("parse upload cursor: %w", err)
	}
	if err := s.underCacheDir(cursor.EncryptedPath); err != nil {
		return err
	}
	if err := os.Remove(cursor.EncryptedPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func encodeJSON(v any) (string, error) {
	encoded, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
