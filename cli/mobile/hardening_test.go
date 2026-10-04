package mobile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func blobWith(t *testing.T, mutate func(*keyBlob)) string {
	t.Helper()
	var blob keyBlob
	if err := json.Unmarshal([]byte(newKeyBlob(t, "correct horse battery staple")), &blob); err != nil {
		t.Fatalf("parse blob: %v", err)
	}
	mutate(&blob)
	encoded, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal blob: %v", err)
	}
	return string(encoded)
}

func assertConfigUntouched(t *testing.T, before *config.Config) {
	t.Helper()
	after := config.Get()
	fields := map[string][2]string{
		"public_key":                            {before.PublicKey, after.PublicKey},
		"encrypted_private_key":                 {before.EncryptedPrivateKey, after.EncryptedPrivateKey},
		"private_key_nonce":                     {before.PrivateKeyNonce, after.PrivateKeyNonce},
		"public_key_kyber":                      {before.PublicKeyKyber, after.PublicKeyKyber},
		"encrypted_private_key_kyber":           {before.EncryptedPrivateKeyKyber, after.EncryptedPrivateKeyKyber},
		"private_key_kyber_nonce":               {before.PrivateKeyKyberNonce, after.PrivateKeyKyberNonce},
		"encrypted_signing_private_key_ed25519": {before.EncryptedSigningPrivateKeyEd25519, after.EncryptedSigningPrivateKeyEd25519},
		"encrypted_signing_private_key_mldsa":   {before.EncryptedSigningPrivateKeyMldsa, after.EncryptedSigningPrivateKeyMldsa},
		"kdf_salt":                              {before.KDFSalt, after.KDFSalt},
		"e2ee_storage_mode":                     {before.E2EEStorageMode, after.E2EEStorageMode},
	}
	for name, pair := range fields {
		if pair[0] != pair[1] {
			t.Errorf("a rejected blob rewrote %s (%q -> %q); validation must run before any config write", name, pair[0], pair[1])
		}
	}
	if before.KDFOpsLimit != after.KDFOpsLimit {
		t.Errorf("a rejected blob rewrote kdf_ops_limit (%d -> %d)", before.KDFOpsLimit, after.KDFOpsLimit)
	}
	if before.KDFMemLimit != after.KDFMemLimit {
		t.Errorf("a rejected blob rewrote kdf_mem_limit (%d -> %d)", before.KDFMemLimit, after.KDFMemLimit)
	}
}

func TestAMalformedKeyBlobIsRefusedWithoutPanicking(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*keyBlob)
		want   string
	}{
		{"zero ops limit", func(b *keyBlob) { b.KDFOpsLimit = 0 }, "kdf_ops_limit"},
		{"absurd mem limit", func(b *keyBlob) { b.KDFMemLimit = 4294967295 }, "kdf_mem_limit"},
		{"tiny mem limit", func(b *keyBlob) { b.KDFMemLimit = 1024 }, "kdf_mem_limit"},
		{"salt not base64", func(b *keyBlob) { b.KDFSalt = "!!!" }, "kdf_salt"},
		{"salt wrong length", func(b *keyBlob) { b.KDFSalt = b64(make([]byte, crypto.SaltSize-1)) }, "kdf_salt"},
		{"no password", func(b *keyBlob) { b.Password = "" }, "password"},
		{"public key absent", func(b *keyBlob) { b.PublicKey = "" }, "public_key"},
		{"public key not base64", func(b *keyBlob) { b.PublicKey = "!!!" }, "base64"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestSession(t)
			before := *config.Get()

			err := s.Unlock(blobWith(t, tc.mutate))
			if err == nil {
				t.Fatal("a malformed blob was accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "recovered from panic") {
				t.Errorf("the refusal came from a recovered panic, not validation: %v", err)
			}
			if s.Unlocked() {
				t.Error("a refused blob left key material behind")
			}
			assertConfigUntouched(t, &before)
		})
	}
}

func TestEveryExportedCallSurvivesGarbageInput(t *testing.T) {
	s, _ := newTestSession(t)

	if _, err := s.SealName("not json"); err == nil {
		t.Error("SealName accepted garbage")
	}
	if _, err := s.PathTokens("/x", 99); err == nil && s.Unlocked() {
		t.Error("PathTokens accepted an out-of-range depth on an unlocked session")
	}
	if _, err := s.Upload("not json", nil); err == nil {
		t.Error("Upload accepted garbage")
	}
	if err := s.DiscardCursor("not json"); err == nil {
		t.Error("DiscardCursor accepted garbage")
	}
	if err := s.Unlock("not json"); err == nil {
		t.Error("Unlock accepted garbage")
	}
	if _, err := NewSession("not json"); err == nil {
		t.Error("NewSession accepted garbage")
	}
}

func TestASecondSessionIsRefused(t *testing.T) {
	_, dir := newTestSession(t)

	cfg, err := json.Marshal(sessionConfig{
		ConfigDir: filepath.Join(dir, "second"),
		CacheDir:  filepath.Join(dir, "second-cache"),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := NewSession(string(cfg))
	if err == nil {
		second.Close()
		t.Fatal("a second Session was created; it would retarget the first one's global config")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error %q does not explain the single-session rule", err)
	}
}

func TestStagingLandsUnderTheCacheDir(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	scannerOffServer(t)

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("bytes"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out, err := s.Upload(string(req), nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.Cursor == "" {
		t.Fatal("no cursor, so there is no staging path to check")
	}
	var cursor uploadCursor
	if err := json.Unmarshal([]byte(result.Cursor), &cursor); err != nil {
		t.Fatalf("parse cursor: %v", err)
	}

	wantDir := filepath.Join(dir, "cache")
	if got := filepath.Dir(cursor.EncryptedPath); got != wantDir {
		t.Errorf("ciphertext staged in %q, want the session cache dir %q; on Android the OS temp dir is outside the sandbox", got, wantDir)
	}
}

func TestACursorOutsideTheCacheDirIsRefused(t *testing.T) {
	s, dir := newTestSession(t)

	outsider := filepath.Join(dir, "not-staging.bin")
	if err := os.WriteFile(outsider, []byte("victim"), 0o600); err != nil {
		t.Fatalf("write outsider: %v", err)
	}
	forged, err := json.Marshal(uploadCursor{EncryptedPath: outsider, RemoteDir: "/", FileName: "x.bin"})
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}

	if err := s.DiscardCursor(string(forged)); err == nil {
		t.Error("DiscardCursor removed a path the session never staged")
	}
	if _, err := os.Stat(outsider); err != nil {
		t.Errorf("the outside file was deleted anyway: %v", err)
	}

	if err := s.underCacheDir(filepath.Join(dir, "cache")); err == nil {
		t.Error("the cache dir itself was accepted as a ciphertext path")
	}
}

func TestASymlinkOutOfTheCacheDirIsRefused(t *testing.T) {
	s, dir := newTestSession(t)

	outside := filepath.Join(dir, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	victim := filepath.Join(outside, "victim.bin")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}

	link := filepath.Join(dir, "cache", "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("this host cannot create symlinks: %v", err)
	}

	through := filepath.Join(link, "victim.bin")
	if err := s.underCacheDir(through); err == nil {
		t.Error("a symlink inside the cache dir let a path out of it; a lexical prefix check is not enough")
	}

	forged, err := json.Marshal(uploadCursor{EncryptedPath: through, RemoteDir: "/", FileName: "victim.bin"})
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	if err := s.DiscardCursor(string(forged)); err == nil {
		t.Error("DiscardCursor followed the symlink out of the cache dir")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Errorf("the file outside the cache dir was deleted: %v", err)
	}
}

func TestATraversingFileNameIsRefused(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("bytes"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}

	for _, name := range []string{"../escape.jpg", "a/b.jpg", "..", `a\b.jpg`} {
		req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: name})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		out, err := s.Upload(string(req), nil)
		if err != nil {
			t.Fatalf("Upload(%q): %v", name, err)
		}
		var result uploadResult
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatalf("parse result: %v", err)
		}
		if result.OK {
			t.Errorf("file_name %q was accepted; it can climb out of the remote directory", name)
		}
		if _, err := s.SealName(`{"file_name":"` + strings.ReplaceAll(name, `\`, `\\`) + `","full_path":"Camera/x"}`); err == nil {
			t.Errorf("SealName accepted the traversing name %q", name)
		}
	}
}

func TestCancelStopsAnUploadInFlight(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "tee-attestation" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"enabled":false,"available":false}`))
			return
		}
		<-release
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(func() {
		close(release)
		srv.Close()
	})
	config.Get().Endpoint = srv.URL + "/cloud/actions.php"

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("a longer capture payload"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var wg sync.WaitGroup
	var out string
	var uploadErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		out, uploadErr = s.Upload(string(req), nil)
	}()

	deadline := time.After(20 * time.Second)
	for {
		s.mu.Lock()
		armed := s.cancel != nil
		s.mu.Unlock()
		if armed {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the upload never reached the transfer; Cancel would prove nothing")
		case <-time.After(5 * time.Millisecond):
		}
	}
	s.Cancel()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Cancel did not stop the upload")
	}

	if uploadErr != nil {
		t.Fatalf("Upload returned a transport error: %v", uploadErr)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.OK {
		t.Error("a cancelled upload reported success")
	}
}

func TestAProgressCallbackMayTouchTheSession(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	scannerOffServer(t)

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("bytes for the wire"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	sink := &reentrantSink{session: s}
	done := make(chan error, 1)
	go func() {
		_, err := s.Upload(string(req), sink)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Upload: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("a Session call from OnProgress deadlocked against the upload's own lock")
	}
	if !sink.called.Load() {
		t.Skip("the transport reported no progress, so the re-entrancy path never ran")
	}
}

type panickingSink struct{}

func (panickingSink) OnProgress(int64, int64) { panic("the host's callback blew up") }

func TestAPanickingProgressCallbackStillYieldsACursor(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	scannerOffServer(t)

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("bytes for the wire"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out, err := s.Upload(string(req), panickingSink{})
	if err != nil {
		t.Fatalf("a panicking callback escaped as an error instead of a result: %v", err)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.OK {
		t.Fatal("the upload reported success through a panicking callback")
	}
	if result.Cursor == "" {
		t.Fatal("a panicking callback orphaned the ciphertext with no cursor naming it")
	}

	var cursor uploadCursor
	if err := json.Unmarshal([]byte(result.Cursor), &cursor); err != nil {
		t.Fatalf("parse cursor: %v", err)
	}
	if _, statErr := os.Stat(cursor.EncryptedPath); statErr != nil {
		t.Fatalf("the cursor names a ciphertext that is gone: %v", statErr)
	}

	removed, err := s.SweepStaging()
	if err != nil {
		t.Fatalf("SweepStaging: %v", err)
	}
	if removed == 0 {
		t.Error("SweepStaging reclaimed nothing while staged ciphertext was on disk")
	}
	if _, statErr := os.Stat(cursor.EncryptedPath); !os.IsNotExist(statErr) {
		t.Error("SweepStaging left the staged ciphertext behind")
	}
}

func TestASecondConcurrentUploadIsRefused(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "tee-attestation" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"enabled":false,"available":false}`))
			return
		}
		<-release
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	config.Get().Endpoint = srv.URL + "/cloud/actions.php"

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("a capture payload"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	first := make(chan struct{})
	go func() {
		defer close(first)
		_, _ = s.Upload(string(req), nil)
	}()

	deadline := time.After(20 * time.Second)
	for {
		s.mu.Lock()
		busy := s.uploading
		s.mu.Unlock()
		if busy {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the first upload never claimed the slot")
		case <-time.After(5 * time.Millisecond):
		}
	}

	out, err := s.Upload(string(req), nil)
	if err != nil {
		t.Fatalf("the second Upload returned a transport error: %v", err)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.OK {
		t.Fatal("two uploads ran at once; the second would have overwritten the first's cancel func")
	}
	if !strings.Contains(result.Message, "already running") {
		t.Errorf("message %q does not explain the single-upload rule", result.Message)
	}

	s.Cancel()
	select {
	case <-first:
	case <-time.After(30 * time.Second):
		t.Fatal("the first upload never finished")
	}
}

func TestCancelDoesNotBlockBehindTheEncryptPass(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	transferStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "tee-attestation" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true,"enabled":false,"available":false}`))
			return
		}
		once.Do(func() { close(transferStarted) })
		<-release
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(func() { close(release); srv.Close() })
	config.Get().Endpoint = srv.URL + "/cloud/actions.php"

	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, 128*1024*1024), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: big, RemoteDir: "/Camera", FileName: "big.bin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.Upload(string(req), nil)
	}()

	var free, held int
	probe := time.After(3 * time.Second)
probing:
	for {
		if s.mu.TryLock() {
			s.mu.Unlock()
			free++
		} else {
			held++
		}
		select {
		case <-probe:
			break probing
		case <-transferStarted:
			break probing
		case <-done:
			break probing
		case <-time.After(2 * time.Millisecond):
		}
	}

	total := free + held
	if total < 10 {
		t.Fatalf("only %d lock probes ran; the window was too short to prove anything", total)
	}
	if free*5 < total*4 {
		t.Errorf("the Session lock was held on %d of %d probes during staging; Cancel would block behind the encrypt pass on a large capture", held, total)
	}

	start := time.Now()
	s.Cancel()
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("Cancel blocked %v behind the staging pass; it must return immediately", waited)
	}

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the upload never observed the cancellation")
	}
}

func TestARemoteDirThatEscapesIsRefused(t *testing.T) {
	good := map[string]string{
		"":                "/",
		"/":               "/",
		"/Camera":         "/Camera",
		"/Camera/":        "/Camera",
		"/Camera//Roll":   "/Camera/Roll",
		"/Camera/./Roll":  "/Camera/Roll",
		"/Camera/Roll/..": "",
	}
	for in, want := range good {
		got, err := cleanRemoteDir(in)
		if want == "" {
			if err == nil {
				t.Errorf("cleanRemoteDir(%q) accepted a parent segment, returning %q", in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("cleanRemoteDir(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("cleanRemoteDir(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"Camera", "../Camera", "/../etc", "/Camera/../../etc", `\Camera`, `/Camera\Roll`} {
		if got, err := cleanRemoteDir(bad); err == nil {
			t.Errorf("cleanRemoteDir(%q) was accepted, returning %q", bad, got)
		}
	}
}

type reentrantSink struct {
	session *Session
	called  atomicBool
}

func (r *reentrantSink) OnProgress(sent, total int64) {
	r.called.Store(true)
	r.session.Unlocked()
}

type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) Store(v bool) { a.mu.Lock(); a.v = v; a.mu.Unlock() }
func (a *atomicBool) Load() bool   { a.mu.Lock(); defer a.mu.Unlock(); return a.v }
