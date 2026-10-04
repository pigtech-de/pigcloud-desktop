package mobile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

const (
	testKDFOps uint32 = 1
	testKDFMem uint32 = 8 * 1024 * 1024
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func newTestSession(t *testing.T) (*Session, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	cfg, err := json.Marshal(sessionConfig{
		Endpoint:  "https://local.test/cloud/actions.php",
		APIKey:    "pc_live_test",
		ConfigDir: filepath.Join(dir, "pigcloud"),
		CacheDir:  filepath.Join(dir, "cache"),
	})
	if err != nil {
		t.Fatalf("marshal session config: %v", err)
	}
	s, err := NewSession(string(cfg))
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	t.Cleanup(func() {
		s.Close()
		config.SetConfigFile("")
		config.SetSecretStore(nil)
	})
	return s, dir
}

func newKeyBlob(t *testing.T, password string) string {
	t.Helper()
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("hybrid keygen: %v", err)
	}
	signPub, signPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("signing keygen: %v", err)
	}
	salt := make([]byte, crypto.SaltSize)
	for i := range salt {
		salt[i] = byte(i)
	}
	pdk := crypto.DeriveKey([]byte(password), salt, testKDFOps, testKDFMem)

	enc, err := crypto.EncryptHybridPrivateKeyWithKey(priv, pdk)
	if err != nil {
		t.Fatalf("wrap encryption keys: %v", err)
	}
	sign, err := crypto.EncryptSigningPrivateKeysWithKey(signPriv, pdk)
	if err != nil {
		t.Fatalf("wrap signing keys: %v", err)
	}

	blob := keyBlob{
		PublicKey:                         b64(pub.X25519[:]),
		EncryptedPrivateKey:               b64(enc.X25519Ciphertext),
		PrivateKeyNonce:                   b64(enc.X25519Nonce),
		PublicKeyKyber:                    b64(pub.Kyber),
		EncryptedPrivateKeyKyber:          b64(enc.KyberCiphertext),
		PrivateKeyKyberNonce:              b64(enc.KyberNonce),
		SigningPublicKeyEd25519:           b64(signPub.Ed25519[:]),
		EncryptedSigningPrivateKeyEd25519: b64(sign.Ed25519Ciphertext),
		SigningPrivateKeyEd25519Nonce:     b64(sign.Ed25519Nonce),
		SigningPublicKeyMldsa:             b64(signPub.Mldsa),
		EncryptedSigningPrivateKeyMldsa:   b64(sign.MldsaCiphertext),
		SigningPrivateKeyMldsaNonce:       b64(sign.MldsaNonce),
		KDFSalt:                           b64(salt),
		KDFOpsLimit:                       testKDFOps,
		KDFMemLimit:                       testKDFMem,
		Password:                          password,
	}
	encoded, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal key blob: %v", err)
	}
	return string(encoded)
}

func TestUnlockImportsAKeyBlobWithoutAKeyring(t *testing.T) {
	s, _ := newTestSession(t)

	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock with a well-formed blob: %v", err)
	}
	if !s.Unlocked() {
		t.Fatal("the session reports locked after a successful import")
	}
	if config.APIKeyInKeychain() {
		t.Error("the binding put the API key in a secret store; a mobile host owns that")
	}

	sealed, err := s.SealName(`{"file_name":"IMG_0042.HEIC","full_path":"Camera/IMG_0042.HEIC"}`)
	if err != nil {
		t.Fatalf("SealName: %v", err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(sealed), &fields); err != nil {
		t.Fatalf("SealName returned %q, which is not a JSON object: %v", sealed, err)
	}
	if fields["e2ee_display_name"] == "" || fields["e2ee_path_token"] == "" {
		t.Fatalf("SealName left a field empty: %v", fields)
	}

	again, err := s.SealName(`{"file_name":"IMG_0042.HEIC","full_path":"Camera/IMG_0042.HEIC"}`)
	if err != nil {
		t.Fatalf("SealName (second call): %v", err)
	}
	var second map[string]string
	if err := json.Unmarshal([]byte(again), &second); err != nil {
		t.Fatalf("parse second SealName: %v", err)
	}
	if second["e2ee_path_token"] != fields["e2ee_path_token"] {
		t.Error("the path token is not deterministic; the server could not resolve the same folder twice")
	}
	if second["e2ee_display_name"] == fields["e2ee_display_name"] {
		t.Error("two seals of one name produced identical blobs; the seal is not randomised")
	}

	s.Lock()
	if s.Unlocked() {
		t.Error("Lock left key material behind")
	}
}

func TestUnlockRefusesTheWrongPassword(t *testing.T) {
	s, _ := newTestSession(t)

	var blob keyBlob
	if err := json.Unmarshal([]byte(newKeyBlob(t, "the real password")), &blob); err != nil {
		t.Fatalf("parse blob: %v", err)
	}
	blob.Password = "not the password"
	wrong, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal blob: %v", err)
	}

	if err := s.Unlock(string(wrong)); err == nil {
		t.Fatal("a wrong password unlocked the blob")
	}
	if s.Unlocked() {
		t.Error("a refused unlock left key material behind")
	}
	if _, err := s.SealName(`{"file_name":"a.jpg","full_path":"a.jpg"}`); err == nil {
		t.Error("SealName worked on a session that never unlocked")
	}
}

func TestSelfTestRunsTheEmbeddedVectors(t *testing.T) {
	out, err := SelfTest(true)
	if err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
	var report selfTestReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("SelfTest returned %q, which is not a JSON object: %v", out, err)
	}
	if !report.OK {
		t.Fatalf("SelfTest failed: %v", report.Failures)
	}
	want := []string{"hybrid_seal_v1", "name_token_v1", "pdk_argon2id_v1"}
	if len(report.Families) != len(want) {
		t.Fatalf("SelfTest covered %v, want %v", report.Families, want)
	}
	for i, family := range want {
		if report.Families[i] != family {
			t.Errorf("family %d = %q, want %q", i, report.Families[i], family)
		}
	}
	if report.Version != Version {
		t.Errorf("report version %q, want %q", report.Version, Version)
	}
}

func scannerOffServer(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") == "tee-attestation" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"success":true,"enabled":false,"available":false}`)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL + "/cloud/actions.php"
}

func TestAFailedUploadHandsBackAResumableCursor(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	scannerOffServer(t)

	local := filepath.Join(dir, "capture.bin")
	if err := os.WriteFile(local, []byte("pretend this is a 4K clip"), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	request, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	out, err := s.Upload(string(request), nil)
	if err != nil {
		t.Fatalf("Upload returned a transport error instead of a result: %v", err)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("Upload returned %q, which is not a JSON object: %v", out, err)
	}
	if result.OK {
		t.Fatal("the upload reported success with no server to talk to")
	}
	if result.Cursor == "" {
		t.Fatal("a failed upload returned no cursor; the host would have to re-encrypt")
	}

	var cursor uploadCursor
	if err := json.Unmarshal([]byte(result.Cursor), &cursor); err != nil {
		t.Fatalf("parse cursor: %v", err)
	}
	if _, statErr := os.Stat(cursor.EncryptedPath); statErr != nil {
		t.Fatalf("the cursor names a ciphertext that is not on disk: %v", statErr)
	}
	for _, field := range []string{"sealed_key", "encryption_meta", "signature_ed25519", "e2ee_display_name", "e2ee_path_token", "upload_idempotency_key", "_original_name"} {
		if cursor.Options[field] == "" {
			t.Errorf("cursor lost %q; a resume would send an incomplete upload", field)
		}
	}

	retry, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.bin", Cursor: result.Cursor})
	if err != nil {
		t.Fatalf("marshal retry: %v", err)
	}
	out, err = s.Upload(string(retry), nil)
	if err != nil {
		t.Fatalf("resumed Upload: %v", err)
	}
	var second uploadResult
	if err := json.Unmarshal([]byte(out), &second); err != nil {
		t.Fatalf("parse resumed result: %v", err)
	}
	var resumed uploadCursor
	if err := json.Unmarshal([]byte(second.Cursor), &resumed); err != nil {
		t.Fatalf("parse resumed cursor: %v", err)
	}
	if resumed.EncryptedPath != cursor.EncryptedPath {
		t.Error("the resume re-encrypted the file instead of reusing the cursor's ciphertext")
	}
	if resumed.Options["upload_idempotency_key"] != cursor.Options["upload_idempotency_key"] {
		t.Error("the resume minted a fresh idempotency key; the server would not dedupe the retry")
	}

	if err := s.DiscardCursor(result.Cursor); err != nil {
		t.Fatalf("DiscardCursor: %v", err)
	}
	if _, statErr := os.Stat(cursor.EncryptedPath); !os.IsNotExist(statErr) {
		t.Error("DiscardCursor left the ciphertext on disk")
	}
}

func TestASpentScanBudgetHandsTheHostTheServersWait(t *testing.T) {
	s, dir := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("action") == "tee-attestation" {
			fmt.Fprint(w, `{"success":true,"enabled":false,"available":false}`)
			return
		}
		w.Header().Set("Retry-After", "3000")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"success":false,"errorCode":"rate_limited","retryAfter":3000,"bucket":"tee_scan","message":"Hourly upload limit reached."}`)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL + "/cloud/actions.php"

	local := filepath.Join(dir, "capture.jpg")
	if err := os.WriteFile(local, []byte("pretend this is a photo"), 0o600); err != nil {
		t.Fatalf("write local file: %v", err)
	}
	request, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera", FileName: "capture.jpg"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	out, err := s.Upload(string(request), nil)
	if err != nil {
		t.Fatalf("Upload returned a transport error instead of a result: %v", err)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("Upload returned %q: %v", out, err)
	}
	if result.OK || !result.Retryable || result.Cursor == "" {
		t.Fatalf("a spent budget must come back retryable with a cursor to resume: %+v", result)
	}
	if result.RetryAfterSeconds != 3000 {
		t.Errorf("retry_after_seconds = %d, want the server's 3000; resuming earlier re-sends the body into the same refusal", result.RetryAfterSeconds)
	}
	if err := s.DiscardCursor(result.Cursor); err != nil {
		t.Fatalf("DiscardCursor: %v", err)
	}
}
