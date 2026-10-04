package mobile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func backgroundMaterialB64(t *testing.T) string {
	t.Helper()
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("hybrid keygen: %v", err)
	}
	_, signPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("signing keygen: %v", err)
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("name key: %v", err)
	}
	parentKey, err := crypto.DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("parent key: %v", err)
	}

	payload := make([]byte, 0, crypto.BackgroundKeyTransferSize)
	payload = append(payload, crypto.BackgroundKeyTransferVersion)
	payload = append(payload, nameKey...)
	payload = append(payload, parentKey...)
	payload = append(payload, signPriv.Ed25519...)
	payload = append(payload, signPriv.Mldsa...)
	payload = append(payload, pub.X25519[:]...)
	payload = append(payload, pub.Kyber...)
	return base64.StdEncoding.EncodeToString(payload)
}

func TestUnlockBackgroundSealsNamesWithoutAPassword(t *testing.T) {
	s, _ := newTestSession(t)

	if err := s.UnlockBackground(backgroundMaterialB64(t)); err != nil {
		t.Fatalf("UnlockBackground: %v", err)
	}
	if !s.BackgroundOnly() {
		t.Error("the session did not report itself as upload-only")
	}
	if !s.Unlocked() {
		t.Error("an enrolled background session must read as unlocked, or the worker never starts")
	}

	out, err := s.SealName(`{"file_name":"IMG_0001.jpg","full_path":"Camera Roll/IMG_0001.jpg"}`)
	if err != nil {
		t.Fatalf("SealName: %v", err)
	}
	var fields map[string]string
	if err := json.Unmarshal([]byte(out), &fields); err != nil {
		t.Fatalf("parse SealName output: %v", err)
	}
	if fields["e2ee_display_name"] == "" || fields["e2ee_path_token"] == "" {
		t.Errorf("an upload-only session produced no name fields: %v", fields)
	}
}

func TestUnlockBackgroundRefusesADeviceLoginBlob(t *testing.T) {
	s, _ := newTestSession(t)

	payload := make([]byte, crypto.DeviceKeyTransferSize)
	payload[0] = crypto.DeviceKeyTransferVersion

	err := s.UnlockBackground(base64.StdEncoding.EncodeToString(payload))
	if err == nil {
		t.Fatal("a full device-login key set was installed as background material")
	}
	if s.BackgroundOnly() {
		t.Error("a refused blob still switched the session to background mode")
	}
}

func TestNewEnrolmentRefusesWhileASessionIsOpen(t *testing.T) {
	_, dir := newTestSession(t)

	cfg, err := json.Marshal(enrolmentConfig{
		Endpoint:  "https://local.test/cloud/actions.php",
		ConfigDir: filepath.Join(dir, "pigcloud"),
	})
	if err != nil {
		t.Fatalf("marshal enrolment config: %v", err)
	}
	if _, err := NewEnrolment(string(cfg)); err == nil {
		t.Fatal("an enrolment was allowed to rewrite the live session's config")
	}
}

func TestNewSessionRefusesWhileAnEnrolmentIsLive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	enrolCfg, err := json.Marshal(enrolmentConfig{
		Endpoint:  "https://local.test/cloud/actions.php",
		ConfigDir: filepath.Join(dir, "pigcloud"),
	})
	if err != nil {
		t.Fatalf("marshal enrolment config: %v", err)
	}
	e, err := NewEnrolment(string(enrolCfg))
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}

	sessionCfg, err := json.Marshal(sessionConfig{
		Endpoint:  "https://local.test/cloud/actions.php",
		APIKey:    "pc_live_test",
		ConfigDir: filepath.Join(dir, "pigcloud"),
		CacheDir:  filepath.Join(dir, "cache"),
	})
	if err != nil {
		t.Fatalf("marshal session config: %v", err)
	}
	if _, err := NewSession(string(sessionCfg)); err == nil {
		t.Fatal("a Session was allowed to rewrite the config an open enrolment is using")
	}

	e.Close()
	s, err := NewSession(string(sessionCfg))
	if err != nil {
		t.Fatalf("NewSession after Close: %v", err)
	}
	s.Close()
	config.SetConfigFile("")
	config.SetSecretStore(nil)
}

func TestEnrolmentGivesBackAKeyItCouldNotUse(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	var mu sync.Mutex
	var revoked []string
	var revokedWith string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("action") {
		case "device-authorize":
			fmt.Fprint(w, `{"success":true,"device_code":"dc","user_code":"AAAA-BBBB","interval":1,"expires_in":60}`)
		case "device-token":
			fmt.Fprint(w, `{"success":true,"api_key":"KEYID1.secret","key_identifier":"KEYID1","sealed_key":""}`)
		case "account-revoke-cli-device":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			revoked = append(revoked, body["identifier"])
			revokedWith = r.Header.Get(api.HeaderAPIKey)
			mu.Unlock()
			fmt.Fprint(w, `{"success":true}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)

	cfg, err := json.Marshal(enrolmentConfig{Endpoint: srv.URL + "/cloud/actions.php", ConfigDir: filepath.Join(dir, "pigcloud")})
	if err != nil {
		t.Fatalf("marshal enrolment config: %v", err)
	}
	e, err := NewEnrolment(string(cfg))
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	t.Cleanup(func() {
		e.Close()
		config.SetConfigFile("")
		config.SetSecretStore(nil)
	})
	if _, err := e.Request("phone"); err != nil {
		t.Fatalf("Request: %v", err)
	}

	out, err := e.Await(30)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	var result enrolmentResult
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.OK {
		t.Fatalf("an approval without key material must fail: %s", out)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(revoked) != 1 || revoked[0] != "KEYID1" {
		t.Errorf("the minted key was left live: revoked %v", revoked)
	}
	if revokedWith != "KEYID1.secret" {
		t.Errorf("the release must authenticate with the minted key itself, got %q", revokedWith)
	}
}

func TestEnrolmentAwaitBeforeRequestIsRefused(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	cfg, err := json.Marshal(enrolmentConfig{
		Endpoint:  "https://local.test/cloud/actions.php",
		ConfigDir: filepath.Join(dir, "pigcloud"),
	})
	if err != nil {
		t.Fatalf("marshal enrolment config: %v", err)
	}
	e, err := NewEnrolment(string(cfg))
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	t.Cleanup(e.Close)

	if _, err := e.Await(1); err == nil {
		t.Error("Await without an open authorization must refuse")
	}
}
