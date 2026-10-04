package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
)

func wakeResponse(status int, body string) *api.Response {
	resp := &api.Response{StatusCode: status, Raw: json.RawMessage(body)}
	_ = json.Unmarshal([]byte(body), resp)
	return resp
}

func TestDecideWakeResponseClasses(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ident := "KEYID1"
	revoked := `{"success":false,"messageKey":"cliErrorUnauthorized","errorCode":"deviceTokenRevoked","identifier":"KEYID1"}`
	current := func(epoch int64) string {
		return fmt.Sprintf(`{"success":true,"username":"alice","key_epoch":%d}`, epoch)
	}
	stale := now.Add(-revocationConfirmDelay - time.Second).Unix()
	fresh := now.Add(-5 * time.Second).Unix()

	cases := []struct {
		name    string
		req     wakeRequest
		resp    *api.Response
		callErr error
		want    string
		reason  string
		strike  int64
	}{
		{"unreachable", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, nil, errors.New("request failed: dial tcp: connection refused"), WakePause, "unreachable", 0},
		{"timeout", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, nil, errors.New("request failed: context deadline exceeded"), WakePause, "unreachable", 0},
		{"tls", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, nil, errors.New("request failed: tls: failed to verify certificate"), WakePause, "unreachable", 0},
		{"malformed body", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, nil, errors.New("failed to parse response (status 200): invalid character '<'"), WakePause, "malformed", 0},
		{"captive portal 200", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(200, `{"success":true,"key_epoch":9}`), nil, WakePause, "malformed", 0},
		{"5xx", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(503, `{"success":false,"error":"maintenance"}`), nil, WakePause, "server_error", 0},
		{"429", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(429, `{"success":false,"error":"rate_limited"}`), nil, WakePause, "rate_limited", 0},
		{"plain 401", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(401, `{"success":false,"messageKey":"cliErrorUnauthorized"}`), nil, WakePause, "unauthorized", 0},
		{"403 without marker", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(403, `{"success":false,"error":"invalid_csrf"}`), nil, WakePause, "unauthorized", 0},
		{"revocation for another key", wakeRequest{KeyEpoch: 3, KeyIdentifier: "OTHER1"}, wakeResponse(401, revoked), nil, WakePause, "unauthorized", 0},
		{"revocation 401 once", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(401, revoked), nil, WakePause, "revocation_unconfirmed", now.Unix()},
		{"revocation 401 twice inside 30s", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident, RevocationStrikeAt: fresh}, wakeResponse(401, revoked), nil, WakePause, "revocation_unconfirmed", fresh},
		{"revocation 401 twice", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident, RevocationStrikeAt: stale}, wakeResponse(401, revoked), nil, WakeWipe, "revoked", 0},
		{"plain 401 after a strike", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident, RevocationStrikeAt: stale}, wakeResponse(401, `{"success":false}`), nil, WakePause, "unauthorized", 0},
		{"higher epoch", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(200, current(4)), nil, WakeWipe, "key_rotated", 0},
		{"equal epoch", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(200, current(3)), nil, WakeContinue, "current", 0},
		{"lower epoch", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(200, current(2)), nil, WakePause, "epoch_behind", 0},
		{"epoch absent", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(200, `{"success":true,"username":"alice"}`), nil, WakeContinue, "epoch_unknown", 0},
		{"success false at 200", wakeRequest{KeyEpoch: 3, KeyIdentifier: ident}, wakeResponse(200, `{"success":false,"username":"alice","key_epoch":9}`), nil, WakePause, "malformed", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideWake(tc.req, tc.resp, tc.callErr, false, now)
			if got.Outcome != tc.want || got.Reason != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", got.Outcome, got.Reason, tc.want, tc.reason)
			}
			if got.RevocationStrikeAt != tc.strike {
				t.Errorf("strike %d, want %d", got.RevocationStrikeAt, tc.strike)
			}
			if got.Outcome == WakePause && got.KeyEpoch != tc.req.KeyEpoch {
				t.Errorf("a pause must hand the stored epoch back unchanged, got %d", got.KeyEpoch)
			}
		})
	}
}

func TestDecideWakeRefusesToWipeWhileAnEnrolmentIsOpen(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	stale := now.Add(-2 * revocationConfirmDelay).Unix()
	req := wakeRequest{KeyEpoch: 3, KeyIdentifier: "KEYID1", RevocationStrikeAt: stale}

	revoked := wakeResponse(401, `{"success":false,"errorCode":"deviceTokenRevoked","identifier":"KEYID1"}`)
	if got := decideWake(req, revoked, nil, true, now); got.Outcome != WakePause || got.RevocationStrikeAt != stale {
		t.Fatalf("a confirmed revocation wiped under an open enrolment: %+v", got)
	}
	rotated := wakeResponse(200, `{"success":true,"username":"alice","key_epoch":4}`)
	if got := decideWake(req, rotated, nil, true, now); got.Outcome != WakePause {
		t.Fatalf("a higher epoch wiped under an open enrolment: %+v", got)
	}
	if got := decideWake(req, rotated, nil, false, now); got.Outcome != WakeWipe {
		t.Fatalf("the same answer must wipe once the enrolment is closed: %+v", got)
	}
}

func TestCheckKeysRefusesToWipeWhileAnEnrolmentIsLive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"success":false,"messageKey":"cliErrorUnauthorized","errorCode":"deviceTokenRevoked","identifier":"KEYID1"}`)
	}))
	t.Cleanup(srv.Close)

	cfg, err := json.Marshal(sessionConfig{
		Endpoint:  srv.URL + "/cloud/actions.php",
		APIKey:    "KEYID1.secret",
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

	stale := time.Now().Add(-2 * revocationConfirmDelay).Unix()
	request := fmt.Sprintf(`{"key_epoch":3,"key_identifier":"KEYID1","revocation_strike_at":%d}`, stale)

	enrolMu.Lock()
	enrolLive = &Enrolment{}
	enrolMu.Unlock()
	t.Cleanup(func() {
		enrolMu.Lock()
		enrolLive = nil
		enrolMu.Unlock()
	})

	out, err := s.CheckKeys(request)
	if err != nil {
		t.Fatalf("CheckKeys: %v", err)
	}
	var result wakeResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.Outcome != WakePause || result.RevocationStrikeAt != stale {
		t.Fatalf("a wipe went through while an enrolment was live: %s", out)
	}

	enrolMu.Lock()
	enrolLive = nil
	enrolMu.Unlock()
	out, err = s.CheckKeys(request)
	if err != nil {
		t.Fatalf("CheckKeys after Close: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Outcome != WakeWipe {
		t.Fatalf("the confirmed revocation must wipe once no enrolment is live: %s", out)
	}
}

func TestCheckKeysPausesWhenTheServerIsUnreachable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	closed := httptest.NewServer(http.NotFoundHandler())
	endpoint := closed.URL + "/cloud/actions.php"
	closed.Close()

	cfg, err := json.Marshal(sessionConfig{
		Endpoint:  endpoint,
		APIKey:    "KEYID1.secret",
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

	out, err := s.CheckKeys(`{"key_epoch":3,"key_identifier":"KEYID1"}`)
	if err != nil {
		t.Fatalf("CheckKeys: %v", err)
	}
	var result wakeResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse result: %v", err)
	}
	if result.Outcome != WakePause || result.Reason != "unreachable" || result.KeyEpoch != 3 {
		t.Fatalf("an unreachable server must pause with the keys intact: %s", out)
	}
}
