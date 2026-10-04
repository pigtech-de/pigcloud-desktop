package config

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

type recordingStore struct {
	values map[string]string
	calls  []string
	refuse bool
}

func newRecordingStore() *recordingStore {
	return &recordingStore{values: map[string]string{}}
}

func (r *recordingStore) GetSecret(key string) (string, bool) {
	r.calls = append(r.calls, "get "+key)
	v, ok := r.values[key]
	return v, ok
}

func (r *recordingStore) SetSecret(key, value string) bool {
	r.calls = append(r.calls, "set "+key)
	if r.refuse {
		return false
	}
	r.values[key] = value
	return true
}

func (r *recordingStore) DeleteSecret(key string) {
	r.calls = append(r.calls, "delete "+key)
	delete(r.values, key)
}

func installRecordingStore(t *testing.T) *recordingStore {
	t.Helper()
	store := newRecordingStore()
	SetSecretStore(store)
	t.Cleanup(func() { SetSecretStore(testSecrets) })
	return store
}

func TestCredentialsReachTheKeychainOnlyThroughTheInjectedStore(t *testing.T) {
	isolateConfig(t)
	store := installRecordingStore(t)

	const endpoint = "https://local.test/cloud/actions.php"
	if err := SetEndpoint(endpoint); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	if err := SetAPIKey("pc_live_injected"); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}
	deviceKey := bytes.Repeat([]byte{0x7e}, 32)
	if !StoreE2EEDeviceKey(deviceKey) {
		t.Fatal("the injected store refused a valid device key")
	}

	if got := store.values["local.test"]; got != "pc_live_injected" {
		t.Errorf("API key landed under %q = %q, want the endpoint host to scope it", "local.test", got)
	}
	if got := store.values["local.test|e2ee"]; got != hex.EncodeToString(deviceKey) {
		t.Errorf("device key landed as %q, want the hex of the 32 raw bytes", got)
	}
	if !APIKeyInKeychain() {
		t.Error("APIKeyInKeychain false with the key in the injected store")
	}

	back, ok := LoadE2EEDeviceKey()
	if !ok || !bytes.Equal(back, deviceKey) {
		t.Fatalf("device key did not round-trip through the injected store (ok=%v, %d bytes)", ok, len(back))
	}

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if len(store.values) != 0 {
		t.Errorf("logout left %d entries in the injected store", len(store.values))
	}
	for _, want := range []string{"set local.test", "get local.test", "set local.test|e2ee", "delete local.test", "delete local.test|e2ee"} {
		if !slices.Contains(store.calls, want) {
			t.Errorf("the config package never issued %q; calls were %s", want, strings.Join(store.calls, ", "))
		}
	}
}

func TestARefusingStoreFallsBackToTheFileForTheAPIKeyAndRefusesTheDeviceKey(t *testing.T) {
	isolateConfig(t)
	store := installRecordingStore(t)
	store.refuse = true

	const key = "pc_live_no_keychain"
	if err := SetAPIKey(key); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}
	if APIKeyInKeychain() {
		t.Error("APIKeyInKeychain true while the store refuses every write")
	}
	cfg = nil
	Load()
	if got := GetAPIKey(); got != key {
		t.Errorf("API key = %q after a refusing store, want the plaintext fallback to hold it", got)
	}
	if StoreE2EEDeviceKey(bytes.Repeat([]byte{1}, 32)) {
		t.Error("a refused device-key write was reported as stored; the blobs would be unrecoverable")
	}
}

func TestTheDefaultStoreIsTheRefusingOne(t *testing.T) {
	SetSecretStore(nil)
	t.Cleanup(func() { SetSecretStore(testSecrets) })

	if ok := storeAPIKey("pc_live_key"); ok {
		t.Error("the default store accepted a secret; a host that forgets to install one must see a refusal")
	}
	if _, ok := loadAPIKey(); ok {
		t.Error("the default store served a secret it never stored")
	}
}
