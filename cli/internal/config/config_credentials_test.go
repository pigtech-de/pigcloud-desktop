package config

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func hostEntry(t *testing.T, host string) (string, bool) {
	t.Helper()
	v, err := keyring.Get(keyringService, host)
	if err != nil {
		return "", false
	}
	return v, true
}

func TestSaveLoadsTheConfigInsteadOfDereferencingNil(t *testing.T) {
	dir := isolateConfig(t)
	SetConfigFile(filepath.Join(dir, "fresh", "config.json"))

	if cfg != nil {
		t.Fatal("isolateConfig left a loaded config; this guard would not exercise the nil path")
	}
	if err := Save(); err != nil {
		t.Fatalf("Save on a fresh process: %v", err)
	}
	if got := GetEndpoint(); got != DefaultEndpoint {
		t.Errorf("endpoint = %q after a bare Save, want the default", got)
	}
}

func TestCredentialsDoNotSurviveAnEndpointChangeThenLogout(t *testing.T) {
	isolateConfig(t)

	const oldEndpoint = "https://pigtech.de/cloud/actions.php"
	const newEndpoint = "https://local.test/cloud/actions.php"
	oldHost := keyringUserFor(oldEndpoint)
	newHost := keyringUserFor(newEndpoint)
	if oldHost == newHost {
		t.Fatal("both endpoints map to one keychain user; this guard would be vacuous")
	}

	if err := SetEndpoint(oldEndpoint); err != nil {
		t.Fatalf("SetEndpoint(old): %v", err)
	}
	if err := SetAPIKey("pc_live_prod_key"); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}
	if !StoreE2EEDeviceKey(bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatal("mock keychain refused the device key")
	}
	if _, ok := hostEntry(t, oldHost); !ok {
		t.Fatalf("API key never reached the keychain under %q; the assertions below would prove nothing", oldHost)
	}

	if err := SetEndpoint(newEndpoint); err != nil {
		t.Fatalf("SetEndpoint(new): %v", err)
	}
	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	for _, host := range []string{oldHost, newHost} {
		if v, ok := hostEntry(t, host); ok && v != "" {
			t.Errorf("API key survived logout in the keychain under %q", host)
		}
		if v, ok := hostEntry(t, host+"|e2ee"); ok && v != "" {
			t.Errorf("E2EE device key survived logout in the keychain under %q", host)
		}
	}
}

func TestEndpointChangeLeavesNoEntryUnderThePreviousHost(t *testing.T) {
	isolateConfig(t)

	const oldEndpoint = "https://pigtech.de/cloud/actions.php"
	const newEndpoint = "https://local.test/cloud/actions.php"
	oldHost := keyringUserFor(oldEndpoint)

	if err := SetEndpoint(oldEndpoint); err != nil {
		t.Fatalf("SetEndpoint(old): %v", err)
	}
	if err := SetAPIKey("pc_live_prod_key"); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}
	if !StoreE2EEDeviceKey(bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatal("mock keychain refused the device key")
	}

	if err := SetEndpoint(newEndpoint); err != nil {
		t.Fatalf("SetEndpoint(new): %v", err)
	}

	if v, ok := hostEntry(t, oldHost); ok && v != "" {
		t.Errorf("API key stayed in the keychain under the previous host %q", oldHost)
	}
	if v, ok := hostEntry(t, oldHost+"|e2ee"); ok && v != "" {
		t.Errorf("E2EE device key stayed in the keychain under the previous host %q", oldHost)
	}
}

func TestEndpointChangeCarriesCredentialsToTheNewHost(t *testing.T) {
	isolateConfig(t)

	const newEndpoint = "https://local.test/cloud/actions.php"
	deviceKey := bytes.Repeat([]byte{0x5a}, 32)

	if err := SetAPIKey("pc_live_key"); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}
	if !StoreE2EEDeviceKey(deviceKey) {
		t.Fatal("mock keychain refused the device key")
	}
	if err := SetEndpoint(newEndpoint); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}

	if !IsLoggedIn() {
		t.Error("endpoint change logged the user out in memory")
	}
	cfg = nil
	Load()
	if got := GetAPIKey(); got != "pc_live_key" {
		t.Errorf("API key = %q after an endpoint change and reload, want it to follow the endpoint", got)
	}
	if got := GetEndpoint(); got != newEndpoint {
		t.Errorf("endpoint = %q after reload, want %q", got, newEndpoint)
	}
	got, ok := LoadE2EEDeviceKey()
	if !ok {
		t.Fatal("E2EE device key was lost in the endpoint change; device-wrapped keys become unrecoverable")
	}
	if !bytes.Equal(got, deviceKey) {
		t.Error("E2EE device key changed value across the endpoint change")
	}
}
