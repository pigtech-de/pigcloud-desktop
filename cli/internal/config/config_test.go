package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	os.Exit(m.Run())
}

func isolateConfig(t *testing.T) string {
	t.Helper()
	keyring.MockInit()

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	prevCfg, prevFile := cfg, configFile
	cfg, configFile = nil, ""
	t.Cleanup(func() {
		cfg, configFile = prevCfg, prevFile
		keyring.MockInit()
	})
	return dir
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prev := os.Stderr
	os.Stderr = w

	out := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()

	fn()

	os.Stderr = prev
	w.Close()
	got := <-out
	r.Close()
	return got
}

func TestSaveWritesAnOwnerOnlyConfigFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	dir := isolateConfig(t)

	c := Get()
	c.EncryptedPrivateKey = "d9f1c0a4-wrapped-x25519-private-key"
	if err := Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	path := GetConfigPath()
	if want := filepath.Join(dir, "pigcloud", "config.json"); path != want {
		t.Fatalf("config path %q escaped the temp dir (want %q)", path, want)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Contains(data, []byte(c.EncryptedPrivateKey)) {
		t.Fatal("config file holds no key material; the mode assertions below would prove nothing")
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("config.json mode %04o, want 0600: it carries the wrapped E2EE private keys", perm)
	}

	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("config dir mode %04o, want 0700", perm)
	}
}

func TestSaveKeepsTheAPIKeyOutOfTheConfigFileWhenTheKeychainWorks(t *testing.T) {
	isolateConfig(t)

	const key = "pc_live_7f3a2b91c4d5e6f708192a3b4c5d6e7f"
	if err := SetAPIKey(key); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}

	raw, err := os.ReadFile(GetConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if bytes.Contains(raw, []byte(key)) {
		t.Error("API key was written to config.json in plaintext even though the keychain accepted it")
	}
	if !APIKeyInKeychain() {
		t.Error("APIKeyInKeychain false after a successful keychain write")
	}

	cfg = nil
	Load()
	if got := GetAPIKey(); got != key {
		t.Errorf("API key did not survive the keychain round trip (got %d characters, want %d)", len(got), len(key))
	}
	if !IsLoggedIn() {
		t.Error("IsLoggedIn false with a key in the keychain")
	}
}

func TestSaveFallsBackToPlaintextWhenTheKeychainIsUnavailable(t *testing.T) {
	isolateConfig(t)
	keyring.MockInitWithError(errors.New("no secret service"))

	const key = "pc_headless_2c8f10ab"
	if err := SetAPIKey(key); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}

	raw, err := os.ReadFile(GetConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Contains(raw, []byte(key)) {
		t.Fatal("headless save dropped the API key: not in the keychain and not in the file")
	}
	if APIKeyInKeychain() {
		t.Error("APIKeyInKeychain true while the keychain is failing")
	}

	cfg = nil
	Load()
	if got := GetAPIKey(); got != key {
		t.Errorf("API key did not survive the plaintext fallback (got %d characters, want %d)", len(got), len(key))
	}
}

func TestKeychainValueWinsOverAStaleFileValue(t *testing.T) {
	isolateConfig(t)

	path := GetConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"api_key":"stale-plaintext-key","endpoint":"`+DefaultEndpoint+`","cwd":"/"}`), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := keyring.Set(keyringService, DefaultDomain, "rotated-keychain-key"); err != nil {
		t.Fatalf("seed keychain: %v", err)
	}

	Load()
	if got := GetAPIKey(); got != "rotated-keychain-key" {
		t.Errorf("Load preferred the config-file key over the keychain (got %q)", got)
	}
}

func TestConfigRoundTripsEveryField(t *testing.T) {
	isolateConfig(t)

	want := &Config{}
	v := reflect.ValueOf(want).Elem()
	ty := v.Type()
	for i := 0; i < ty.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString(ty.Field(i).Name + "-value")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Uint32:
			f.SetUint(uint64(i + 1))
		default:
			t.Fatalf("Config.%s has unhandled kind %s; extend this round trip", ty.Field(i).Name, f.Kind())
		}
	}

	Load()
	*cfg = *want
	if err := Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	cfg = nil
	Load()
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config did not round-trip.\n got %+v\nwant %+v", cfg, want)
	}
}

func TestLoadOnACorruptConfigFailsClosed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"truncated json", `{"api_key":"leaked-key","endpoint":`},
		{"not json", "this is not json"},
		{"json array", `[{"api_key":"leaked-key"}]`},
		{"binary garbage", "\x00\x01\x02\xff\xfe"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateConfig(t)
			path := GetConfigPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("seed config: %v", err)
			}

			warning := captureStderr(t, Load)
			if !strings.Contains(warning, "Failed to parse config file") {
				t.Errorf("Load swallowed a corrupt config silently; stderr was %q", warning)
			}

			if IsLoggedIn() {
				t.Error("a corrupt config left the CLI believing it is logged in")
			}
			if got := GetEndpoint(); got != DefaultEndpoint {
				t.Errorf("endpoint = %q after a corrupt load, want the default; requests must not go somewhere half-parsed", got)
			}
			if got := GetCwd(); got != "/" {
				t.Errorf("cwd = %q after a corrupt load, want /", got)
			}
			if HasEncryptionKeys() || HasSigningKeys() {
				t.Error("a corrupt config reported usable E2EE key material")
			}

			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("re-read config: %v", err)
			}
			if !bytes.Equal(after, []byte(tc.body)) {
				t.Error("Load rewrote the corrupt config file; the user's only copy of the wrapped keys must survive a read")
			}
		})
	}
}

func TestLoadWarnsAboutAGroupOrWorldReadableConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	isolateConfig(t)

	Get().EncryptedPrivateKey = "wrapped-private-key"
	if err := Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	path := GetConfigPath()

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg = nil
	warning := captureStderr(t, Load)
	for _, want := range []string{path, "0644", "0600"} {
		if !strings.Contains(warning, want) {
			t.Errorf("permission warning does not mention %q; stderr was %q", want, warning)
		}
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod back: %v", err)
	}
	cfg = nil
	if quiet := captureStderr(t, Load); quiet != "" {
		t.Errorf("Load complained about a correctly-permissioned config: %q", quiet)
	}
}

func TestGetConfigPathHonoursOverrides(t *testing.T) {
	dir := isolateConfig(t)

	if runtime.GOOS != "windows" {
		if got, want := GetConfigPath(), filepath.Join(dir, "pigcloud", "config.json"); got != want {
			t.Errorf("XDG_CONFIG_HOME ignored: got %q, want %q", got, want)
		}

		home := t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", home)
		if got, want := GetConfigPath(), filepath.Join(home, ".config", "pigcloud", "config.json"); got != want {
			t.Errorf("home fallback: got %q, want %q", got, want)
		}
	}

	custom := filepath.Join(t.TempDir(), "elsewhere.json")
	SetConfigFile(custom)
	if got := GetConfigPath(); got != custom {
		t.Errorf("--config path ignored: got %q, want %q", got, custom)
	}
	if got, want := Dir(), filepath.Dir(custom); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}

	Load()
	Get().Cwd = "/Photos"
	if err := Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Errorf("Save ignored the --config path: %v", err)
	}
	cfg = nil
	Load()
	if got := GetCwd(); got != "/Photos" {
		t.Errorf("--config path did not round-trip: cwd = %q", got)
	}
}

func TestClearRemovesEveryStoredCredential(t *testing.T) {
	isolateConfig(t)

	if err := SetAPIKey("pc_live_to_be_revoked"); err != nil {
		t.Fatalf("SetAPIKey: %v", err)
	}
	deviceKey := bytes.Repeat([]byte{0xa5}, 32)
	if !StoreE2EEDeviceKey(deviceKey) {
		t.Fatal("mock keychain refused the device key")
	}
	if _, ok := keyringGet(); !ok {
		t.Fatal("API key never reached the keychain; the assertions below would prove nothing")
	}

	if err := Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	if _, err := os.Stat(GetConfigPath()); !os.IsNotExist(err) {
		t.Errorf("config file survived logout (stat err %v)", err)
	}
	if IsLoggedIn() {
		t.Error("still logged in after Clear")
	}
	if _, ok := keyringGet(); ok {
		t.Error("API key survived logout in the OS keychain")
	}
	if _, ok := LoadE2EEDeviceKey(); ok {
		t.Error("E2EE device key survived logout in the OS keychain")
	}
	if got := GetEndpoint(); got != DefaultEndpoint {
		t.Errorf("endpoint = %q after Clear, want the default", got)
	}
	if got := GetCwd(); got != "/" {
		t.Errorf("cwd = %q after Clear, want /", got)
	}
	if err := Clear(); err != nil {
		t.Errorf("Clear must be idempotent, second call returned: %v", err)
	}
}

func TestDeviceKeyStorageIsStrictAboutSizeAndEncoding(t *testing.T) {
	isolateConfig(t)

	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if StoreE2EEDeviceKey(make([]byte, n)) {
			t.Errorf("accepted a %d-byte device key; the E2EE wrap key must be exactly 32 bytes", n)
		}
	}

	key := bytes.Repeat([]byte{0x5c}, 32)
	if !StoreE2EEDeviceKey(key) {
		t.Fatal("StoreE2EEDeviceKey refused a valid 32-byte key")
	}
	got, ok := LoadE2EEDeviceKey()
	if !ok || !bytes.Equal(got, key) {
		t.Fatalf("device key did not round-trip (ok=%v, %d bytes)", ok, len(got))
	}

	corrupt := map[string]string{
		"non-hex":         "not-hex-at-all",
		"empty":           "",
		"half length":     hex.EncodeToString(make([]byte, 16)),
		"double length":   hex.EncodeToString(make([]byte, 64)),
		"odd digit count": hex.EncodeToString(key)[:63],
	}
	for name, value := range corrupt {
		if err := keyring.Set(keyringService, e2eeKeyringUser(), value); err != nil {
			t.Fatalf("seed keychain: %v", err)
		}
		if b, ok := LoadE2EEDeviceKey(); ok {
			t.Errorf("accepted a %s device key from the keychain, returning %d bytes", name, len(b))
		}
	}

	if !StoreE2EEDeviceKey(key) {
		t.Fatal("StoreE2EEDeviceKey refused a valid key on the second write")
	}
	Get()
	if err := Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(GetConfigPath())
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if bytes.Contains(raw, []byte(hex.EncodeToString(key))) {
		t.Error("the E2EE device key leaked into config.json; it must live only in the OS keychain")
	}
}

func TestKeyPresenceChecksAreStrictAnd(t *testing.T) {
	isolateConfig(t)

	groups := []struct {
		name   string
		fields []string
		probe  func() bool
	}{
		{"HasEncryptionKeys", []string{"PublicKey", "EncryptedPrivateKey", "PublicKeyKyber", "EncryptedPrivateKeyKyber"}, HasEncryptionKeys},
		{"HasSigningKeys", []string{"SigningPublicKeyEd25519", "EncryptedSigningPrivateKeyEd25519", "SigningPublicKeyMldsa", "EncryptedSigningPrivateKeyMldsa"}, HasSigningKeys},
	}

	for _, g := range groups {
		full := 1<<len(g.fields) - 1
		for mask := 0; mask <= full; mask++ {
			cfg = &Config{}
			v := reflect.ValueOf(cfg).Elem()
			for i, name := range g.fields {
				f := v.FieldByName(name)
				if !f.IsValid() {
					t.Fatalf("Config has no field %s; %s guard is stale", name, g.name)
				}
				if mask&(1<<i) != 0 {
					f.SetString("present")
				}
			}
			want := mask == full
			if got := g.probe(); got != want {
				t.Errorf("%s() = %v for field mask %04b, want %v (a partial key set is unusable)", g.name, got, mask, want)
			}
		}
	}
}

func TestPasswordSetupAndDeviceWrapAreMutuallyExclusive(t *testing.T) {
	isolateConfig(t)

	if err := SetDeviceWrappedE2EEKeys(
		"pub", "enc", "nonce",
		"kpub", "kenc", "knonce",
		"edpub", "edenc", "ednonce",
		"mlpub", "mlenc", "mlnonce",
	); err != nil {
		t.Fatalf("SetDeviceWrappedE2EEKeys: %v", err)
	}
	if !IsDeviceWrapped() {
		t.Fatal("device wrap did not flip the storage mode")
	}
	c := Get()
	if c.KDFSalt != "" || c.KDFOpsLimit != 0 || c.KDFMemLimit != 0 {
		t.Error("device-wrapped keys kept the password KDF params; unlock would take the wrong unwrap path")
	}
	if !HasEncryptionKeys() || !HasSigningKeys() {
		t.Error("device wrap did not store a complete key set")
	}

	cfg = nil
	Load()
	if !IsDeviceWrapped() {
		t.Error("device storage mode did not persist across a reload")
	}

	if err := SetEncryptionKeys("pub2", "enc2", "nonce2", "kpub2", "kenc2", "knonce2", "salt", 3, 268435456); err != nil {
		t.Fatalf("SetEncryptionKeys: %v", err)
	}
	if IsDeviceWrapped() {
		t.Error("password setup left the device storage mode set; unlock would look for a keychain key that no longer wraps the blobs")
	}
	cfg = nil
	Load()
	if IsDeviceWrapped() {
		t.Error("device storage mode survived password setup across a reload")
	}
	if got := Get().KDFOpsLimit; got != 3 {
		t.Errorf("kdf ops limit = %d, want 3", got)
	}
}

func TestDefaultsWithNoConfigFile(t *testing.T) {
	isolateConfig(t)

	if _, err := os.Stat(GetConfigPath()); !os.IsNotExist(err) {
		t.Fatalf("temp dir already holds a config file: %v", err)
	}

	if Get() == nil {
		t.Fatal("Get() returned nil with no config file")
	}
	if got := GetEndpoint(); got != DefaultEndpoint {
		t.Errorf("endpoint = %q, want %q", got, DefaultEndpoint)
	}
	if got := GetCwd(); got != "/" {
		t.Errorf("cwd = %q, want /", got)
	}
	if IsLoggedIn() {
		t.Error("IsLoggedIn true with no config and an empty keychain")
	}
	if APIKeyInKeychain() {
		t.Error("APIKeyInKeychain true with an empty keychain")
	}
	if HasEncryptionKeys() || HasSigningKeys() || IsDeviceWrapped() {
		t.Error("a fresh config reported E2EE state it does not have")
	}
}

func TestGetCwdAndGetLanguageNeverReturnAnEmptyValue(t *testing.T) {
	isolateConfig(t)
	Load()

	for _, in := range []string{"", "fr", "EN", "de-DE", "en", "DE", " de"} {
		cfg.Language = in
		if got := GetLanguage(); got != "en" {
			t.Errorf("GetLanguage() = %q for stored %q, want the en fallback", got, in)
		}
	}
	cfg.Language = "de"
	if got := GetLanguage(); got != "de" {
		t.Errorf("GetLanguage() = %q for stored \"de\", want \"de\"", got)
	}

	cfg.Cwd = ""
	if got := GetCwd(); got != "/" {
		t.Errorf("GetCwd() = %q for an empty stored cwd, want /", got)
	}
	cfg.Cwd = "/Photos/2026"
	if got := GetCwd(); got != "/Photos/2026" {
		t.Errorf("GetCwd() = %q, want /Photos/2026", got)
	}
}

func TestSetCwdAndSetEndpointPersist(t *testing.T) {
	isolateConfig(t)

	if err := SetCwd("/Documents"); err != nil {
		t.Fatalf("SetCwd: %v", err)
	}
	if err := SetEndpoint("https://local.test/cloud/actions.php"); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	if err := MarkCLIWelcomeCompleted(); err != nil {
		t.Fatalf("MarkCLIWelcomeCompleted: %v", err)
	}

	cfg = nil
	Load()
	if got := GetCwd(); got != "/Documents" {
		t.Errorf("cwd = %q after reload, want /Documents", got)
	}
	if got := GetEndpoint(); got != "https://local.test/cloud/actions.php" {
		t.Errorf("endpoint = %q after reload", got)
	}
	if !Get().CLIWelcomeCompleted {
		t.Error("welcome flag did not persist")
	}
}
