package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"pigcloud/internal/fsutil"
	"runtime"

	"github.com/zalando/go-keyring"
)

const keyringService = "pigcloud-cli"

func keyringUserFor(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "default"
	}
	return u.Host
}

func keyringUser() string {
	if cfg == nil {
		return "default"
	}
	return keyringUserFor(cfg.Endpoint)
}

func keyringSet(apiKey string) bool {
	if apiKey == "" {
		return false
	}
	return keyring.Set(keyringService, keyringUser(), apiKey) == nil
}

func keyringGet() (string, bool) {
	v, err := keyring.Get(keyringService, keyringUser())
	if err != nil {
		return "", false
	}
	return v, true
}

func keyringDelete() {
	_ = keyring.Delete(keyringService, keyringUser())
}

func e2eeKeyringUser() string {
	return keyringUser() + "|e2ee"
}

func keyringSetDeviceKey(deviceKey []byte) bool {
	if len(deviceKey) != 32 {
		return false
	}
	return keyring.Set(keyringService, e2eeKeyringUser(), hex.EncodeToString(deviceKey)) == nil
}

func keyringGetDeviceKey() ([]byte, bool) {
	v, err := keyring.Get(keyringService, e2eeKeyringUser())
	if err != nil {
		return nil, false
	}
	decoded, err := hex.DecodeString(v)
	if err != nil || len(decoded) != 32 {
		return nil, false
	}
	return decoded, true
}

func keyringDeleteDeviceKey() {
	_ = keyring.Delete(keyringService, e2eeKeyringUser())
}

func APIKeyInKeychain() bool {
	Get()
	v, ok := keyringGet()
	return ok && v != ""
}

type Config struct {
	APIKey       string `json:"api_key"`
	Endpoint     string `json:"endpoint"`
	Cwd          string `json:"cwd"`
	DefaultJSON  bool   `json:"default_json,omitempty"`
	DefaultQuiet bool   `json:"default_quiet,omitempty"`
	NoColor      bool   `json:"no_color,omitempty"`
	Language     string `json:"language,omitempty"`

	PublicKey           string `json:"public_key,omitempty"`
	EncryptedPrivateKey string `json:"encrypted_private_key,omitempty"`
	PrivateKeyNonce     string `json:"private_key_nonce,omitempty"`

	PublicKeyKyber           string `json:"public_key_kyber,omitempty"`
	EncryptedPrivateKeyKyber string `json:"encrypted_private_key_kyber,omitempty"`
	PrivateKeyKyberNonce     string `json:"private_key_kyber_nonce,omitempty"`

	SigningPublicKeyEd25519           string `json:"signing_public_key_ed25519,omitempty"`
	EncryptedSigningPrivateKeyEd25519 string `json:"encrypted_signing_private_key_ed25519,omitempty"`
	SigningPrivateKeyEd25519Nonce     string `json:"signing_private_key_ed25519_nonce,omitempty"`

	SigningPublicKeyMldsa           string `json:"signing_public_key_mldsa,omitempty"`
	EncryptedSigningPrivateKeyMldsa string `json:"encrypted_signing_private_key_mldsa,omitempty"`
	SigningPrivateKeyMldsaNonce     string `json:"signing_private_key_mldsa_nonce,omitempty"`

	KDFSalt     string `json:"kdf_salt,omitempty"`
	KDFOpsLimit uint32 `json:"kdf_ops_limit,omitempty"`
	KDFMemLimit uint32 `json:"kdf_mem_limit,omitempty"`

	E2EEStorageMode string `json:"e2ee_storage_mode,omitempty"`

	CLIWelcomeCompleted bool `json:"cli_welcome_completed,omitempty"`
}

var (
	cfg        *Config
	configFile string
)

const (
	DefaultDomain   = "pigcloud.de"
	DefaultBaseURL  = "https://" + DefaultDomain
	DefaultEndpoint = DefaultBaseURL + "/cloud/actions.php"
)

func Load() {
	cfg = &Config{
		Endpoint: DefaultEndpoint,
		Cwd:      "/",
	}

	path := getConfigPath()

	if runtime.GOOS != "windows" {
		if info, statErr := os.Stat(path); statErr == nil {
			if perm := info.Mode().Perm(); perm&0077 != 0 {
				fmt.Fprintf(os.Stderr, "Warning: Config file %s has permissions %04o, expected 0600. Run: chmod 600 %s\n", path, perm, path)
			}
		}
	}

	if data, err := os.ReadFile(path); err == nil {
		if jerr := json.Unmarshal(data, cfg); jerr != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to parse config file: %v\n", jerr)
		}
	}

	if v, ok := keyringGet(); ok {
		cfg.APIKey = v
	}
}

func Save() error {
	current := Get()
	path := getConfigPath()

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	keychainOk := keyringSet(current.APIKey)

	persist := *current
	if keychainOk {
		persist.APIKey = ""
	}
	data, err := json.MarshalIndent(persist, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func SetConfigFile(path string) {
	configFile = path
}

func getConfigPath() string {
	if configFile != "" {
		return configFile
	}
	return PathFor("config.json")
}

func PathFor(name string) string {
	var configDir string
	if runtime.GOOS == "windows" {
		configDir = os.Getenv("APPDATA")
		if configDir == "" {
			configDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
	} else {
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			home, _ := os.UserHomeDir()
			configDir = filepath.Join(home, ".config")
		}
	}

	return filepath.Join(configDir, "pigcloud", name)
}

func Dir() string {
	return filepath.Dir(getConfigPath())
}

func GetConfigPath() string {
	return getConfigPath()
}

func Get() *Config {
	if cfg == nil {
		Load()
	}
	return cfg
}

func GetAPIKey() string {
	return Get().APIKey
}

func SetAPIKey(key string) error {
	Get().APIKey = key
	return Save()
}

func GetEndpoint() string {
	return Get().Endpoint
}

func SetEndpoint(endpoint string) error {
	current := Get()
	if keyringUserFor(current.Endpoint) == keyringUserFor(endpoint) {
		current.Endpoint = endpoint
		return Save()
	}

	deviceKey, hadDeviceKey := keyringGetDeviceKey()
	keyringDelete()
	keyringDeleteDeviceKey()

	current.Endpoint = endpoint
	if err := Save(); err != nil {
		return err
	}
	if hadDeviceKey {
		keyringSetDeviceKey(deviceKey)
	}
	return nil
}

func GetLanguage() string {
	switch Get().Language {
	case "de":
		return "de"
	default:
		return "en"
	}
}

func GetCwd() string {
	cwd := Get().Cwd
	if cwd == "" {
		return "/"
	}
	return cwd
}

func SetCwd(cwd string) error {
	Get().Cwd = cwd
	return Save()
}

func Clear() error {
	keyringDelete()
	keyringDeleteDeviceKey()

	cfg = &Config{
		Endpoint: DefaultEndpoint,
		Cwd:      "/",
	}

	path := getConfigPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove config file: %w", err)
	}

	return nil
}

func IsLoggedIn() bool {
	return Get().APIKey != ""
}

func MarkCLIWelcomeCompleted() error {
	Get().CLIWelcomeCompleted = true
	return Save()
}

func HasEncryptionKeys() bool {
	c := Get()
	return c.PublicKey != "" && c.EncryptedPrivateKey != "" &&
		c.PublicKeyKyber != "" && c.EncryptedPrivateKeyKyber != ""
}

func HasSigningKeys() bool {
	c := Get()
	return c.SigningPublicKeyEd25519 != "" && c.EncryptedSigningPrivateKeyEd25519 != "" &&
		c.SigningPublicKeyMldsa != "" && c.EncryptedSigningPrivateKeyMldsa != ""
}

func SetEncryptionKeys(
	publicKey, encPrivKey, nonce string,
	publicKeyKyber, encPrivKeyKyber, kyberNonce string,
	salt string,
	ops, mem uint32,
) error {
	c := Get()
	c.PublicKey = publicKey
	c.EncryptedPrivateKey = encPrivKey
	c.PrivateKeyNonce = nonce
	c.PublicKeyKyber = publicKeyKyber
	c.EncryptedPrivateKeyKyber = encPrivKeyKyber
	c.PrivateKeyKyberNonce = kyberNonce
	c.KDFSalt = salt
	c.KDFOpsLimit = ops
	c.KDFMemLimit = mem
	c.E2EEStorageMode = ""
	return Save()
}

func SetSigningKeys(
	pubEd, encPrivEd, edNonce string,
	pubMldsa, encPrivMldsa, mldsaNonce string,
) error {
	c := Get()
	c.SigningPublicKeyEd25519 = pubEd
	c.EncryptedSigningPrivateKeyEd25519 = encPrivEd
	c.SigningPrivateKeyEd25519Nonce = edNonce
	c.SigningPublicKeyMldsa = pubMldsa
	c.EncryptedSigningPrivateKeyMldsa = encPrivMldsa
	c.SigningPrivateKeyMldsaNonce = mldsaNonce
	return Save()
}

func StoreE2EEDeviceKey(deviceKey []byte) bool {
	return keyringSetDeviceKey(deviceKey)
}

func LoadE2EEDeviceKey() ([]byte, bool) {
	return keyringGetDeviceKey()
}

func IsDeviceWrapped() bool {
	return Get().E2EEStorageMode == "device"
}

func SetDeviceWrappedE2EEKeys(
	publicKey, encPrivKey, nonce string,
	publicKeyKyber, encPrivKeyKyber, kyberNonce string,
	pubEd, encPrivEd, edNonce string,
	pubMldsa, encPrivMldsa, mldsaNonce string,
) error {
	c := Get()
	c.PublicKey = publicKey
	c.EncryptedPrivateKey = encPrivKey
	c.PrivateKeyNonce = nonce
	c.PublicKeyKyber = publicKeyKyber
	c.EncryptedPrivateKeyKyber = encPrivKeyKyber
	c.PrivateKeyKyberNonce = kyberNonce
	c.SigningPublicKeyEd25519 = pubEd
	c.EncryptedSigningPrivateKeyEd25519 = encPrivEd
	c.SigningPrivateKeyEd25519Nonce = edNonce
	c.SigningPublicKeyMldsa = pubMldsa
	c.EncryptedSigningPrivateKeyMldsa = encPrivMldsa
	c.SigningPrivateKeyMldsaNonce = mldsaNonce
	c.KDFSalt = ""
	c.KDFOpsLimit = 0
	c.KDFMemLimit = 0
	c.E2EEStorageMode = "device"
	return Save()
}
