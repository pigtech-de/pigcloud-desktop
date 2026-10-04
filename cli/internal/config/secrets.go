package config

import (
	"encoding/hex"
	"net/url"
	"sync"
)

type SecretStore interface {
	GetSecret(key string) (string, bool)
	SetSecret(key, value string) bool
	DeleteSecret(key string)
}

type noSecretStore struct{}

func (noSecretStore) GetSecret(string) (string, bool) { return "", false }
func (noSecretStore) SetSecret(string, string) bool   { return false }
func (noSecretStore) DeleteSecret(string)             {}

type MemorySecretStore struct {
	mu     sync.RWMutex
	values map[string]string
}

func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{values: make(map[string]string)}
}

func (m *MemorySecretStore) GetSecret(key string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.values[key]
	return v, ok
}

func (m *MemorySecretStore) SetSecret(key, value string) bool {
	if value == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
	return true
}

func (m *MemorySecretStore) DeleteSecret(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
}

var (
	secretsMu sync.RWMutex
	secrets   SecretStore = noSecretStore{}
)

func SetSecretStore(store SecretStore) {
	if store == nil {
		store = noSecretStore{}
	}
	secretsMu.Lock()
	defer secretsMu.Unlock()
	secrets = store
}

func secretStore() SecretStore {
	secretsMu.RLock()
	defer secretsMu.RUnlock()
	return secrets
}

func secretKeyFor(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "default"
	}
	return u.Host
}

func secretKey() string {
	if cfg == nil {
		return "default"
	}
	return secretKeyFor(cfg.Endpoint)
}

func e2eeSecretKey() string {
	return secretKey() + "|e2ee"
}

func storeAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}
	return secretStore().SetSecret(secretKey(), apiKey)
}

func loadAPIKey() (string, bool) {
	return secretStore().GetSecret(secretKey())
}

func deleteAPIKey() {
	secretStore().DeleteSecret(secretKey())
}

func storeDeviceKey(deviceKey []byte) bool {
	if len(deviceKey) != 32 {
		return false
	}
	return secretStore().SetSecret(e2eeSecretKey(), hex.EncodeToString(deviceKey))
}

func loadDeviceKey() ([]byte, bool) {
	v, ok := secretStore().GetSecret(e2eeSecretKey())
	if !ok {
		return nil, false
	}
	decoded, err := hex.DecodeString(v)
	if err != nil || len(decoded) != 32 {
		return nil, false
	}
	return decoded, true
}

func deleteDeviceKey() {
	secretStore().DeleteSecret(e2eeSecretKey())
}
