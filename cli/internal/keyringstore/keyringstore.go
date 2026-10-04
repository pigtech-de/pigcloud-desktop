package keyringstore

import (
	"pigcloud/internal/config"

	"github.com/zalando/go-keyring"
)

const Service = "pigcloud-cli"

type Store struct{}

func New() config.SecretStore { return Store{} }

func (Store) GetSecret(key string) (string, bool) {
	v, err := keyring.Get(Service, key)
	if err != nil {
		return "", false
	}
	return v, true
}

func (Store) SetSecret(key, value string) bool {
	if value == "" {
		return false
	}
	return keyring.Set(Service, key, value) == nil
}

func (Store) DeleteSecret(key string) {
	_ = keyring.Delete(Service, key)
}
