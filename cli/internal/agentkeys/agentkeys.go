package agentkeys

import (
	"pigcloud/internal/agent"
	"pigcloud/internal/e2ee"
)

type Source struct{}

func New() e2ee.KeyAgent { return Source{} }

func (Source) Keys() *e2ee.AgentKeys {
	km := agent.RequestKeys()
	if km == nil {
		return nil
	}
	return &e2ee.AgentKeys{
		PublicKey:                km.PublicKey,
		PrivateKey:               km.PrivateKey,
		KyberPublicKey:           km.KyberPublicKey,
		KyberSeed:                km.KyberSeed,
		NameKey:                  km.NameKey,
		SigningPublicKeyEd25519:  km.SigningPublicKeyEd25519,
		SigningPrivateKeyEd25519: km.SigningPrivateKeyEd25519,
		SigningPublicKeyMldsa:    km.SigningPublicKeyMldsa,
		SigningPrivateKeyMldsa:   km.SigningPrivateKeyMldsa,
	}
}
