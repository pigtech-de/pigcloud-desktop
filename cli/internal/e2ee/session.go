package e2ee

import (
	"bytes"
	"sync"
	"time"

	"pigcloud/internal/crypto"
)

type Fault struct {
	Message string
	Cause   error
}

func (f *Fault) Error() string {
	if f.Cause == nil {
		return f.Message
	}
	return f.Message + ": " + f.Cause.Error()
}

func (f *Fault) Unwrap() error { return f.Cause }

func fault(message string, cause error) *Fault {
	return &Fault{Message: message, Cause: cause}
}

var (
	ErrNoEncryptionKeys     = &Fault{Message: "No encryption keys configured. Run 'pc li' to set up encryption."}
	ErrDeviceKeysLost       = &Fault{Message: "Encryption keys unavailable (device keychain locked or reset). Run 'pc login' again."}
	ErrKeysLocked           = &Fault{Message: "Keys are locked. Run 'pc uk' to unlock."}
	ErrWrongPassword        = &Fault{Message: "Wrong password"}
	ErrNoSigningKeys        = &Fault{Message: "Signing keys not configured for this account. Open the web app to complete E2EE setup."}
	ErrSigningUnlockFailed  = &Fault{Message: "Failed to unlock signing keys. Re-run 'pc uk' to refresh, then retry."}
	ErrScannerUnreachable   = &Fault{Message: "Security scanner is not reachable. Please try again shortly."}
	ErrNoKeychainForDevice  = &Fault{Message: "no OS keychain available to hold the device key"}
	ErrScannerRefusedUpload = &Fault{Message: "Security scanner refused"}
)

type AgentKeys struct {
	PublicKey      [32]byte
	PrivateKey     [32]byte
	KyberPublicKey []byte
	KyberSeed      []byte
	NameKey        []byte

	SigningPublicKeyEd25519  []byte
	SigningPrivateKeyEd25519 []byte
	SigningPublicKeyMldsa    []byte
	SigningPrivateKeyMldsa   []byte
}

type KeyAgent interface {
	Keys() *AgentKeys
}

type PasswordPrompter interface {
	Password() ([]byte, error)
}

type Session struct {
	mu sync.Mutex

	agent      KeyAgent
	prompter   PasswordPrompter
	supplied   []byte
	stagingDir string

	pub  *crypto.PublicKeySet
	priv *crypto.PrivateKeySet

	nameKey   []byte
	parentKey []byte

	background bool

	signingPub  *crypto.SigningPublicKeySet
	signingPriv *crypto.SigningPrivateKeySet

	teeEnclaveKeySet           *crypto.PublicKeySet
	teeScannerDisabledByServer bool
	teeEnclaveKeyRefusal       error
	teeKeysFetch               *teeKeysCall
	teeKeysEpoch               uint64
	teeStaleCheckedAt          time.Time
}

func NewSession(keyAgent KeyAgent, prompter PasswordPrompter) *Session {
	return &Session{agent: keyAgent, prompter: prompter}
}

func (s *Session) SetKeyAgent(keyAgent KeyAgent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agent = keyAgent
}

func (s *Session) SetPasswordPrompter(prompter PasswordPrompter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompter = prompter
}

func clonePrivateKeySet(p *crypto.PrivateKeySet) *crypto.PrivateKeySet {
	if p == nil {
		return nil
	}
	return &crypto.PrivateKeySet{X25519: p.X25519, Kyber: bytes.Clone(p.Kyber)}
}

func clonePublicKeySet(p *crypto.PublicKeySet) *crypto.PublicKeySet {
	if p == nil {
		return nil
	}
	return &crypto.PublicKeySet{X25519: p.X25519, Kyber: bytes.Clone(p.Kyber)}
}

func cloneSigningPrivateKeySet(p *crypto.SigningPrivateKeySet) *crypto.SigningPrivateKeySet {
	if p == nil {
		return nil
	}
	return &crypto.SigningPrivateKeySet{
		Ed25519: bytes.Clone(p.Ed25519),
		Mldsa:   bytes.Clone(p.Mldsa),
	}
}

func cloneSigningPublicKeySet(p *crypto.SigningPublicKeySet) *crypto.SigningPublicKeySet {
	if p == nil {
		return nil
	}
	return &crypto.SigningPublicKeySet{Ed25519: p.Ed25519, Mldsa: bytes.Clone(p.Mldsa)}
}

func (s *Session) SetStagingDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stagingDir = dir
}

func (s *Session) StagingDir() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stagingDir
}

func (s *Session) agentKeys() *AgentKeys {
	if s.agent == nil {
		return nil
	}
	return s.agent.Keys()
}

var defaultSession = &Session{}

func SetDefaultKeyAgent(keyAgent KeyAgent) { defaultSession.SetKeyAgent(keyAgent) }

func SetDefaultPasswordPrompter(prompter PasswordPrompter) {
	defaultSession.SetPasswordPrompter(prompter)
}
