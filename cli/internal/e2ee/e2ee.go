package e2ee

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/output"
)

type UploadArtifacts struct {
	EncryptedPath    string
	SealedKeyB64     string
	EncMetaB64       string
	TeeSealedKeyB64  string
	PlaintextHmacHex string
	TeeKeySet        *crypto.PublicKeySet
}

type UploadSignatures struct {
	SignatureEd25519B64 string
	SignatureMldsaB64   string
	SigningPkEd25519B64 string
	SigningPkMldsaB64   string
}

func (s *Session) KeyPair() (*crypto.PublicKeySet, *crypto.PrivateKeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, priv, err := s.keyPairLocked()
	return clonePublicKeySet(pub), clonePrivateKeySet(priv), err
}

func (s *Session) keyPairLocked() (*crypto.PublicKeySet, *crypto.PrivateKeySet, error) {
	if s.background {
		return nil, nil, ErrBackgroundUploadOnly
	}
	cfg := config.Get()
	if cfg.PublicKey == "" || cfg.EncryptedPrivateKey == "" || cfg.PublicKeyKyber == "" || cfg.EncryptedPrivateKeyKyber == "" {
		return nil, nil, ErrNoEncryptionKeys
	}

	if s.pub != nil && s.priv != nil {
		return s.pub, s.priv, nil
	}

	pub, err := decodePublicKeySet(cfg)
	if err != nil {
		return nil, nil, fault("Invalid public key in config", err)
	}

	if keys := s.agentKeys(); keys != nil {
		priv := &crypto.PrivateKeySet{
			X25519: keys.PrivateKey,
			Kyber:  bytes.Clone(keys.KyberSeed),
		}
		s.pub = pub
		s.priv = priv
		s.nameKey = bytes.Clone(keys.NameKey)
		s.hydrateSigningFromAgent(keys)
		return pub, priv, nil
	}

	if config.IsDeviceWrapped() {
		deviceKey, ok := config.LoadE2EEDeviceKey()
		if ok && len(deviceKey) == 32 {
			if enc, derr := decodeEncryptedHybridFromConfig(cfg); derr == nil {
				if priv, uerr := crypto.DecryptHybridPrivateKeyWithRawKey(enc, deviceKey); uerr == nil {
					s.pub = pub
					s.priv = priv
					s.hydrateSigningFromConfigWithPDK(cfg, deviceKey)
					for i := range deviceKey {
						deviceKey[i] = 0
					}
					return pub, priv, nil
				}
			}
			for i := range deviceKey {
				deviceKey[i] = 0
			}
		}
		return nil, nil, ErrDeviceKeysLost
	}

	enc, err := decodeEncryptedHybridFromConfig(cfg)
	if err != nil {
		return nil, nil, fault("Invalid encrypted key material in config", err)
	}

	pwBytes, err := s.readPassword()
	if err != nil {
		return nil, nil, fault("Failed to read password", err)
	}
	if pwBytes == nil {
		return nil, nil, ErrKeysLocked
	}

	salt, err := base64.StdEncoding.DecodeString(cfg.KDFSalt)
	if err != nil {
		return nil, nil, fault("Invalid KDF salt in config", err)
	}
	pdk := crypto.DeriveKey(pwBytes, salt, cfg.KDFOpsLimit, cfg.KDFMemLimit)
	for i := range pwBytes {
		pwBytes[i] = 0
	}
	defer func() {
		for i := range pdk {
			pdk[i] = 0
		}
	}()

	priv, err := crypto.DecryptHybridPrivateKeyWithRawKey(enc, pdk)
	if err != nil {
		return nil, nil, ErrWrongPassword
	}

	s.pub = pub
	s.priv = priv

	s.hydrateSigningFromConfigWithPDK(cfg, pdk)

	return pub, priv, nil
}

func (s *Session) ImportDeviceTransferredKeys(sealedB64 string, ephPriv *crypto.PrivateKeySet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return fmt.Errorf("decode sealed key: %w", err)
	}
	payload, err := crypto.HybridUnseal(sealed, ephPriv)
	if err != nil {
		return fmt.Errorf("unseal key material: %w", err)
	}
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()

	priv, signPriv, err := crypto.ParseDeviceKeyTransfer(payload)
	if err != nil {
		return err
	}
	pub, err := crypto.DeriveHybridPublic(priv)
	if err != nil {
		return fmt.Errorf("derive encryption public: %w", err)
	}
	signPub, err := crypto.DeriveSigningPublic(signPriv)
	if err != nil {
		return fmt.Errorf("derive signing public: %w", err)
	}

	deviceKey := make([]byte, 32)
	if _, err := rand.Read(deviceKey); err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	defer func() {
		for i := range deviceKey {
			deviceKey[i] = 0
		}
	}()

	wrapEnc, err := crypto.EncryptHybridPrivateKeyWithKey(priv, deviceKey)
	if err != nil {
		return fmt.Errorf("wrap encryption key: %w", err)
	}
	wrapSign, err := crypto.EncryptSigningPrivateKeysWithKey(signPriv, deviceKey)
	if err != nil {
		return fmt.Errorf("wrap signing key: %w", err)
	}

	if !config.StoreE2EEDeviceKey(deviceKey) {
		return ErrNoKeychainForDevice
	}

	b64 := base64.StdEncoding.EncodeToString
	if err := config.SetDeviceWrappedE2EEKeys(
		b64(pub.X25519[:]), b64(wrapEnc.X25519Ciphertext), b64(wrapEnc.X25519Nonce),
		b64(pub.Kyber), b64(wrapEnc.KyberCiphertext), b64(wrapEnc.KyberNonce),
		b64(signPub.Ed25519[:]), b64(wrapSign.Ed25519Ciphertext), b64(wrapSign.Ed25519Nonce),
		b64(signPub.Mldsa), b64(wrapSign.MldsaCiphertext), b64(wrapSign.MldsaNonce),
	); err != nil {
		return err
	}

	s.pub = pub
	s.priv = priv
	s.signingPub = signPub
	s.signingPriv = signPriv
	return nil
}

func (s *Session) PublicKey() (*crypto.PublicKeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, err := s.publicKeyLocked()
	return clonePublicKeySet(pub), err
}

func (s *Session) publicKeyLocked() (*crypto.PublicKeySet, error) {
	if s.pub != nil {
		return s.pub, nil
	}
	cfg := config.Get()
	if cfg.PublicKey == "" || cfg.PublicKeyKyber == "" {
		return nil, ErrNoEncryptionKeys
	}
	pub, err := decodePublicKeySet(cfg)
	if err != nil {
		return nil, fault("Invalid public key in config", err)
	}
	s.pub = pub
	return pub, nil
}

func HasE2EEKeys() bool {
	return config.HasEncryptionKeys()
}

func (s *Session) EnsureKeysFromAgent() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ensureKeysFromAgentLocked()
}

func (s *Session) ensureKeysFromAgentLocked() bool {
	if s.priv != nil {
		return true
	}
	keys := s.agentKeys()
	if keys == nil {
		return false
	}
	s.priv = &crypto.PrivateKeySet{X25519: keys.PrivateKey, Kyber: bytes.Clone(keys.KyberSeed)}
	if s.pub == nil {
		s.pub = &crypto.PublicKeySet{X25519: keys.PublicKey, Kyber: bytes.Clone(keys.KyberPublicKey)}
	}
	s.nameKey = bytes.Clone(keys.NameKey)
	s.hydrateSigningFromAgent(keys)
	return true
}

func (s *Session) ClearCachedKey() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priv != nil {
		s.priv.Zero()
		s.priv = nil
	}
	s.pub = nil
	for i := range s.nameKey {
		s.nameKey[i] = 0
	}
	s.nameKey = nil
	for i := range s.parentKey {
		s.parentKey[i] = 0
	}
	s.parentKey = nil
	if s.signingPriv != nil {
		s.signingPriv.Zero()
		s.signingPriv = nil
	}
	s.signingPub = nil
	s.background = false
}

func (s *Session) hasKeysLocked() bool {
	return s.background || HasE2EEKeys()
}

func (s *Session) SigningKeys() (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, priv, err := s.signingKeysLocked()
	return cloneSigningPublicKeySet(pub), cloneSigningPrivateKeySet(priv), err
}

func (s *Session) signingKeysLocked() (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet, error) {
	if s.signingPub != nil && s.signingPriv != nil {
		return s.signingPub, s.signingPriv, nil
	}
	if !config.HasSigningKeys() {
		return nil, nil, ErrNoSigningKeys
	}
	if _, _, err := s.keyPairLocked(); err != nil {
		return nil, nil, err
	}
	if s.signingPub != nil && s.signingPriv != nil {
		return s.signingPub, s.signingPriv, nil
	}
	return nil, nil, ErrSigningUnlockFailed
}

func (s *Session) SigningKeysIfAvailable() (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pub, priv := s.signingKeysIfAvailableLocked()
	return cloneSigningPublicKeySet(pub), cloneSigningPrivateKeySet(priv)
}

func (s *Session) signingKeysIfAvailableLocked() (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	if s.signingPub != nil && s.signingPriv != nil {
		return s.signingPub, s.signingPriv
	}
	if !config.HasSigningKeys() {
		return nil, nil
	}
	_, _, _ = s.keyPairLocked()
	return s.signingPub, s.signingPriv
}

func (s *Session) hydrateSigningFromAgent(keys *AgentKeys) {
	if keys == nil || len(keys.SigningPublicKeyEd25519) != crypto.Ed25519PKSize ||
		len(keys.SigningPrivateKeyEd25519) != crypto.Ed25519SKSize ||
		len(keys.SigningPublicKeyMldsa) != crypto.Mldsa44PKSize ||
		len(keys.SigningPrivateKeyMldsa) != crypto.Mldsa44SKSize {
		return
	}
	var edPub [crypto.Ed25519PKSize]byte
	copy(edPub[:], keys.SigningPublicKeyEd25519)
	pub := &crypto.SigningPublicKeySet{Ed25519: edPub, Mldsa: bytes.Clone(keys.SigningPublicKeyMldsa)}
	edPriv := make([]byte, crypto.Ed25519SKSize)
	copy(edPriv, keys.SigningPrivateKeyEd25519)
	priv := &crypto.SigningPrivateKeySet{Ed25519: edPriv, Mldsa: bytes.Clone(keys.SigningPrivateKeyMldsa)}
	s.signingPub = pub
	s.signingPriv = priv
}

func (s *Session) hydrateSigningFromConfigWithPDK(cfg *config.Config, pdk []byte) {
	if !config.HasSigningKeys() {
		return
	}
	pubEdBytes, err := base64.StdEncoding.DecodeString(cfg.SigningPublicKeyEd25519)
	if err != nil || len(pubEdBytes) != crypto.Ed25519PKSize {
		return
	}
	pubMlBytes, err := base64.StdEncoding.DecodeString(cfg.SigningPublicKeyMldsa)
	if err != nil || len(pubMlBytes) != crypto.Mldsa44PKSize {
		return
	}
	edCT, err := base64.StdEncoding.DecodeString(cfg.EncryptedSigningPrivateKeyEd25519)
	if err != nil {
		return
	}
	edNonce, err := base64.StdEncoding.DecodeString(cfg.SigningPrivateKeyEd25519Nonce)
	if err != nil {
		return
	}
	mlCT, err := base64.StdEncoding.DecodeString(cfg.EncryptedSigningPrivateKeyMldsa)
	if err != nil {
		return
	}
	mlNonce, err := base64.StdEncoding.DecodeString(cfg.SigningPrivateKeyMldsaNonce)
	if err != nil {
		return
	}
	enc := &crypto.EncryptedSigningPrivateKeySet{
		Ed25519Ciphertext: edCT,
		Ed25519Nonce:      edNonce,
		MldsaCiphertext:   mlCT,
		MldsaNonce:        mlNonce,
	}
	priv, err := crypto.DecryptSigningPrivateKeys(enc, pdk)
	if err != nil {
		return
	}
	var edPub [crypto.Ed25519PKSize]byte
	copy(edPub[:], pubEdBytes)
	s.signingPub = &crypto.SigningPublicKeySet{Ed25519: edPub, Mldsa: pubMlBytes}
	s.signingPriv = priv
}

func (s *Session) TeeScannerDisabledByServer() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.teeScannerDisabledByServer
}

func (s *Session) TeeEnclaveKeyRefusal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.teeEnclaveKeyRefusal
}

type teeKeysCall struct {
	done  chan struct{}
	epoch uint64
	set   *crypto.PublicKeySet
}

const teeStaleRecheckGap = 30 * time.Second

var errTeePinOwnerUnknown = errors.New("tee_pin_owner_unknown: no account key set is loaded, so the scanner key the server now offers cannot be checked against this account's pin; the upload was not resent and can be retried once the keys are available")

func (s *Session) FetchTeeEnclaveKeySet(ctx context.Context) *crypto.PublicKeySet {
	s.mu.Lock()
	if cached := s.teeEnclaveKeySet; cached != nil {
		s.mu.Unlock()
		return cached
	}
	if call := s.teeKeysFetch; call != nil {
		s.mu.Unlock()
		return call.wait(ctx)
	}
	call := &teeKeysCall{done: make(chan struct{}), epoch: s.teeKeysEpoch}
	s.teeKeysFetch = call
	s.mu.Unlock()

	set, disabled, answered, refusal := probeTeeEnclaveKeySet(ctx)

	s.mu.Lock()
	if s.teeKeysFetch == call {
		s.teeKeysFetch = nil
	}
	if s.teeKeysEpoch == call.epoch {
		s.teeEnclaveKeyRefusal = refusal
		if answered {
			s.teeScannerDisabledByServer = disabled
		}
		if set != nil {
			s.teeEnclaveKeySet = set
		}
	} else {
		set = nil
	}
	call.set = set
	s.mu.Unlock()
	close(call.done)
	return set
}

func (c *teeKeysCall) wait(ctx context.Context) *crypto.PublicKeySet {
	select {
	case <-c.done:
		return c.set
	case <-ctx.Done():
		return nil
	}
}

func (s *Session) TeeSealWentStale(ctx context.Context, err error, sealedTo *crypto.PublicKeySet) (bool, error) {
	if !api.MayBeStaleTeeSeal(err) {
		return false, nil
	}
	s.mu.Lock()
	if time.Since(s.teeStaleCheckedAt) < teeStaleRecheckGap {
		current, call := s.teeEnclaveKeySet, s.teeKeysFetch
		s.mu.Unlock()
		if current == nil && call != nil {
			current = call.wait(ctx)
		}
		return s.staleSealVerdict(current, sealedTo)
	}
	s.teeStaleCheckedAt = time.Now()
	s.teeEnclaveKeySet = nil
	s.mu.Unlock()

	return s.staleSealVerdict(s.FetchTeeEnclaveKeySet(ctx), sealedTo)
}

func (s *Session) staleSealVerdict(fresh, sealedTo *crypto.PublicKeySet) (bool, error) {
	if fresh == nil {
		return false, s.TeeEnclaveKeyRefusal()
	}
	if signingPinOwner() == "" {
		return false, errTeePinOwnerUnknown
	}
	if !teeKeySetMatchesPin(fresh) {
		return false, errTeeEnclavePkChanged()
	}
	return !sameTeeKeySet(fresh, sealedTo), nil
}

func sameTeeKeySet(a, b *crypto.PublicKeySet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.X25519 == b.X25519 && bytes.Equal(a.Kyber, b.Kyber)
}

func probeTeeEnclaveKeySet(ctx context.Context) (set *crypto.PublicKeySet, disabled, answered bool, refusal error) {
	client := api.NewClient()
	resp, err := client.FetchTeeAttestation(ctx)
	if err != nil || resp == nil || !resp.Success {
		return nil, false, false, nil
	}
	answered = true
	disabled = !resp.Enabled
	if !resp.Available {
		return nil, disabled, answered, nil
	}
	att := resp.Attestation
	commit, err := checkTeeAttestationPosture(servedAttestation{
		Mode:           att.AttestationMode,
		Mrenclave:      att.Mrenclave,
		Quote:          att.SgxQuote,
		Status:         att.VerificationStatus,
		SealingPk:      att.EnclavePublicKey,
		SealingPkKyber: att.EnclavePublicKeyKyber,
	})
	if err != nil {
		return nil, disabled, answered, err
	}
	xBytes, err := base64.StdEncoding.DecodeString(att.EnclavePublicKey)
	if err != nil || len(xBytes) != 32 {
		return nil, disabled, answered, errors.New("tee_enclave_key_malformed: the server answered with an X25519 sealing key that is not 32 bytes")
	}
	kBytes, err := base64.StdEncoding.DecodeString(att.EnclavePublicKeyKyber)
	if err != nil || len(kBytes) != crypto.KyberPublicKeySize {
		return nil, disabled, answered, errors.New("tee_enclave_key_malformed: the server answered with an ML-KEM sealing key of the wrong size")
	}
	commit()
	var x [32]byte
	copy(x[:], xBytes)
	return &crypto.PublicKeySet{X25519: x, Kyber: kBytes}, disabled, answered, nil
}

func (s *Session) ParentKey() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	parentKey, err := s.parentKeyLocked()
	return bytes.Clone(parentKey), err
}

func (s *Session) parentKeyLocked() ([]byte, error) {
	if s.parentKey != nil {
		return s.parentKey, nil
	}
	_, priv, err := s.keyPairLocked()
	if err != nil {
		return nil, err
	}
	parentKey, err := crypto.DeriveParentKey(priv)
	if err != nil {
		return nil, fault("Failed to derive parent key", err)
	}
	s.parentKey = parentKey
	return s.parentKey, nil
}

func SealedRootParentB64(nodeIDHex string, parentKey []byte) string {
	nodeID, err := hex.DecodeString(nodeIDHex)
	if err != nil || len(parentKey) == 0 {
		return ""
	}
	blob, err := crypto.SealParentRef(nil, nodeID, parentKey)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(blob)
}

func (s *Session) NameKey() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	nameKey, err := s.nameKeyLocked()
	return bytes.Clone(nameKey), err
}

func (s *Session) nameKeyLocked() ([]byte, error) {
	if s.nameKey != nil {
		return s.nameKey, nil
	}
	_, priv, err := s.keyPairLocked()
	if err != nil {
		return nil, err
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		return nil, fault("Failed to derive name key", err)
	}
	s.nameKey = nameKey
	return nameKey, nil
}

func (s *Session) AddE2eeNameFields(options map[string]string, fileName, fullPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasKeysLocked() {
		return nil
	}
	pub, err := s.publicKeyLocked()
	if err != nil {
		return err
	}
	nameKey, err := s.nameKeyLocked()
	if err != nil {
		return err
	}

	sealedName, err := crypto.SealDisplayName(fileName, pub)
	if err != nil {
		return fault("Failed to seal display name", err)
	}
	pathToken, err := crypto.ComputePathToken(nameKey, fullPath)
	if err != nil {
		return fault("Failed to compute path token", err)
	}

	options["e2ee_display_name"] = base64.StdEncoding.EncodeToString(sealedName)
	options["e2ee_path_token"] = hex.EncodeToString(pathToken)
	return nil
}

func (s *Session) AddE2eeNameFieldsForMkParents(options map[string]string, pathSegments []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasKeysLocked() {
		return nil
	}
	pub, err := s.publicKeyLocked()
	if err != nil {
		return err
	}
	nameKey, err := s.nameKeyLocked()
	if err != nil {
		return err
	}

	type segment struct {
		DisplayName string `json:"e2ee_display_name"`
		PathToken   string `json:"e2ee_path_token"`
	}

	segments := make([]segment, 0, len(pathSegments))
	currentPath := ""
	for _, part := range pathSegments {
		if currentPath == "" {
			currentPath = part
		} else {
			currentPath = currentPath + "/" + part
		}
		sealedName, err := crypto.SealDisplayName(part, pub)
		if err != nil {
			continue
		}
		pathToken, err := crypto.ComputePathToken(nameKey, currentPath)
		if err != nil {
			continue
		}
		segments = append(segments, segment{
			DisplayName: base64.StdEncoding.EncodeToString(sealedName),
			PathToken:   hex.EncodeToString(pathToken),
		})
	}

	if len(segments) > 0 {
		data, err := json.Marshal(segments)
		if err == nil {
			options["e2ee_path_segments"] = string(data)
		}
	}
	return nil
}

func ResolveAndBaseName(resolvedPath string) (fullPath, baseName string) {
	fullPath = resolvedPath
	if len(fullPath) > 0 && fullPath[0] == '/' {
		fullPath = fullPath[1:]
	}
	baseName = filepath.Base(resolvedPath)
	return
}

const NameUnavailable = output.NameUnavailable

func IsNameUnavailable(name string) bool {
	return name == "" || name == NameUnavailable
}

func OpenDisplayName(sealedB64 string, priv *crypto.PrivateKeySet) string {
	if sealedB64 == "" {
		return ""
	}
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return NameUnavailable
	}
	name, err := crypto.UnsealDisplayName(sealed, priv)
	if err != nil || !fsutil.IsDisplaySafeName(name) {
		return NameUnavailable
	}
	return name
}

func OpenLocalName(sealedB64 string, priv *crypto.PrivateKeySet) string {
	name := OpenDisplayName(sealedB64, priv)
	if name != "" && !fsutil.IsSafeName(name) {
		return NameUnavailable
	}
	return name
}

func ResolveName(sealedB64, fallback string) string {
	if sealedB64 == "" {
		return fallback
	}
	return DecryptE2EEName(sealedB64)
}

func (s *Session) DecryptE2EEName(e2eeDisplayNameB64 string) string {
	if e2eeDisplayNameB64 == "" || !HasE2EEKeys() {
		return NameUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.priv == nil {
		keys := s.agentKeys()
		if keys == nil {
			return NameUnavailable
		}
		s.priv = &crypto.PrivateKeySet{
			X25519: keys.PrivateKey,
			Kyber:  bytes.Clone(keys.KyberSeed),
		}
		if s.pub == nil {
			s.pub = &crypto.PublicKeySet{X25519: keys.PublicKey, Kyber: bytes.Clone(keys.KyberPublicKey)}
		}
		s.nameKey = bytes.Clone(keys.NameKey)
	}
	return OpenDisplayName(e2eeDisplayNameB64, s.priv)
}

func (s *Session) ComputePathTokenMaps(paths []string) (canonicalJSON, legacyJSON string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.computePathTokenMapsLocked(paths)
}

func (s *Session) computePathTokenMapsLocked(paths []string) (canonicalJSON, legacyJSON string, err error) {
	if !HasE2EEKeys() || len(paths) == 0 {
		return "", "", nil
	}
	cleaned := make([]string, len(paths))
	for i, p := range paths {
		cleaned[i] = strings.ReplaceAll(p, "\\", "/")
	}
	nameKey, err := s.nameKeyLocked()
	if err != nil {
		return "", "", err
	}
	canonicalJSON, legacyJSON = crypto.PathTokenOptionJSON(nameKey, cleaned)
	return canonicalJSON, legacyJSON, nil
}

func (s *Session) AddPathTokens(options map[string]string, paths []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addPathTokensLocked(options, paths)
}

func (s *Session) addPathTokensLocked(options map[string]string, paths []string) error {
	canonicalJSON, legacyJSON, err := s.computePathTokenMapsLocked(paths)
	if err != nil {
		return err
	}
	if canonicalJSON != "" {
		options["path_tokens"] = canonicalJSON
	}
	if legacyJSON != "" {
		options["path_tokens_legacy"] = legacyJSON
	}
	return nil
}

type Depth = crypto.PathTokenDepth

const (
	SelfOnly = crypto.PathTokenSelfOnly
	SelfAndParent = crypto.PathTokenSelfAndParent
	SelfAndAncestors = crypto.PathTokenSelfAndAncestors
)

func (s *Session) AddPathTokensFor(options map[string]string, remotePath string, depth Depth) error {
	return s.AddPathTokensForAll(options, []string{remotePath}, depth)
}

func (s *Session) AddPathTokensForAll(options map[string]string, remotePaths []string, depth Depth) error {
	if !HasE2EEKeys() {
		return nil
	}
	var paths []string
	for _, remotePath := range remotePaths {
		paths = append(paths, crypto.PathTokenPaths(remotePath, depth)...)
	}
	return s.AddPathTokens(options, paths)
}

func (s *Session) SetSuppliedPassword(pw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.supplied = pw
}

func (s *Session) EncryptForUpload(ctx context.Context, localPath string) (*UploadArtifacts, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return nil, err
	}

	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		return nil, fault("Failed to generate data key", err)
	}

	tempFile, err := os.CreateTemp(s.StagingDir(), "pigcloud-e2ee-*")
	if err != nil {
		return nil, fault("Failed to create temp file", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	meta, err := crypto.EncryptFile(localPath, tempPath, dataKey)
	if err != nil {
		os.Remove(tempPath)
		return nil, fault("Failed to encrypt file", err)
	}

	sealedKey, err := crypto.SealDataKey(dataKey, pub)
	if err != nil {
		os.Remove(tempPath)
		return nil, fault("Failed to seal data key", err)
	}

	metaJSON, err := meta.WireJSON()
	if err != nil {
		os.Remove(tempPath)
		return nil, fault("Failed to encode encryption metadata", err)
	}

	teeKeys := s.FetchTeeEnclaveKeySet(ctx)
	if teeKeys == nil && !s.TeeScannerDisabledByServer() {
		os.Remove(tempPath)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if refusal := s.TeeEnclaveKeyRefusal(); refusal != nil {
			return nil, fault(ErrScannerRefusedUpload.Message, refusal)
		}
		return nil, ErrScannerUnreachable
	}
	teeSealedB64 := ""
	if teeKeys != nil {
		teeSealed, err := crypto.SealDataKey(dataKey, teeKeys)
		if err != nil {
			os.Remove(tempPath)
			return nil, fault("Failed to seal data key to enclave", err)
		}
		teeSealedB64 = base64.StdEncoding.EncodeToString(teeSealed)
	}

	var hmacHex string
	nameKey, nameErr := s.NameKey()
	if nameErr != nil {
		os.Remove(tempPath)
		return nil, nameErr
	}
	if nameKey != nil {
		if h, err := crypto.ComputePlaintextHmac(meta.PlaintextSHA256, nameKey); err == nil {
			hmacHex = h
		}
	}

	return &UploadArtifacts{
		EncryptedPath:    tempPath,
		SealedKeyB64:     base64.StdEncoding.EncodeToString(sealedKey),
		EncMetaB64:       base64.StdEncoding.EncodeToString(metaJSON),
		TeeSealedKeyB64:  teeSealedB64,
		PlaintextHmacHex: hmacHex,
		TeeKeySet:        teeKeys,
	}, nil
}

func (s *Session) SignEncryptedFile(encryptedPath string) (*UploadSignatures, error) {
	signPub, signPriv, err := s.SigningKeys()
	if err != nil {
		return nil, err
	}
	f, err := os.Open(encryptedPath)
	if err != nil {
		return nil, fault("Failed to open encrypted file for signing", err)
	}
	defer f.Close()
	sigEd, sigMldsa, err := crypto.SignFileBytes(f, signPriv)
	if err != nil {
		return nil, fault("Failed to sign encrypted file", err)
	}
	return &UploadSignatures{
		SignatureEd25519B64: base64.StdEncoding.EncodeToString(sigEd),
		SignatureMldsaB64:   base64.StdEncoding.EncodeToString(sigMldsa),
		SigningPkEd25519B64: base64.StdEncoding.EncodeToString(signPub.Ed25519[:]),
		SigningPkMldsaB64:   base64.StdEncoding.EncodeToString(signPub.Mldsa),
	}, nil
}

func PropagateNameToShares(ctx context.Context, nodeIDHex, plaintextName string) {
	if nodeIDHex == "" || plaintextName == "" || !HasE2EEKeys() {
		return
	}
	client := api.NewClient()
	resp, err := client.ShareRecipientsForNode(ctx, nodeIDHex)
	if err != nil || !resp.Success || len(resp.Recipients) == 0 {
		return
	}
	for _, r := range resp.Recipients {
		recipient, err := PinShareRecipientSealKey(ctx, r)
		if err != nil {
			if IsSealPinFailure(err) {
				output.PrintError(err.Error())
			}
			continue
		}
		sealed, err := crypto.SealDisplayName(plaintextName, recipient)
		if err != nil {
			continue
		}
		_ = client.StoreShareDisplayNames(ctx, r.Username, "", []api.SealedNameEntry{{
			NodeID:            nodeIDHex,
			SealedDisplayName: base64.StdEncoding.EncodeToString(sealed),
		}})
	}
}

func (s *Session) PropagateSubtreeNamesAtPath(ctx context.Context, path string) error {
	if !HasE2EEKeys() {
		return nil
	}
	client := api.NewClient()
	keysResp, err := client.Execute(ctx, "e2ee_list_keys", map[string]string{
		"source":        path,
		"include_names": "1",
		"include_dirs":  "1",
	})
	if err != nil || !keysResp.Success {
		return nil
	}
	var keysPayload api.E2EEListKeysPayload
	if err := json.Unmarshal(keysResp.Raw, &keysPayload); err != nil {
		return nil
	}
	if len(keysPayload.Keys) == 0 {
		return nil
	}

	_, priv, err := s.KeyPair()
	if err != nil {
		return err
	}

	pubKeyCache := make(map[string]*crypto.PublicKeySet)
	perRecipient := make(map[string][]api.SealedNameEntry)

	for _, k := range keysPayload.Keys {
		if k.E2EEDisplayName == "" {
			continue
		}
		sealedNameBytes, err := base64.StdEncoding.DecodeString(k.E2EEDisplayName)
		if err != nil {
			continue
		}
		plaintext, err := crypto.UnsealDisplayName(sealedNameBytes, priv)
		if err != nil {
			continue
		}
		recResp, err := client.ShareRecipientsForNode(ctx, k.NodeID)
		if err != nil || !recResp.Success || len(recResp.Recipients) == 0 {
			continue
		}
		for _, r := range recResp.Recipients {
			recipient, ok := pubKeyCache[r.Username]
			if !ok {
				pinned, err := PinShareRecipientSealKey(ctx, r)
				if err != nil {
					if IsSealPinFailure(err) {
						output.PrintError(err.Error())
					}
					continue
				}
				recipient = pinned
				pubKeyCache[r.Username] = recipient
			}
			sealed, err := crypto.SealDisplayName(plaintext, recipient)
			if err != nil {
				continue
			}
			perRecipient[r.Username] = append(perRecipient[r.Username], api.SealedNameEntry{
				NodeID:            k.NodeID,
				SealedDisplayName: base64.StdEncoding.EncodeToString(sealed),
			})
		}
	}

	for username, names := range perRecipient {
		_ = client.StoreShareDisplayNames(ctx, username, "", names)
	}
	return nil
}

func decodeRecipient(r api.ShareRecipientWithKey) (*crypto.PublicKeySet, error) {
	if r.PublicKey == "" || r.PublicKeyKyber == "" {
		return nil, fmt.Errorf("recipient missing one or both public keys")
	}
	xBytes, err := base64.StdEncoding.DecodeString(r.PublicKey)
	if err != nil || len(xBytes) != 32 {
		return nil, fmt.Errorf("invalid x25519 pubkey")
	}
	kBytes, err := base64.StdEncoding.DecodeString(r.PublicKeyKyber)
	if err != nil || len(kBytes) != crypto.KyberPublicKeySize {
		return nil, fmt.Errorf("invalid kyber pubkey")
	}
	var x [32]byte
	copy(x[:], xBytes)
	return &crypto.PublicKeySet{X25519: x, Kyber: kBytes}, nil
}

func decodePublicKeySet(cfg *config.Config) (*crypto.PublicKeySet, error) {
	xBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil || len(xBytes) != 32 {
		return nil, fmt.Errorf("invalid x25519 pubkey")
	}
	kBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKeyKyber)
	if err != nil || len(kBytes) != crypto.KyberPublicKeySize {
		return nil, fmt.Errorf("invalid kyber pubkey")
	}
	var x [32]byte
	copy(x[:], xBytes)
	return &crypto.PublicKeySet{X25519: x, Kyber: kBytes}, nil
}

func decodeEncryptedHybridFromConfig(cfg *config.Config) (*crypto.EncryptedHybridPrivateKey, error) {
	xCT, err := base64.StdEncoding.DecodeString(cfg.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("encrypted_private_key: %w", err)
	}
	xN, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyNonce)
	if err != nil {
		return nil, fmt.Errorf("private_key_nonce: %w", err)
	}
	kCT, err := base64.StdEncoding.DecodeString(cfg.EncryptedPrivateKeyKyber)
	if err != nil {
		return nil, fmt.Errorf("encrypted_private_key_kyber: %w", err)
	}
	kN, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyKyberNonce)
	if err != nil {
		return nil, fmt.Errorf("private_key_kyber_nonce: %w", err)
	}
	salt, err := base64.StdEncoding.DecodeString(cfg.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("kdf_salt: %w", err)
	}
	return &crypto.EncryptedHybridPrivateKey{
		X25519Ciphertext: xCT,
		X25519Nonce:      xN,
		KyberCiphertext:  kCT,
		KyberNonce:       kN,
		Salt:             salt,
		OpsLimit:         cfg.KDFOpsLimit,
		MemLimit:         cfg.KDFMemLimit,
	}, nil
}

func (s *Session) readPassword() ([]byte, error) {
	if s.supplied != nil {
		pw := s.supplied
		s.supplied = nil
		return pw, nil
	}
	if s.prompter == nil {
		return nil, nil
	}
	return s.prompter.Password()
}
