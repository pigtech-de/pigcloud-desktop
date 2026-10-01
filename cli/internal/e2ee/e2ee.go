package e2ee

import (
	"bufio"
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
	"syscall"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/output"

	"golang.org/x/term"
)

var (
	cachedPub  *crypto.PublicKeySet
	cachedPriv *crypto.PrivateKeySet

	cachedTeeEnclaveKeySet     *crypto.PublicKeySet
	teeScannerDisabledByServer bool
	teeEnclaveKeyRefusal       error

	cachedNameKey []byte

	cachedParentKey []byte

	cachedSigningPub  *crypto.SigningPublicKeySet
	cachedSigningPriv *crypto.SigningPrivateKeySet
)

func GetKeyPair(exitFn func()) (*crypto.PublicKeySet, *crypto.PrivateKeySet) {
	cfg := config.Get()
	if cfg.PublicKey == "" || cfg.EncryptedPrivateKey == "" || cfg.PublicKeyKyber == "" || cfg.EncryptedPrivateKeyKyber == "" {
		output.PrintError("No encryption keys configured. Run 'pc li' to set up encryption.")
		exitFn()
		return nil, nil
	}

	if cachedPub != nil && cachedPriv != nil {
		return cachedPub, cachedPriv
	}

	pub, err := decodePublicKeySet(cfg)
	if err != nil {
		output.PrintError("Invalid public key in config: " + err.Error())
		exitFn()
		return nil, nil
	}

	if keys := agent.RequestKeys(); keys != nil {
		priv := &crypto.PrivateKeySet{
			X25519: keys.PrivateKey,
			Kyber:  keys.KyberSeed,
		}
		cachedPub = pub
		cachedPriv = priv
		cachedNameKey = keys.NameKey
		hydrateSigningFromAgent(keys)
		return pub, priv
	}

	if config.IsDeviceWrapped() {
		deviceKey, ok := config.LoadE2EEDeviceKey()
		if ok && len(deviceKey) == 32 {
			if enc, derr := decodeEncryptedHybridFromConfig(cfg); derr == nil {
				if priv, uerr := crypto.DecryptHybridPrivateKeyWithRawKey(enc, deviceKey); uerr == nil {
					cachedPub = pub
					cachedPriv = priv
					hydrateSigningFromConfigWithPDK(cfg, deviceKey)
					for i := range deviceKey {
						deviceKey[i] = 0
					}
					return pub, priv
				}
			}
			for i := range deviceKey {
				deviceKey[i] = 0
			}
		}
		output.PrintError("Encryption keys unavailable (device keychain locked or reset). Run 'pc login' again.")
		exitFn()
		return nil, nil
	}

	enc, err := decodeEncryptedHybridFromConfig(cfg)
	if err != nil {
		output.PrintError("Invalid encrypted key material in config: " + err.Error())
		exitFn()
		return nil, nil
	}

	pwBytes, err := readPasswordPrompt()
	if err != nil {
		output.PrintError("Failed to read password: " + err.Error())
		exitFn()
		return nil, nil
	}
	if pwBytes == nil {
		output.PrintError("Keys are locked. Run 'pc uk' to unlock.")
		exitFn()
		return nil, nil
	}

	salt, err := base64.StdEncoding.DecodeString(cfg.KDFSalt)
	if err != nil {
		output.PrintError("Invalid KDF salt in config: " + err.Error())
		exitFn()
		return nil, nil
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
		output.PrintError("Wrong password")
		exitFn()
		return nil, nil
	}

	cachedPub = pub
	cachedPriv = priv

	hydrateSigningFromConfigWithPDK(cfg, pdk)

	return pub, priv
}

func ImportDeviceTransferredKeys(sealedB64 string, ephPriv *crypto.PrivateKeySet) error {
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
		return fmt.Errorf("no OS keychain available to hold the device key")
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

	cachedPub = pub
	cachedPriv = priv
	cachedSigningPub = signPub
	cachedSigningPriv = signPriv
	return nil
}

func GetPublicKey(exitFn func()) *crypto.PublicKeySet {
	if cachedPub != nil {
		return cachedPub
	}
	cfg := config.Get()
	if cfg.PublicKey == "" || cfg.PublicKeyKyber == "" {
		output.PrintError("No encryption keys configured. Run 'pc li' to set up encryption.")
		exitFn()
		return nil
	}
	pub, err := decodePublicKeySet(cfg)
	if err != nil {
		output.PrintError("Invalid public key in config: " + err.Error())
		exitFn()
		return nil
	}
	cachedPub = pub
	return pub
}

func HasE2EEKeys() bool {
	return config.HasEncryptionKeys()
}

func EnsureKeysFromAgent() bool {
	if cachedPriv != nil {
		return true
	}
	keys := agent.RequestKeys()
	if keys == nil {
		return false
	}
	cachedPriv = &crypto.PrivateKeySet{X25519: keys.PrivateKey, Kyber: keys.KyberSeed}
	if cachedPub == nil {
		cachedPub = &crypto.PublicKeySet{X25519: keys.PublicKey, Kyber: keys.KyberPublicKey}
	}
	cachedNameKey = keys.NameKey
	hydrateSigningFromAgent(keys)
	return true
}

func StartAgentForKeys(pub *crypto.PublicKeySet, priv *crypto.PrivateKeySet, nameKey []byte, signPub *crypto.SigningPublicKeySet, signPriv *crypto.SigningPrivateKeySet, ttl time.Duration) error {
	agent.Shutdown()

	pubHex := hex.EncodeToString(pub.X25519[:])
	privHex := hex.EncodeToString(priv.X25519[:])
	kyberPubHex := hex.EncodeToString(pub.Kyber)
	kyberSeedHex := hex.EncodeToString(priv.Kyber)
	nameHex := hex.EncodeToString(nameKey)

	var signPubEdHex, signPrivEdHex, signPubMlHex, signPrivMlHex string
	if signPub != nil && signPriv != nil {
		signPubEdHex = hex.EncodeToString(signPub.Ed25519[:])
		signPrivEdHex = hex.EncodeToString(signPriv.Ed25519)
		signPubMlHex = hex.EncodeToString(signPub.Mldsa)
		signPrivMlHex = hex.EncodeToString(signPriv.Mldsa)
	}

	if err := agent.SpawnBackground(agent.SpawnKeys{
		PubHex:        pubHex,
		PrivHex:       privHex,
		KyberPubHex:   kyberPubHex,
		KyberSeedHex:  kyberSeedHex,
		NameKeyHex:    nameHex,
		SignPubEdHex:  signPubEdHex,
		SignPrivEdHex: signPrivEdHex,
		SignPubMlHex:  signPubMlHex,
		SignPrivMlHex: signPrivMlHex,
	}, int(ttl.Seconds())); err != nil {
		return err
	}
	for range 10 {
		time.Sleep(100 * time.Millisecond)
		if agent.IsRunning() {
			return nil
		}
	}
	return fmt.Errorf("agent did not start")
}

func EnsureNamesReadable() bool {
	if EnsureKeysFromAgent() {
		return true
	}
	if !HasE2EEKeys() {
		output.PrintWarning("Encryption isn't set up for this account. Finish setup in the web app.")
		return false
	}
	if !term.IsTerminal(int(syscall.Stdin)) {
		output.PrintWarning("Encryption is locked — file names are hidden. Run 'pc uk' to unlock.")
		return false
	}
	output.PrintInfo("Encryption is locked — unlock to view file names.")
	pub, priv := GetKeyPair(func() {})
	if priv == nil {
		return false
	}
	nameKey := GetNameKey(func() {})
	signPub, signPriv := GetSigningKeysIfAvailable(func() {})
	if err := StartAgentForKeys(pub, priv, nameKey, signPub, signPriv, time.Hour); err != nil {
		output.PrintWarning("Unlocked for this command (agent didn't start — run 'pc uk' to persist).")
	}
	return true
}

func ClearCachedKey() {
	if cachedPriv != nil {
		cachedPriv.Zero()
		cachedPriv = nil
	}
	cachedPub = nil
	for i := range cachedNameKey {
		cachedNameKey[i] = 0
	}
	cachedNameKey = nil
	for i := range cachedParentKey {
		cachedParentKey[i] = 0
	}
	cachedParentKey = nil
	if cachedSigningPriv != nil {
		cachedSigningPriv.Zero()
		cachedSigningPriv = nil
	}
	cachedSigningPub = nil
}

func GetSigningKeys(exitFn func()) (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	if cachedSigningPub != nil && cachedSigningPriv != nil {
		return cachedSigningPub, cachedSigningPriv
	}
	if !config.HasSigningKeys() {
		output.PrintError("Signing keys not configured for this account. Open the web app to complete E2EE setup.")
		exitFn()
		return nil, nil
	}
	GetKeyPair(exitFn)
	if cachedSigningPub != nil && cachedSigningPriv != nil {
		return cachedSigningPub, cachedSigningPriv
	}
	output.PrintError("Failed to unlock signing keys. Re-run 'pc uk' to refresh, then retry.")
	exitFn()
	return nil, nil
}

func GetSigningKeysIfAvailable(exitFn func()) (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	if cachedSigningPub != nil && cachedSigningPriv != nil {
		return cachedSigningPub, cachedSigningPriv
	}
	if !config.HasSigningKeys() {
		return nil, nil
	}
	GetKeyPair(exitFn)
	return cachedSigningPub, cachedSigningPriv
}

func hydrateSigningFromAgent(keys *agent.KeyMaterial) {
	if keys == nil || len(keys.SigningPublicKeyEd25519) != crypto.Ed25519PKSize ||
		len(keys.SigningPrivateKeyEd25519) != crypto.Ed25519SKSize ||
		len(keys.SigningPublicKeyMldsa) != crypto.Mldsa44PKSize ||
		len(keys.SigningPrivateKeyMldsa) != crypto.Mldsa44SKSize {
		return
	}
	var edPub [crypto.Ed25519PKSize]byte
	copy(edPub[:], keys.SigningPublicKeyEd25519)
	pub := &crypto.SigningPublicKeySet{Ed25519: edPub, Mldsa: keys.SigningPublicKeyMldsa}
	edPriv := make([]byte, crypto.Ed25519SKSize)
	copy(edPriv, keys.SigningPrivateKeyEd25519)
	priv := &crypto.SigningPrivateKeySet{Ed25519: edPriv, Mldsa: keys.SigningPrivateKeyMldsa}
	cachedSigningPub = pub
	cachedSigningPriv = priv
}

func hydrateSigningFromConfigWithPDK(cfg *config.Config, pdk []byte) {
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
	cachedSigningPub = &crypto.SigningPublicKeySet{Ed25519: edPub, Mldsa: pubMlBytes}
	cachedSigningPriv = priv
}

func TeeScannerDisabledByServer() bool {
	return teeScannerDisabledByServer
}

func TeeEnclaveKeyRefusal() error {
	return teeEnclaveKeyRefusal
}

func FetchTeeEnclaveKeySet() *crypto.PublicKeySet {
	if cachedTeeEnclaveKeySet != nil {
		return cachedTeeEnclaveKeySet
	}
	teeEnclaveKeyRefusal = nil
	client := api.NewClient()
	resp, err := client.FetchTeeAttestation(context.Background())
	if err != nil || resp == nil || !resp.Success {
		return nil
	}
	teeScannerDisabledByServer = !resp.Enabled
	if !resp.Available {
		return nil
	}
	att := resp.Attestation
	commit, err := checkTeeAttestationPosture(servedAttestation{
		Mode:      att.AttestationMode,
		Mrenclave: att.Mrenclave,
		Quote:     att.SgxQuote,
		Status:    att.VerificationStatus,
		SealingPk: att.EnclavePublicKey,
	})
	if err != nil {
		teeEnclaveKeyRefusal = err
		return nil
	}
	xBytes, err := base64.StdEncoding.DecodeString(att.EnclavePublicKey)
	if err != nil || len(xBytes) != 32 {
		teeEnclaveKeyRefusal = errors.New("tee_enclave_key_malformed: the server answered with an X25519 sealing key that is not 32 bytes")
		return nil
	}
	kBytes, err := base64.StdEncoding.DecodeString(att.EnclavePublicKeyKyber)
	if err != nil || len(kBytes) != crypto.KyberPublicKeySize {
		teeEnclaveKeyRefusal = errors.New("tee_enclave_key_malformed: the server answered with an ML-KEM sealing key of the wrong size")
		return nil
	}
	commit()
	var x [32]byte
	copy(x[:], xBytes)
	cachedTeeEnclaveKeySet = &crypto.PublicKeySet{X25519: x, Kyber: kBytes}
	return cachedTeeEnclaveKeySet
}

func GetParentKey(exitFn func()) []byte {
	if cachedParentKey != nil {
		return cachedParentKey
	}
	_, priv := GetKeyPair(exitFn)
	if priv == nil {
		return nil
	}
	parentKey, err := crypto.DeriveParentKey(priv)
	if err != nil {
		output.PrintError("Failed to derive parent key: " + err.Error())
		exitFn()
		return nil
	}
	cachedParentKey = parentKey
	return cachedParentKey
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

func GetNameKey(exitFn func()) []byte {
	if cachedNameKey != nil {
		return cachedNameKey
	}
	_, priv := GetKeyPair(exitFn)
	if priv == nil {
		return nil
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		output.PrintError("Failed to derive name key: " + err.Error())
		exitFn()
		return nil
	}
	cachedNameKey = nameKey
	return nameKey
}

func AddE2eeNameFields(options map[string]string, fileName, fullPath string, exitFn func()) {
	if !HasE2EEKeys() {
		return
	}
	pub := GetPublicKey(exitFn)
	nameKey := GetNameKey(exitFn)

	sealedName, err := crypto.SealDisplayName(fileName, pub)
	if err != nil {
		output.PrintError("Failed to seal display name: " + err.Error())
		exitFn()
		return
	}
	pathToken, err := crypto.ComputePathToken(nameKey, fullPath)
	if err != nil {
		output.PrintError("Failed to compute path token: " + err.Error())
		exitFn()
		return
	}

	options["e2ee_display_name"] = base64.StdEncoding.EncodeToString(sealedName)
	options["e2ee_path_token"] = hex.EncodeToString(pathToken)
}

func AddE2eeNameFieldsForMkParents(options map[string]string, pathSegments []string, exitFn func()) {
	if !HasE2EEKeys() {
		return
	}
	pub := GetPublicKey(exitFn)
	nameKey := GetNameKey(exitFn)

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
}

func ResolveAndBaseName(resolvedPath string) (fullPath, baseName string) {
	fullPath = resolvedPath
	if len(fullPath) > 0 && fullPath[0] == '/' {
		fullPath = fullPath[1:]
	}
	baseName = filepath.Base(resolvedPath)
	return
}

func DecryptE2EEName(e2eeDisplayNameB64 string) string {
	if e2eeDisplayNameB64 == "" || !HasE2EEKeys() {
		return "(encrypted)"
	}
	sealed, err := base64.StdEncoding.DecodeString(e2eeDisplayNameB64)
	if err != nil {
		return "(encrypted)"
	}
	if cachedPriv != nil {
		name, err := crypto.UnsealDisplayName(sealed, cachedPriv)
		if err != nil {
			return "(encrypted)"
		}
		return name
	}
	if keys := agent.RequestKeys(); keys != nil {
		priv := &crypto.PrivateKeySet{
			X25519: keys.PrivateKey,
			Kyber:  keys.KyberSeed,
		}
		cachedPriv = priv
		if cachedPub == nil {
			cachedPub = &crypto.PublicKeySet{X25519: keys.PublicKey, Kyber: keys.KyberPublicKey}
		}
		cachedNameKey = keys.NameKey
		name, err := crypto.UnsealDisplayName(sealed, priv)
		if err != nil {
			return "(encrypted)"
		}
		return name
	}
	return "(encrypted)"
}

func ComputePathTokenMaps(paths []string, exitFn func()) (canonicalJSON, legacyJSON string) {
	if !HasE2EEKeys() || len(paths) == 0 {
		return "", ""
	}
	cleaned := make([]string, len(paths))
	for i, p := range paths {
		cleaned[i] = strings.ReplaceAll(p, "\\", "/")
	}
	return crypto.PathTokenOptionJSON(GetNameKey(exitFn), cleaned)
}

func AddPathTokens(options map[string]string, paths []string, exitFn func()) {
	canonicalJSON, legacyJSON := ComputePathTokenMaps(paths, exitFn)
	if canonicalJSON != "" {
		options["path_tokens"] = canonicalJSON
	}
	if legacyJSON != "" {
		options["path_tokens_legacy"] = legacyJSON
	}
}

type Depth = crypto.PathTokenDepth

const (
	SelfOnly = crypto.PathTokenSelfOnly
	SelfAndParent = crypto.PathTokenSelfAndParent
	SelfAndAncestors = crypto.PathTokenSelfAndAncestors
)

func AddPathTokensFor(options map[string]string, remotePath string, depth Depth, exitFn func()) {
	AddPathTokensForAll(options, []string{remotePath}, depth, exitFn)
}

func AddPathTokensForAll(options map[string]string, remotePaths []string, depth Depth, exitFn func()) {
	if !HasE2EEKeys() {
		return
	}
	var paths []string
	for _, remotePath := range remotePaths {
		paths = append(paths, crypto.PathTokenPaths(remotePath, depth)...)
	}
	AddPathTokens(options, paths, exitFn)
}

func HandleE2EEUpload(localPath string, exitFn func()) (encryptedPath string, sealedKeyB64 string, encMetaB64 string, teeSealedKeyB64 string, plaintextHmacHex string) {
	pub := GetPublicKey(exitFn)

	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		output.PrintError("Failed to generate data key: " + err.Error())
		exitFn()
		return "", "", "", "", ""
	}

	tempFile, err := os.CreateTemp("", "pigcloud-e2ee-*")
	if err != nil {
		output.PrintError("Failed to create temp file: " + err.Error())
		exitFn()
		return "", "", "", "", ""
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	meta, err := crypto.EncryptFile(localPath, tempPath, dataKey)
	if err != nil {
		os.Remove(tempPath)
		output.PrintError("Failed to encrypt file: " + err.Error())
		exitFn()
		return "", "", "", "", ""
	}

	sealedKey, err := crypto.SealDataKey(dataKey, pub)
	if err != nil {
		os.Remove(tempPath)
		output.PrintError("Failed to seal data key: " + err.Error())
		exitFn()
		return "", "", "", "", ""
	}

	metaJSON, err := meta.WireJSON()
	if err != nil {
		os.Remove(tempPath)
		output.PrintError("Failed to encode encryption metadata: " + err.Error())
		exitFn()
		return "", "", "", "", ""
	}

	teeKeys := FetchTeeEnclaveKeySet()
	if teeKeys == nil && !TeeScannerDisabledByServer() {
		os.Remove(tempPath)
		if refusal := TeeEnclaveKeyRefusal(); refusal != nil {
			output.PrintError("Security scanner refused: " + refusal.Error())
		} else {
			output.PrintError("Security scanner is not reachable. Please try again shortly.")
		}
		exitFn()
		return "", "", "", "", ""
	}
	teeSealedB64 := ""
	if teeKeys != nil {
		teeSealed, err := crypto.SealDataKey(dataKey, teeKeys)
		if err != nil {
			os.Remove(tempPath)
			output.PrintError("Failed to seal data key to enclave: " + err.Error())
			exitFn()
			return "", "", "", "", ""
		}
		teeSealedB64 = base64.StdEncoding.EncodeToString(teeSealed)
	}

	var hmacHex string
	if nameKey := GetNameKey(exitFn); nameKey != nil {
		if h, err := crypto.ComputePlaintextHmac(meta.PlaintextSHA256, nameKey); err == nil {
			hmacHex = h
		}
	}

	return tempPath, base64.StdEncoding.EncodeToString(sealedKey), base64.StdEncoding.EncodeToString(metaJSON), teeSealedB64, hmacHex
}

func SignEncryptedFile(encryptedPath string, exitFn func()) (sigEdB64, sigMldsaB64, pkEdB64, pkMldsaB64 string) {
	signPub, signPriv := GetSigningKeys(exitFn)
	if signPub == nil || signPriv == nil {
		return "", "", "", ""
	}
	f, err := os.Open(encryptedPath)
	if err != nil {
		output.PrintError("Failed to open encrypted file for signing: " + err.Error())
		exitFn()
		return "", "", "", ""
	}
	defer f.Close()
	sigEd, sigMldsa, err := crypto.SignFileBytes(f, signPriv)
	if err != nil {
		output.PrintError("Failed to sign encrypted file: " + err.Error())
		exitFn()
		return "", "", "", ""
	}
	return base64.StdEncoding.EncodeToString(sigEd),
		base64.StdEncoding.EncodeToString(sigMldsa),
		base64.StdEncoding.EncodeToString(signPub.Ed25519[:]),
		base64.StdEncoding.EncodeToString(signPub.Mldsa)
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
		_ = client.StoreShareDisplayNames(ctx, r.Username, []api.SealedNameEntry{{
			NodeID:            nodeIDHex,
			SealedDisplayName: base64.StdEncoding.EncodeToString(sealed),
		}})
	}
}

func PropagateSubtreeNamesAtPath(ctx context.Context, path string, exitFn func()) {
	if !HasE2EEKeys() {
		return
	}
	client := api.NewClient()
	keysResp, err := client.Execute(ctx, "e2ee_list_keys", map[string]string{
		"source":        path,
		"include_names": "1",
		"include_dirs":  "1",
	})
	if err != nil || !keysResp.Success {
		return
	}
	var keysPayload api.E2EEListKeysPayload
	if err := json.Unmarshal(keysResp.Raw, &keysPayload); err != nil {
		return
	}
	if len(keysPayload.Keys) == 0 {
		return
	}

	_, priv := GetKeyPair(exitFn)
	if priv == nil {
		return
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
		_ = client.StoreShareDisplayNames(ctx, username, names)
	}
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

var suppliedPassword []byte

func SetSuppliedPassword(pw []byte) {
	suppliedPassword = pw
}

func readPasswordPrompt() ([]byte, error) {
	if suppliedPassword != nil {
		pw := suppliedPassword
		suppliedPassword = nil
		return pw, nil
	}
	interactive := term.IsTerminal(int(syscall.Stdin))
	if interactive {
		fmt.Print("Password: ")
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		return pwBytes, err
	}
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return []byte(scanner.Text()), nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}
