package e2ee

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"pigcloud/internal/crypto"
)

type AccountKeys struct {
	Params         map[string]string
	Public         *crypto.PublicKeySet
	Wrapped        *crypto.EncryptedHybridPrivateKey
	SigningPublic  *crypto.SigningPublicKeySet
	SigningWrapped *crypto.EncryptedSigningPrivateKeySet
	RecoveryKey    []byte
}

func NewAccountKeys(password []byte) (*AccountKeys, error) {
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate key pair: %w", err)
	}
	enc, err := crypto.EncryptHybridPrivateKey(priv, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}
	recoveryKey, err := crypto.GenerateRecoveryKey()
	if err != nil {
		return nil, fmt.Errorf("generate recovery key: %w", err)
	}
	recovered, err := crypto.EncryptHybridPrivateKeyWithKey(priv, recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("wrap recovery key: %w", err)
	}

	signPub, signPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate signing key pair: %w", err)
	}
	pdk := crypto.DeriveKey(password, enc.Salt, enc.OpsLimit, enc.MemLimit)
	signEnc, err := crypto.EncryptSigningPrivateKeys(signPriv, pdk)
	for i := range pdk {
		pdk[i] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("wrap signing private keys: %w", err)
	}
	signRecovered, err := crypto.EncryptSigningPrivateKeysWithKey(signPriv, recoveryKey)
	if err != nil {
		return nil, fmt.Errorf("recovery-wrap signing keys: %w", err)
	}

	b64 := base64.StdEncoding.EncodeToString
	params := map[string]string{
		"public_key":                           b64(pub.X25519[:]),
		"encrypted_private_key":                b64(enc.X25519Ciphertext),
		"private_key_nonce":                    b64(enc.X25519Nonce),
		"public_key_kyber":                     b64(pub.Kyber),
		"encrypted_private_key_kyber":          b64(enc.KyberCiphertext),
		"private_key_kyber_nonce":              b64(enc.KyberNonce),
		"kdf_salt":                             b64(enc.Salt),
		"kdf_ops_limit":                        fmt.Sprintf("%d", enc.OpsLimit),
		"kdf_mem_limit":                        fmt.Sprintf("%d", enc.MemLimit),
		"recovery_encrypted_key":               b64(recovered.X25519Ciphertext),
		"recovery_key_nonce":                   b64(recovered.X25519Nonce),
		"recovery_private_key_kyber_encrypted": b64(recovered.KyberCiphertext),
		"recovery_private_key_kyber_nonce":     b64(recovered.KyberNonce),

		"signing_public_key_ed25519":                     b64(signPub.Ed25519[:]),
		"encrypted_signing_private_key_ed25519":          b64(signEnc.Ed25519Ciphertext),
		"signing_private_key_ed25519_nonce":              b64(signEnc.Ed25519Nonce),
		"signing_public_key_mldsa":                       b64(signPub.Mldsa),
		"encrypted_signing_private_key_mldsa":            b64(signEnc.MldsaCiphertext),
		"signing_private_key_mldsa_nonce":                b64(signEnc.MldsaNonce),
		"recovery_signing_private_key_ed25519_encrypted": b64(signRecovered.Ed25519Ciphertext),
		"recovery_signing_private_key_ed25519_nonce":     b64(signRecovered.Ed25519Nonce),
		"recovery_signing_private_key_mldsa_encrypted":   b64(signRecovered.MldsaCiphertext),
		"recovery_signing_private_key_mldsa_nonce":       b64(signRecovered.MldsaNonce),
	}
	sig, err := KeyBundleSig(pub, signPub, signPriv)
	if err != nil {
		return nil, fmt.Errorf("sign the published key bundle: %w", err)
	}
	params["key_bundle_sig"] = sig

	return &AccountKeys{
		Params:         params,
		Public:         pub,
		Wrapped:        enc,
		SigningPublic:  signPub,
		SigningWrapped: signEnc,
		RecoveryKey:    recoveryKey,
	}, nil
}

func KeyBundleSig(pub *crypto.PublicKeySet, signPub *crypto.SigningPublicKeySet, signPriv *crypto.SigningPrivateKeySet) (string, error) {
	sigEd, sigMl, err := crypto.SignKeyBundle(&crypto.KeyBundle{
		X25519:  pub.X25519[:],
		Kyber:   pub.Kyber,
		Ed25519: signPub.Ed25519[:],
		Mldsa:   signPub.Mldsa,
	}, signPriv)
	if err != nil {
		return "", err
	}
	blob, err := json.Marshal(map[string]any{
		"v":      1,
		"sig_ed": base64.StdEncoding.EncodeToString(sigEd),
		"sig_ml": base64.StdEncoding.EncodeToString(sigMl),
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}
