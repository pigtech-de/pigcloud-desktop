package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	SignatureDomain    = "pigcloud-file-signature-v1"
	TEESignatureDomain = "pigcloud-tee-file-signature-v1"

	Ed25519SigSize = 64
	Ed25519PKSize  = 32
	Ed25519SKSize  = 64

	Mldsa44SigSize = mldsa44.SignatureSize
	Mldsa44PKSize  = mldsa44.PublicKeySize
	Mldsa44SKSize  = mldsa44.PrivateKeySize
)

type SigningPublicKeySet struct {
	Ed25519 [Ed25519PKSize]byte
	Mldsa   []byte
}

type SigningPrivateKeySet struct {
	Ed25519 ed25519.PrivateKey
	Mldsa   []byte
}

func (s *SigningPrivateKeySet) Zero() {
	if s == nil {
		return
	}
	for i := range s.Ed25519 {
		s.Ed25519[i] = 0
	}
	for i := range s.Mldsa {
		s.Mldsa[i] = 0
	}
}

func GenerateSigningKeyPair() (*SigningPublicKeySet, *SigningPrivateKeySet, error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	mlPub, mlPriv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa44 keygen: %w", err)
	}

	mlPubBytes, err := mlPub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa44 pub marshal: %w", err)
	}
	mlPrivBytes, err := mlPriv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("mldsa44 priv marshal: %w", err)
	}

	pub := &SigningPublicKeySet{Mldsa: mlPubBytes}
	copy(pub.Ed25519[:], edPub)
	priv := &SigningPrivateKeySet{Ed25519: edPriv, Mldsa: mlPrivBytes}
	return pub, priv, nil
}

type EncryptedSigningPrivateKeySet struct {
	Ed25519Ciphertext []byte
	Ed25519Nonce      []byte
	MldsaCiphertext   []byte
	MldsaNonce        []byte
}

func EncryptSigningPrivateKeys(priv *SigningPrivateKeySet, pdk []byte) (*EncryptedSigningPrivateKeySet, error) {
	if priv == nil || len(priv.Ed25519) != Ed25519SKSize || len(priv.Mldsa) != Mldsa44SKSize {
		return nil, fmt.Errorf("invalid signing private key set")
	}
	if len(pdk) != KeySize {
		return nil, fmt.Errorf("pdk must be %d bytes", KeySize)
	}
	aead, err := chacha20poly1305.NewX(pdk)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}

	edNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, edNonce); err != nil {
		return nil, fmt.Errorf("ed25519 nonce: %w", err)
	}
	edCT := aead.Seal(nil, edNonce, priv.Ed25519, nil)

	mlNonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, mlNonce); err != nil {
		return nil, fmt.Errorf("mldsa nonce: %w", err)
	}
	mlCT := aead.Seal(nil, mlNonce, priv.Mldsa, nil)

	return &EncryptedSigningPrivateKeySet{
		Ed25519Ciphertext: edCT,
		Ed25519Nonce:      edNonce,
		MldsaCiphertext:   mlCT,
		MldsaNonce:        mlNonce,
	}, nil
}

func DecryptSigningPrivateKeys(enc *EncryptedSigningPrivateKeySet, pdk []byte) (*SigningPrivateKeySet, error) {
	if enc == nil {
		return nil, fmt.Errorf("encrypted signing key set is nil")
	}
	if len(pdk) != KeySize {
		return nil, fmt.Errorf("pdk must be %d bytes", KeySize)
	}
	if len(enc.Ed25519Nonce) != NonceSize {
		return nil, fmt.Errorf("ed25519 nonce must be %d bytes, got %d", NonceSize, len(enc.Ed25519Nonce))
	}
	if len(enc.MldsaNonce) != NonceSize {
		return nil, fmt.Errorf("mldsa nonce must be %d bytes, got %d", NonceSize, len(enc.MldsaNonce))
	}
	aead, err := chacha20poly1305.NewX(pdk)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	edPlain, err := aead.Open(nil, enc.Ed25519Nonce, enc.Ed25519Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong key or corrupted ed25519 sk: %w", err)
	}
	if len(edPlain) != Ed25519SKSize {
		for i := range edPlain {
			edPlain[i] = 0
		}
		return nil, fmt.Errorf("unexpected ed25519 sk length: %d", len(edPlain))
	}
	mlPlain, err := aead.Open(nil, enc.MldsaNonce, enc.MldsaCiphertext, nil)
	if err != nil {
		for i := range edPlain {
			edPlain[i] = 0
		}
		return nil, fmt.Errorf("wrong key or corrupted mldsa sk: %w", err)
	}
	if len(mlPlain) != Mldsa44SKSize {
		for i := range edPlain {
			edPlain[i] = 0
		}
		for i := range mlPlain {
			mlPlain[i] = 0
		}
		return nil, fmt.Errorf("unexpected mldsa sk length: %d", len(mlPlain))
	}
	return &SigningPrivateKeySet{Ed25519: ed25519.PrivateKey(edPlain), Mldsa: mlPlain}, nil
}

func EncryptSigningPrivateKeysWithKey(priv *SigningPrivateKeySet, key []byte) (*EncryptedSigningPrivateKeySet, error) {
	return EncryptSigningPrivateKeys(priv, key)
}

func signingInput(domain string, ciphertextSha256 []byte) []byte {
	if len(ciphertextSha256) != sha256.Size {
		panic(fmt.Sprintf("ciphertext sha256 must be %d bytes, got %d", sha256.Size, len(ciphertextSha256)))
	}
	d := []byte(domain)
	out := make([]byte, 0, len(d)+len(ciphertextSha256))
	out = append(out, d...)
	out = append(out, ciphertextSha256...)
	return out
}

func hashCiphertext(r io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, fmt.Errorf("hash ciphertext: %w", err)
	}
	return h.Sum(nil), nil
}

func SignFileBytes(r io.Reader, priv *SigningPrivateKeySet) ([]byte, []byte, error) {
	if priv == nil || len(priv.Ed25519) != Ed25519SKSize || len(priv.Mldsa) != Mldsa44SKSize {
		return nil, nil, fmt.Errorf("invalid signing private key set")
	}
	digest, err := hashCiphertext(r)
	if err != nil {
		return nil, nil, err
	}
	input := signingInput(SignatureDomain, digest)

	edSig := ed25519.Sign(priv.Ed25519, input)

	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(priv.Mldsa); err != nil {
		return nil, nil, fmt.Errorf("mldsa44 priv unmarshal: %w", err)
	}
	mlSig := make([]byte, Mldsa44SigSize)
	if err := mldsa44.SignTo(&mlPriv, input, nil, false, mlSig); err != nil {
		return nil, nil, fmt.Errorf("mldsa44 sign: %w", err)
	}

	return edSig, mlSig, nil
}

func VerifyFileSignatures(r io.Reader, sigEd, sigMldsa []byte, pub *SigningPublicKeySet) error {
	return verifySignaturePair(r, SignatureDomain, sigEd, sigMldsa, pub, "file_signature")
}

func VerifyTEEFileSignatures(r io.Reader, sigEd, sigMldsa []byte, teePub *SigningPublicKeySet) error {
	return verifySignaturePair(r, TEESignatureDomain, sigEd, sigMldsa, teePub, "tee_file_signature")
}

func verifySignaturePair(r io.Reader, domain string, sigEd, sigMldsa []byte, pub *SigningPublicKeySet, errPrefix string) error {
	if len(sigEd) != Ed25519SigSize || len(sigMldsa) != Mldsa44SigSize {
		return fmt.Errorf("%s_missing", errPrefix)
	}
	if pub == nil || len(pub.Mldsa) != Mldsa44PKSize {
		return fmt.Errorf("%s_public_key_missing", errPrefix)
	}
	digest, err := hashCiphertext(r)
	if err != nil {
		return err
	}
	input := signingInput(domain, digest)

	if !ed25519.Verify(ed25519.PublicKey(pub.Ed25519[:]), input, sigEd) {
		return fmt.Errorf("%s_invalid_ed25519", errPrefix)
	}

	var mlPub mldsa44.PublicKey
	if err := mlPub.UnmarshalBinary(pub.Mldsa); err != nil {
		return fmt.Errorf("mldsa44 pub unmarshal: %w", err)
	}
	if !mldsa44.Verify(&mlPub, input, nil, sigMldsa) {
		return fmt.Errorf("%s_invalid_mldsa", errPrefix)
	}
	return nil
}

const KeyBundleDomain = "pigcloud-key-bundle-v1"

type KeyBundle struct {
	X25519  []byte
	Kyber   []byte
	Ed25519 []byte
	Mldsa   []byte
}

func keyBundleInput(b *KeyBundle) ([]byte, error) {
	fields := []struct {
		raw  []byte
		size int
	}{
		{b.X25519, 32},
		{b.Kyber, KyberPublicKeySize},
		{b.Ed25519, Ed25519PKSize},
		{b.Mldsa, Mldsa44PKSize},
	}
	input := []byte(KeyBundleDomain)
	for _, f := range fields {
		if len(f.raw) != f.size {
			return nil, fmt.Errorf("key bundle field size mismatch")
		}
		input = append(input, f.raw...)
	}
	return input, nil
}

func SignKeyBundle(b *KeyBundle, priv *SigningPrivateKeySet) (sigEd, sigMldsa []byte, err error) {
	input, err := keyBundleInput(b)
	if err != nil {
		return nil, nil, err
	}
	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(priv.Mldsa); err != nil {
		return nil, nil, fmt.Errorf("mldsa44 priv unmarshal: %w", err)
	}
	sigMldsa = make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(&mlPriv, input, nil, false, sigMldsa); err != nil {
		return nil, nil, fmt.Errorf("mldsa44 sign: %w", err)
	}
	return ed25519.Sign(priv.Ed25519, input), sigMldsa, nil
}

func VerifyKeyBundle(b *KeyBundle, sigEd, sigMldsa []byte) bool {
	input, err := keyBundleInput(b)
	if err != nil || len(sigEd) != Ed25519SigSize || len(sigMldsa) != Mldsa44SigSize {
		return false
	}
	if !ed25519.Verify(ed25519.PublicKey(b.Ed25519), input, sigEd) {
		return false
	}
	var mlPub mldsa44.PublicKey
	if mlPub.UnmarshalBinary(b.Mldsa) != nil {
		return false
	}
	return mldsa44.Verify(&mlPub, input, nil, sigMldsa)
}
