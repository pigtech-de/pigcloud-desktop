package crypto

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	HybridKDFInfo = "pigcloud-hybrid-seal-v2"

	X25519KeySize = 32

	KyberPublicKeySize  = 1184
	KyberSeedSize       = 64
	KyberCiphertextSize = 1088
	KyberSharedSize     = 32

	hybridX25519PKLen = 32
	hybridHeaderSize  = hybridX25519PKLen + KyberCiphertextSize + NonceSize
	hybridMinSize     = hybridHeaderSize + 16
)

type PublicKeySet struct {
	X25519 [32]byte
	Kyber  []byte
}

type PrivateKeySet struct {
	X25519 [32]byte
	Kyber  []byte
}

func (p *PrivateKeySet) Zero() {
	if p == nil {
		return
	}
	for i := range p.X25519 {
		p.X25519[i] = 0
	}
	for i := range p.Kyber {
		p.Kyber[i] = 0
	}
}

func HybridSeal(plaintext []byte, recipient *PublicKeySet) ([]byte, error) {
	if recipient == nil || len(recipient.Kyber) != KyberPublicKeySize {
		return nil, fmt.Errorf("invalid recipient key set")
	}

	var ephPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, fmt.Errorf("ephemeral keygen: %w", err)
	}
	defer func() {
		for i := range ephPriv {
			ephPriv[i] = 0
		}
	}()
	var ephPub [32]byte
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)

	ssX, err := curve25519.X25519(ephPriv[:], recipient.X25519[:])
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	ek, err := mlkem.NewEncapsulationKey768(recipient.Kyber)
	if err != nil {
		return nil, fmt.Errorf("mlkem encapsulation key: %w", err)
	}
	ssK, ctK := ek.Encapsulate()

	wrapKey := deriveHybridKey(ctK, ephPub[:], recipient.X25519[:], ssX, ssK)
	defer func() {
		for i := range wrapKey {
			wrapKey[i] = 0
		}
	}()

	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aead nonce: %w", err)
	}
	aeadCT := aead.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, hybridHeaderSize+len(aeadCT))
	out = append(out, ephPub[:]...)
	out = append(out, ctK...)
	out = append(out, nonce...)
	out = append(out, aeadCT...)
	return out, nil
}

func HybridUnseal(sealed []byte, priv *PrivateKeySet) ([]byte, error) {
	if priv == nil || len(priv.Kyber) != KyberSeedSize {
		return nil, fmt.Errorf("invalid private key set")
	}
	if len(sealed) < hybridMinSize {
		return nil, fmt.Errorf("hybrid blob too short: %d", len(sealed))
	}

	var ephPub [32]byte
	copy(ephPub[:], sealed[:hybridX25519PKLen])
	ctK := sealed[hybridX25519PKLen : hybridX25519PKLen+KyberCiphertextSize]
	nonceOff := hybridX25519PKLen + KyberCiphertextSize
	nonce := sealed[nonceOff : nonceOff+NonceSize]
	aeadCT := sealed[nonceOff+NonceSize:]

	ssX, err := curve25519.X25519(priv.X25519[:], ephPub[:])
	if err != nil {
		return nil, fmt.Errorf("x25519 ecdh: %w", err)
	}

	dk, err := mlkem.NewDecapsulationKey768(priv.Kyber)
	if err != nil {
		return nil, fmt.Errorf("mlkem decapsulation key: %w", err)
	}
	ssK, err := dk.Decapsulate(ctK)
	if err != nil {
		return nil, fmt.Errorf("mlkem decap: %w", err)
	}

	var recipientStaticPub [32]byte
	curve25519.ScalarBaseMult(&recipientStaticPub, &priv.X25519)

	wrapKey := deriveHybridKey(ctK, ephPub[:], recipientStaticPub[:], ssX, ssK)
	defer func() {
		for i := range wrapKey {
			wrapKey[i] = 0
		}
	}()

	aead, err := chacha20poly1305.NewX(wrapKey)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, aeadCT, nil)
	if err != nil {
		return nil, fmt.Errorf("aead open (corrupted blob or wrong key): %w", err)
	}
	return plaintext, nil
}

func deriveHybridKey(mlkemCT, ephX25519PK, recipientStaticPK, ssX, ssK []byte) []byte {
	salt := make([]byte, 0, len(mlkemCT)+len(ephX25519PK)+len(recipientStaticPK))
	salt = append(salt, mlkemCT...)
	salt = append(salt, ephX25519PK...)
	salt = append(salt, recipientStaticPK...)

	ikm := make([]byte, 0, len(ssX)+len(ssK))
	ikm = append(ikm, ssX...)
	ikm = append(ikm, ssK...)

	h := hkdf.New(sha256.New, ikm, salt, []byte(HybridKDFInfo))
	out := make([]byte, KeySize)
	if _, err := io.ReadFull(h, out); err != nil {
		panic(fmt.Errorf("hkdf: %w", err))
	}
	return out
}

func GenerateHybridKeyPair() (*PublicKeySet, *PrivateKeySet, error) {
	var x25519Priv [32]byte
	if _, err := io.ReadFull(rand.Reader, x25519Priv[:]); err != nil {
		return nil, nil, fmt.Errorf("x25519 keygen: %w", err)
	}
	var x25519Pub [32]byte
	curve25519.ScalarBaseMult(&x25519Pub, &x25519Priv)

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem keygen: %w", err)
	}
	seed := dk.Bytes()
	if len(seed) != KyberSeedSize {
		return nil, nil, fmt.Errorf("unexpected mlkem seed length: %d", len(seed))
	}
	ekBytes := dk.EncapsulationKey().Bytes()
	if len(ekBytes) != KyberPublicKeySize {
		return nil, nil, fmt.Errorf("unexpected mlkem encapsulation key length: %d", len(ekBytes))
	}

	pub := &PublicKeySet{X25519: x25519Pub, Kyber: ekBytes}
	priv := &PrivateKeySet{X25519: x25519Priv, Kyber: seed}
	return pub, priv, nil
}

type EncryptedHybridPrivateKey struct {
	X25519Ciphertext []byte
	X25519Nonce      []byte
	KyberCiphertext  []byte
	KyberNonce       []byte
	Salt             []byte
	OpsLimit         uint32
	MemLimit         uint32
}

func EncryptHybridPrivateKey(priv *PrivateKeySet, password []byte) (*EncryptedHybridPrivateKey, error) {
	if priv == nil || len(priv.Kyber) != KyberSeedSize {
		return nil, fmt.Errorf("invalid private key set")
	}

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	pdk := DeriveKey(password, salt, KDFOpsLimit, KDFMemLimitBytes)
	defer func() {
		for i := range pdk {
			pdk[i] = 0
		}
	}()
	xCT, xNonce, kCT, kNonce, err := wrapWithKey(pdk, priv)
	if err != nil {
		return nil, err
	}

	return &EncryptedHybridPrivateKey{
		X25519Ciphertext: xCT, X25519Nonce: xNonce,
		KyberCiphertext: kCT, KyberNonce: kNonce,
		Salt: salt, OpsLimit: KDFOpsLimit, MemLimit: KDFMemLimitBytes,
	}, nil
}

func wrapWithKey(key []byte, priv *PrivateKeySet) (xCT, xNonce, kCT, kNonce []byte, err error) {
	aead, aeadErr := chacha20poly1305.NewX(key)
	if aeadErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("aead init: %w", aeadErr)
	}

	xNonce = make([]byte, NonceSize)
	if _, nonceErr := io.ReadFull(rand.Reader, xNonce); nonceErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("x25519 nonce: %w", nonceErr)
	}
	xCT = aead.Seal(nil, xNonce, priv.X25519[:], nil)

	kNonce = make([]byte, NonceSize)
	if _, nonceErr := io.ReadFull(rand.Reader, kNonce); nonceErr != nil {
		return nil, nil, nil, nil, fmt.Errorf("kyber nonce: %w", nonceErr)
	}
	kCT = aead.Seal(nil, kNonce, priv.Kyber, nil)

	return xCT, xNonce, kCT, kNonce, nil
}

func DecryptHybridPrivateKey(enc *EncryptedHybridPrivateKey, password []byte) (*PrivateKeySet, error) {
	pdk := DeriveKey(password, enc.Salt, enc.OpsLimit, enc.MemLimit)
	defer func() {
		for i := range pdk {
			pdk[i] = 0
		}
	}()
	return DecryptHybridPrivateKeyWithRawKey(enc, pdk)
}

func DecryptHybridPrivateKeyWithRawKey(enc *EncryptedHybridPrivateKey, pdk []byte) (*PrivateKeySet, error) {
	if len(pdk) != KeySize {
		return nil, fmt.Errorf("pdk must be %d bytes", KeySize)
	}
	if len(enc.X25519Nonce) != NonceSize {
		return nil, fmt.Errorf("x25519 nonce must be %d bytes, got %d", NonceSize, len(enc.X25519Nonce))
	}
	if len(enc.KyberNonce) != NonceSize {
		return nil, fmt.Errorf("kyber nonce must be %d bytes, got %d", NonceSize, len(enc.KyberNonce))
	}
	aead, err := chacha20poly1305.NewX(pdk)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	xPlain, err := aead.Open(nil, enc.X25519Nonce, enc.X25519Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong key or corrupted x25519 key: %w", err)
	}
	defer func() {
		for i := range xPlain {
			xPlain[i] = 0
		}
	}()
	kPlain, err := aead.Open(nil, enc.KyberNonce, enc.KyberCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("wrong key or corrupted kyber seed: %w", err)
	}
	if len(xPlain) != 32 {
		return nil, fmt.Errorf("unexpected x25519 sk length: %d", len(xPlain))
	}
	if len(kPlain) != KyberSeedSize {
		return nil, fmt.Errorf("unexpected kyber seed length: %d", len(kPlain))
	}
	var x [32]byte
	copy(x[:], xPlain)
	return &PrivateKeySet{X25519: x, Kyber: kPlain}, nil
}

type RecoveryWrappedHybridKey struct {
	X25519Ciphertext []byte
	X25519Nonce      []byte
	KyberCiphertext  []byte
	KyberNonce       []byte
}

func EncryptHybridPrivateKeyWithKey(priv *PrivateKeySet, key []byte) (*RecoveryWrappedHybridKey, error) {
	if priv == nil || len(priv.Kyber) != KyberSeedSize {
		return nil, fmt.Errorf("invalid private key set")
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("recovery key must be %d bytes", KeySize)
	}
	xCT, xNonce, kCT, kNonce, err := wrapWithKey(key, priv)
	if err != nil {
		return nil, err
	}

	return &RecoveryWrappedHybridKey{
		X25519Ciphertext: xCT, X25519Nonce: xNonce,
		KyberCiphertext: kCT, KyberNonce: kNonce,
	}, nil
}
