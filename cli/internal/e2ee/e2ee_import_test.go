package e2ee

import (
	"bytes"
	"testing"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func (f *keyFixture) deviceTransferPayload(t *testing.T) []byte {
	t.Helper()
	payload := make([]byte, 0, crypto.DeviceKeyTransferSize)
	payload = append(payload, crypto.DeviceKeyTransferVersion)
	payload = append(payload, f.priv.X25519[:]...)
	payload = append(payload, f.priv.Kyber...)
	payload = append(payload, f.signPriv.Ed25519...)
	payload = append(payload, f.signPriv.Mldsa...)
	if len(payload) != crypto.DeviceKeyTransferSize {
		t.Fatalf("packed payload is %d bytes, want %d", len(payload), crypto.DeviceKeyTransferSize)
	}
	return payload
}

func TestImportDeviceTransferredKeysPersistsUnlockableDeviceWrappedKeys(t *testing.T) {
	isolateKeyEnv(t)
	config.SetSecretStore(config.NewMemorySecretStore())
	t.Cleanup(func() { config.SetSecretStore(nil) })

	f := newKeyFixture(t)
	ephPub, ephPriv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("ephemeral keygen: %v", err)
	}

	sealed, err := crypto.HybridSeal(f.deviceTransferPayload(t), ephPub)
	if err != nil {
		t.Fatalf("seal transfer payload: %v", err)
	}
	if err := ImportDeviceTransferredKeys(b64(sealed), ephPriv); err != nil {
		t.Fatalf("import of a well-formed transfer failed: %v", err)
	}

	if defaultSession.pub == nil || defaultSession.pub.X25519 != f.pub.X25519 || !bytes.Equal(defaultSession.pub.Kyber, f.pub.Kyber) {
		t.Fatal("imported encryption public key does not match the source account")
	}
	if defaultSession.priv == nil || defaultSession.priv.X25519 != f.priv.X25519 || !bytes.Equal(defaultSession.priv.Kyber, f.priv.Kyber) {
		t.Fatal("imported encryption private key does not match the source account")
	}
	if defaultSession.signingPub == nil || defaultSession.signingPub.Ed25519 != f.signPub.Ed25519 || !bytes.Equal(defaultSession.signingPub.Mldsa, f.signPub.Mldsa) {
		t.Fatal("imported signing public key does not match the source account")
	}
	if defaultSession.signingPriv == nil {
		t.Fatal("import left the signing private cache empty")
	}
	msg := randKey(t, 256)
	sigEd, sigMl, err := crypto.SignFileBytes(bytes.NewReader(msg), defaultSession.signingPriv)
	if err != nil {
		t.Fatalf("sign with imported key: %v", err)
	}
	if err := crypto.VerifyFileSignatures(bytes.NewReader(msg), sigEd, sigMl, defaultSession.signingPub); err != nil {
		t.Fatalf("imported signing pair does not verify its own signature: %v", err)
	}

	if !config.IsDeviceWrapped() {
		t.Fatal("import did not flip the config to device-wrapped storage")
	}
	dk, ok := config.LoadE2EEDeviceKey()
	if !ok || len(dk) != 32 {
		t.Fatalf("device key not persisted to the keychain (ok=%v len=%d)", ok, len(dk))
	}

	resetKeyCaches()
	SetSuppliedPassword([]byte("a password the device path must never read"))
	pub, priv := getKeyPair(func() { t.Fatal("device-wrapped unlock signalled failure") })
	if pub == nil || priv == nil {
		t.Fatal("persisted device-wrapped keys did not unlock")
	}
	if priv.X25519 != f.priv.X25519 || !bytes.Equal(priv.Kyber, f.priv.Kyber) {
		t.Fatal("device-wrapped unlock returned the wrong private key")
	}
	if defaultSession.supplied == nil {
		t.Error("device-wrapped unlock consumed a password; it must not")
	}
}

func TestImportDeviceTransferredKeysRejectsBadInputWithoutTouchingState(t *testing.T) {
	f := newKeyFixture(t)
	ephPub, ephPriv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("ephemeral keygen: %v", err)
	}
	_, otherPriv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("other keygen: %v", err)
	}
	validPayload := f.deviceTransferPayload(t)

	sealedTo := func(payload []byte, pub *crypto.PublicKeySet) string {
		t.Helper()
		s, err := crypto.HybridSeal(payload, pub)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		return b64(s)
	}

	wrongVersion := append([]byte(nil), validPayload...)
	wrongVersion[0] = crypto.DeviceKeyTransferVersion + 1

	cases := []struct {
		name    string
		sealed  string
		ephPriv *crypto.PrivateKeySet
	}{
		{"not base64", "!!!not base64!!!", ephPriv},
		{"garbage blob", b64(randKey(t, 128)), ephPriv},
		{"sealed to a different ephemeral key", sealedTo(validPayload, ephPub), otherPriv},
		{"payload too short", sealedTo(validPayload[:64], ephPub), ephPriv},
		{"unsupported version", sealedTo(wrongVersion, ephPub), ephPriv},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			if err := ImportDeviceTransferredKeys(tc.sealed, tc.ephPriv); err == nil {
				t.Fatal("a malformed transfer was accepted")
			}
			if defaultSession.pub != nil || defaultSession.priv != nil || defaultSession.signingPub != nil || defaultSession.signingPriv != nil {
				t.Fatal("a rejected import mutated the key caches")
			}
			if config.IsDeviceWrapped() {
				t.Fatal("a rejected import flipped storage to device-wrapped")
			}
		})
	}
}

func TestImportDeviceTransferredKeysFailsClosedWithoutAKeychain(t *testing.T) {
	isolateKeyEnv(t)
	config.SetSecretStore(nil)

	f := newKeyFixture(t)
	ephPub, ephPriv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("ephemeral keygen: %v", err)
	}
	sealed, err := crypto.HybridSeal(f.deviceTransferPayload(t), ephPub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	if err := ImportDeviceTransferredKeys(b64(sealed), ephPriv); err == nil {
		t.Fatal("import succeeded with no keychain to hold the device key")
	}
	if defaultSession.pub != nil || defaultSession.priv != nil || defaultSession.signingPub != nil || defaultSession.signingPriv != nil {
		t.Fatal("a keychain-less import left key material in the caches")
	}
	if config.IsDeviceWrapped() {
		t.Fatal("a keychain-less import still flipped storage to device-wrapped")
	}
}
