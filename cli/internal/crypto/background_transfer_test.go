package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func packBackground(t *testing.T) ([]byte, []byte, []byte, *PublicKeySet, *SigningPublicKeySet) {
	t.Helper()
	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("hybrid keygen: %v", err)
	}
	signPub, signPriv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("signing keygen: %v", err)
	}
	nameKey, err := DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("name key: %v", err)
	}
	parentKey, err := DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("parent key: %v", err)
	}

	payload := make([]byte, 0, BackgroundKeyTransferSize)
	payload = append(payload, BackgroundKeyTransferVersion)
	payload = append(payload, nameKey...)
	payload = append(payload, parentKey...)
	payload = append(payload, signPriv.Ed25519...)
	payload = append(payload, signPriv.Mldsa...)
	payload = append(payload, pub.X25519[:]...)
	payload = append(payload, pub.Kyber...)
	return payload, nameKey, parentKey, pub, signPub
}

func TestParseBackgroundKeyTransferRoundTrip(t *testing.T) {
	payload, nameKey, parentKey, pub, signPub := packBackground(t)
	if len(payload) != BackgroundKeyTransferSize {
		t.Fatalf("packed %d bytes, want %d", len(payload), BackgroundKeyTransferSize)
	}

	material, err := ParseBackgroundKeyTransfer(payload)
	if err != nil {
		t.Fatalf("ParseBackgroundKeyTransfer: %v", err)
	}
	if !bytes.Equal(material.NameKey, nameKey) {
		t.Error("name key did not survive the transfer")
	}
	if !bytes.Equal(material.ParentKey, parentKey) {
		t.Error("parent key did not survive the transfer")
	}
	if material.Pub.X25519 != pub.X25519 || !bytes.Equal(material.Pub.Kyber, pub.Kyber) {
		t.Error("encryption public set did not survive the transfer")
	}
	if material.SigningPub.Ed25519 != signPub.Ed25519 || !bytes.Equal(material.SigningPub.Mldsa, signPub.Mldsa) {
		t.Error("signing public set was not derived from the transferred private half")
	}
}

func TestParseBackgroundKeyTransferRefusesDeviceLoginPayload(t *testing.T) {
	payload := make([]byte, DeviceKeyTransferSize)
	payload[0] = DeviceKeyTransferVersion

	_, err := ParseBackgroundKeyTransfer(payload)
	if err == nil {
		t.Fatal("a device-login payload was accepted into the background store")
	}
	if !strings.Contains(err.Error(), "device-login payload") {
		t.Errorf("refusal must name the device-login payload, got %q", err)
	}
}

func TestParseBackgroundKeyTransferRefusesWrongVersionAndLength(t *testing.T) {
	payload, _, _, _, _ := packBackground(t)

	short := payload[:len(payload)-1]
	if _, err := ParseBackgroundKeyTransfer(short); err == nil {
		t.Error("a truncated payload was accepted")
	}

	wrong := bytes.Clone(payload)
	wrong[0] = 9
	if _, err := ParseBackgroundKeyTransfer(wrong); err == nil {
		t.Error("an unknown version was accepted")
	}
}

func TestBackgroundKeyMaterialZero(t *testing.T) {
	payload, _, _, _, _ := packBackground(t)
	material, err := ParseBackgroundKeyTransfer(payload)
	if err != nil {
		t.Fatalf("ParseBackgroundKeyTransfer: %v", err)
	}
	material.Zero()

	if !bytes.Equal(material.NameKey, make([]byte, NameKeySize)) {
		t.Error("Zero left the name key in memory")
	}
	if !bytes.Equal(material.ParentKey, make([]byte, NameKeySize)) {
		t.Error("Zero left the parent key in memory")
	}
	if !bytes.Equal(material.SigningPriv.Mldsa, make([]byte, Mldsa44SKSize)) {
		t.Error("Zero left the ML-DSA secret in memory")
	}
}
