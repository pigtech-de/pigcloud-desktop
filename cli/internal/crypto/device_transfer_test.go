package crypto

import (
	"bytes"
	"testing"
)

func buildTransferPayload(priv *PrivateKeySet, signPriv *SigningPrivateKeySet) []byte {
	payload := make([]byte, 0, DeviceKeyTransferSize)
	payload = append(payload, DeviceKeyTransferVersion)
	payload = append(payload, priv.X25519[:]...)
	payload = append(payload, priv.Kyber...)
	payload = append(payload, signPriv.Ed25519...)
	payload = append(payload, signPriv.Mldsa...)
	return payload
}

func TestDeviceKeyTransferRoundTrip(t *testing.T) {
	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	payload := buildTransferPayload(priv, signPriv)
	if len(payload) != DeviceKeyTransferSize {
		t.Fatalf("payload size %d != %d", len(payload), DeviceKeyTransferSize)
	}

	gotPriv, gotSign, err := ParseDeviceKeyTransfer(payload)
	if err != nil {
		t.Fatal(err)
	}
	if gotPriv.X25519 != priv.X25519 || !bytes.Equal(gotPriv.Kyber, priv.Kyber) {
		t.Fatal("encryption private mismatch")
	}
	if !bytes.Equal(gotSign.Ed25519, signPriv.Ed25519) || !bytes.Equal(gotSign.Mldsa, signPriv.Mldsa) {
		t.Fatal("signing private mismatch")
	}

	gotPub, err := DeriveHybridPublic(gotPriv)
	if err != nil {
		t.Fatal(err)
	}
	if gotPub.X25519 != pub.X25519 || !bytes.Equal(gotPub.Kyber, pub.Kyber) {
		t.Fatal("derived hybrid public mismatch")
	}
	gotSignPub, err := DeriveSigningPublic(gotSign)
	if err != nil {
		t.Fatal(err)
	}
	if gotSignPub.Ed25519 != signPub.Ed25519 || !bytes.Equal(gotSignPub.Mldsa, signPub.Mldsa) {
		t.Fatal("derived signing public mismatch")
	}
}

func TestDeviceKeyTransferSealUnseal(t *testing.T) {
	ephPub, ephPriv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, signPriv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := HybridSeal(buildTransferPayload(priv, signPriv), ephPub)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := HybridUnseal(sealed, ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	gotPriv, gotSign, err := ParseDeviceKeyTransfer(opened)
	if err != nil {
		t.Fatal(err)
	}
	if gotPriv.X25519 != priv.X25519 || !bytes.Equal(gotSign.Mldsa, signPriv.Mldsa) {
		t.Fatal("round-trip mismatch")
	}
}

func TestParseDeviceKeyTransferRejectsBadInput(t *testing.T) {
	if _, _, err := ParseDeviceKeyTransfer(make([]byte, 10)); err == nil {
		t.Fatal("expected error on short payload")
	}
	bad := make([]byte, DeviceKeyTransferSize)
	bad[0] = 2
	if _, _, err := ParseDeviceKeyTransfer(bad); err == nil {
		t.Fatal("expected error on bad version")
	}
}
