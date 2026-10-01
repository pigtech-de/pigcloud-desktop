package crypto

import (
	"bytes"
	"testing"
)

func parentRefFixture(t *testing.T) (parentKey []byte, pub *PublicKeySet, priv *PrivateKeySet, parentID, nodeID []byte) {
	t.Helper()
	pub, priv = mustGenKeyPair(t)
	key, err := DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}
	parentID = bytes.Repeat([]byte{0xAB}, 16)
	nodeID = bytes.Repeat([]byte{0xCD}, 16)
	return key, pub, priv, parentID, nodeID
}

func TestParentRefOwnRoundTrip(t *testing.T) {
	parentKey, _, _, parentID, nodeID := parentRefFixture(t)
	sealed, err := SealParentRef(parentID, nodeID, parentKey)
	if err != nil {
		t.Fatalf("SealParentRef: %v", err)
	}
	if len(sealed) != 1+24+16+16 {
		t.Fatalf("own-write blob is %d bytes, want 57", len(sealed))
	}
	got, err := OpenParentRef(sealed, nodeID, parentKey, nil)
	if err != nil {
		t.Fatalf("OpenParentRef: %v", err)
	}
	if !bytes.Equal(got, parentID) {
		t.Fatalf("parent mismatch: got %x", got)
	}
}

func TestParentRefRootSentinel(t *testing.T) {
	parentKey, pub, priv, _, nodeID := parentRefFixture(t)
	for _, seal := range []func() ([]byte, error){
		func() ([]byte, error) { return SealParentRef(nil, nodeID, parentKey) },
		func() ([]byte, error) { return SealParentRefForRecipient(nil, nodeID, pub) },
	} {
		sealed, err := seal()
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		got, err := OpenParentRef(sealed, nodeID, parentKey, priv)
		if err != nil {
			t.Fatalf("OpenParentRef: %v", err)
		}
		if got != nil {
			t.Fatalf("root sentinel must open to nil, got %x", got)
		}
	}
}

func TestParentRefForeignRoundTrip(t *testing.T) {
	parentKey, pub, priv, parentID, nodeID := parentRefFixture(t)
	sealed, err := SealParentRefForRecipient(parentID, nodeID, pub)
	if err != nil {
		t.Fatalf("SealParentRefForRecipient: %v", err)
	}
	got, err := OpenParentRef(sealed, nodeID, parentKey, priv)
	if err != nil {
		t.Fatalf("OpenParentRef: %v", err)
	}
	if !bytes.Equal(got, parentID) {
		t.Fatalf("parent mismatch: got %x", got)
	}
}

func TestParentRefRejectsWrongNode(t *testing.T) {
	parentKey, pub, priv, parentID, nodeID := parentRefFixture(t)
	otherNode := bytes.Repeat([]byte{0xEE}, 16)

	own, err := SealParentRef(parentID, nodeID, parentKey)
	if err != nil {
		t.Fatalf("SealParentRef: %v", err)
	}
	if _, err := OpenParentRef(own, otherNode, parentKey, nil); err == nil {
		t.Fatal("own-write blob must not open under another node id (AAD)")
	}

	foreign, err := SealParentRefForRecipient(parentID, nodeID, pub)
	if err != nil {
		t.Fatalf("SealParentRefForRecipient: %v", err)
	}
	if _, err := OpenParentRef(foreign, otherNode, parentKey, priv); err == nil {
		t.Fatal("foreign blob must not open under another node id (embedded id)")
	}
}

func TestParentRefRejectsTamperAndUnknownVersion(t *testing.T) {
	parentKey, _, priv, parentID, nodeID := parentRefFixture(t)
	sealed, err := SealParentRef(parentID, nodeID, parentKey)
	if err != nil {
		t.Fatalf("SealParentRef: %v", err)
	}
	flipped := append([]byte(nil), sealed...)
	flipped[len(flipped)-1] ^= 0x01
	if _, err := OpenParentRef(flipped, nodeID, parentKey, nil); err == nil {
		t.Fatal("bit-flipped blob must not open")
	}
	unknown := append([]byte(nil), sealed...)
	unknown[0] = 0x03
	if _, err := OpenParentRef(unknown, nodeID, parentKey, priv); err == nil {
		t.Fatal("unknown version must error, not fall through")
	}
}

func TestParentRefSiblingsUncorrelatable(t *testing.T) {
	parentKey, _, _, parentID, _ := parentRefFixture(t)
	a, err := SealParentRef(parentID, bytes.Repeat([]byte{0x01}, 16), parentKey)
	if err != nil {
		t.Fatalf("SealParentRef: %v", err)
	}
	b, err := SealParentRef(parentID, bytes.Repeat([]byte{0x02}, 16), parentKey)
	if err != nil {
		t.Fatalf("SealParentRef: %v", err)
	}
	if bytes.Equal(a[1:25], b[1:25]) {
		t.Fatal("two seals reused a nonce")
	}
	if bytes.Equal(a, b) {
		t.Fatal("siblings under one parent must not produce equal blobs")
	}
}

func TestDeriveParentKeyDistinctFromNameKey(t *testing.T) {
	_, priv := func() (*PublicKeySet, *PrivateKeySet) { pk, sk := mustGenKeyPair(t); return pk, sk }()
	defer priv.Zero()
	parentKey, err := DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}
	nameKey, err := DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}
	if bytes.Equal(parentKey, nameKey) {
		t.Fatal("parent key must differ from name key (distinct contexts)")
	}
	again, err := DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}
	if !bytes.Equal(parentKey, again) {
		t.Fatal("parent key derivation must be deterministic")
	}
}
