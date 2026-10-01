package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestPadDisplayNameBucketBoundaries(t *testing.T) {
	cases := []struct {
		nameLen int
		want    int
	}{
		{0, 64}, {1, 64}, {60, 64},
		{61, 128}, {124, 128},
		{125, 256}, {252, 256},
		{253, 512}, {508, 512},
		{509, 888}, {884, 888},
	}
	for _, c := range cases {
		padded := padDisplayName(bytes.Repeat([]byte{'a'}, c.nameLen))
		if len(padded) != c.want {
			t.Errorf("nameLen %d: padded to %d bytes, want %d", c.nameLen, len(padded), c.want)
		}
	}
}

func TestPadDisplayNameOversizePassthrough(t *testing.T) {
	name := bytes.Repeat([]byte{'a'}, 885)
	if padded := padDisplayName(name); !bytes.Equal(padded, name) {
		t.Fatal("name past the top bucket must pass through unpadded")
	}
}

func TestPadDisplayNameOversizeMarkerLeadGetsEnvelope(t *testing.T) {
	name := append([]byte{0xff}, bytes.Repeat([]byte{'a'}, 884)...)
	padded := padDisplayName(name)
	if len(padded) != displayNamePadHeader+len(name) {
		t.Fatalf("0xFF-lead oversize name must get an exact-size envelope, got %d bytes", len(padded))
	}
	got, err := unpadDisplayName(padded)
	if err != nil {
		t.Fatalf("unpadDisplayName: %v", err)
	}
	if !bytes.Equal(got, name) {
		t.Fatal("0xFF-lead oversize round-trip mismatch")
	}
}

func TestUnpadDisplayNameRoundTrip(t *testing.T) {
	for _, name := range []string{"", "a", "report.pdf", "unicode-äöü-名前.txt", strings.Repeat("x", 884), strings.Repeat("x", 885)} {
		got, err := unpadDisplayName(padDisplayName([]byte(name)))
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		if string(got) != name {
			t.Errorf("round-trip: got %q, want %q", got, name)
		}
	}
}

func TestUnpadDisplayNameLegacyPassthrough(t *testing.T) {
	plain := []byte("pre-padding name.txt")
	got, err := unpadDisplayName(plain)
	if err != nil {
		t.Fatalf("unpadDisplayName: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("legacy plaintext must pass through: got %q", got)
	}
}

func TestUnpadDisplayNameRejectsUnknownVersion(t *testing.T) {
	if _, err := unpadDisplayName([]byte{0xff, 0x02, 0x00, 0x01, 'a'}); err == nil {
		t.Fatal("unknown pad version must error, not decode as garbage")
	}
}

func TestUnpadDisplayNameRejectsOutOfBoundsLength(t *testing.T) {
	if _, err := unpadDisplayName([]byte{0xff, 0x01, 0xff, 0xff, 'a', 'b'}); err == nil {
		t.Fatal("length past the blob end must error")
	}
}

func TestSealDisplayNameLengthHidesNameLength(t *testing.T) {
	pk, sk := mustGenKeyPair(t)
	defer sk.Zero()
	sealedShort, err := SealDisplayName("a.txt", pk)
	if err != nil {
		t.Fatalf("SealDisplayName: %v", err)
	}
	sealedLonger, err := SealDisplayName("a-much-longer-filename-in-the-same-bucket.txt", pk)
	if err != nil {
		t.Fatalf("SealDisplayName: %v", err)
	}
	if len(sealedShort) != len(sealedLonger) {
		t.Fatalf("same-bucket names must seal to equal lengths: %d vs %d", len(sealedShort), len(sealedLonger))
	}
	if len(sealedShort) != 1160+64 {
		t.Fatalf("sealed length %d, want %d (seal overhead + smallest bucket)", len(sealedShort), 1160+64)
	}
}
