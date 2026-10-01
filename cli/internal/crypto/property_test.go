package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

const propertyIterations = 200

func randSize(max int) int {
	var b [2]byte
	_, _ = rand.Read(b[:])
	n := (int(b[0])<<8 | int(b[1])) % (max + 1)
	if n < 0 {
		n = -n
	}
	return n
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return out
}

func mustGenKeyPair(t *testing.T) (*PublicKeySet, *PrivateKeySet) {
	t.Helper()
	pk, sk, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	return pk, sk
}

func TestProperty_HybridSealRoundTrip(t *testing.T) {
	pk, sk := mustGenKeyPair(t)
	for i := range propertyIterations {
		size := randSize(8192)
		pt := randBytes(t, size)

		sealed, err := HybridSeal(pt, pk)
		if err != nil {
			t.Fatalf("iter=%d size=%d HybridSeal: %v", i, size, err)
		}
		got, err := HybridUnseal(sealed, sk)
		if err != nil {
			t.Fatalf("iter=%d size=%d HybridUnseal: %v", i, size, err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("iter=%d size=%d round-trip mismatch", i, size)
		}
	}
}

func TestProperty_HybridSealEmptyPlaintext(t *testing.T) {
	pk, sk := mustGenKeyPair(t)
	sealed, err := HybridSeal(nil, pk)
	if err != nil {
		t.Fatalf("HybridSeal(empty): %v", err)
	}
	got, err := HybridUnseal(sealed, sk)
	if err != nil {
		t.Fatalf("HybridUnseal(empty): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty round-trip got %d bytes, want 0", len(got))
	}
}

func TestProperty_HybridSealFreshCiphertextPerCall(t *testing.T) {
	pk, _ := mustGenKeyPair(t)
	pt := []byte("identical plaintext for both seals")
	for i := range 20 {
		a, err := HybridSeal(pt, pk)
		if err != nil {
			t.Fatalf("seal A: %v", err)
		}
		b, err := HybridSeal(pt, pk)
		if err != nil {
			t.Fatalf("seal B: %v", err)
		}
		if bytes.Equal(a, b) {
			t.Fatalf("iter=%d: two seals of same plaintext produced identical ciphertext — ephemeral key or nonce repeating", i)
		}
	}
}

func TestProperty_HybridUnsealRejectsBitFlips(t *testing.T) {
	pk, sk := mustGenKeyPair(t)
	pt := []byte("authentic plaintext")

	for i := range 50 {
		sealed, err := HybridSeal(pt, pk)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}

		var posByte [2]byte
		_, _ = rand.Read(posByte[:])
		pos := (int(posByte[0])<<8 | int(posByte[1])) % len(sealed)

		var bitByte [1]byte
		_, _ = rand.Read(bitByte[:])
		bit := uint(bitByte[0] % 8)

		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[pos] ^= 1 << bit

		got, err := HybridUnseal(tampered, sk)
		if err == nil && bytes.Equal(got, pt) {
			t.Errorf("iter=%d pos=%d bit=%d: tampered ciphertext unsealed to original plaintext — AEAD tag not enforced", i, pos, bit)
		}
	}
}

func TestProperty_HybridUnsealRejectsWrongRecipient(t *testing.T) {
	pkA, _ := mustGenKeyPair(t)
	_, skB := mustGenKeyPair(t)
	for i := range 20 {
		pt := randBytes(t, randSize(256))
		sealed, err := HybridSeal(pt, pkA)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		got, err := HybridUnseal(sealed, skB)
		if err == nil && bytes.Equal(got, pt) {
			t.Errorf("iter=%d: sealed-to-A unsealed by B — recipient binding broken", i)
		}
	}
}

func TestProperty_HybridUnsealRejectsTruncated(t *testing.T) {
	pk, sk := mustGenKeyPair(t)
	sealed, err := HybridSeal([]byte("plaintext"), pk)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for cut := 1; cut <= 64; cut += 4 {
		if cut >= len(sealed) {
			break
		}
		short := sealed[:len(sealed)-cut]
		if _, err := HybridUnseal(short, sk); err == nil {
			t.Errorf("cut=%d: truncated ciphertext unsealed without error", cut)
		}
	}
}

func TestProperty_PathTokenIsDeterministic(t *testing.T) {
	_, sk := mustGenKeyPair(t)
	nameKey, err := DeriveNameKey(sk)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}
	paths := []string{
		"/",
		"/folder",
		"/folder/sub",
		"/with spaces/and-dashes",
		"/" + string([]byte{0xc3, 0xa4, 0xc3, 0xb6, 0xc3, 0xbc}),
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			a, err := ComputePathToken(nameKey, p)
			if err != nil {
				t.Fatalf("compute A: %v", err)
			}
			b, err := ComputePathToken(nameKey, p)
			if err != nil {
				t.Fatalf("compute B: %v", err)
			}
			if !bytes.Equal(a, b) {
				t.Errorf("path token not deterministic for %q", p)
			}
			if len(a) != 32 {
				t.Errorf("path token len=%d, want 32", len(a))
			}
		})
	}
}

func TestProperty_PathTokenIsCaseInsensitive(t *testing.T) {
	_, sk := mustGenKeyPair(t)
	nameKey, err := DeriveNameKey(sk)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}
	cases := [][2]string{
		{"/Documents", "/documents"},
		{"/FOO/BAR", "/foo/bar"},
		{"/Mixed/CaSe/Path", "/mixed/case/path"},
	}
	for _, c := range cases {
		t.Run(c[0]+"_vs_"+c[1], func(t *testing.T) {
			a, _ := ComputePathToken(nameKey, c[0])
			b, _ := ComputePathToken(nameKey, c[1])
			if !bytes.Equal(a, b) {
				t.Errorf("path tokens differ for case-only variant: %q vs %q", c[0], c[1])
			}
		})
	}
}

func TestProperty_PathTokenDoublesAndTrailingSlashesEqual(t *testing.T) {
	_, sk := mustGenKeyPair(t)
	nameKey, err := DeriveNameKey(sk)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}
	cases := [][2]string{
		{"/foo/bar", "/foo//bar"},
		{"/foo/bar", "/foo/bar/"},
		{"/foo/bar", "//foo/bar"},
		{"/foo/bar", "/foo///bar"},
	}
	for _, c := range cases {
		t.Run(c[0]+"_vs_"+c[1], func(t *testing.T) {
			a, _ := ComputePathToken(nameKey, c[0])
			b, _ := ComputePathToken(nameKey, c[1])
			if !bytes.Equal(a, b) {
				t.Errorf("path tokens differ for normalization-equivalent variants %q vs %q", c[0], c[1])
			}
		})
	}
}

func TestProperty_PathTokenDistinguishesDifferentPaths(t *testing.T) {
	_, sk := mustGenKeyPair(t)
	nameKey, err := DeriveNameKey(sk)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}
	seen := map[string]string{}
	for range propertyIterations {
		path := "/p" + hex.EncodeToString(randBytes(t, 8))
		tok, err := ComputePathToken(nameKey, path)
		if err != nil {
			continue
		}
		key := string(tok)
		if prev, ok := seen[key]; ok && prev != path {
			t.Errorf("collision: %q and %q hash to same path token", prev, path)
		}
		seen[key] = path
	}
}

func TestProperty_NameKeyChangesWithDifferentPrivate(t *testing.T) {
	_, skA := mustGenKeyPair(t)
	_, skB := mustGenKeyPair(t)
	a, err := DeriveNameKey(skA)
	if err != nil {
		t.Fatalf("DeriveNameKey A: %v", err)
	}
	b, err := DeriveNameKey(skB)
	if err != nil {
		t.Fatalf("DeriveNameKey B: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("name key identical across two random key pairs — derivation not binding to private")
	}
}

func TestPathTokenOptionJSON_LegacyOnlyForAffected(t *testing.T) {
	_, sk := mustGenKeyPair(t)
	nameKey, err := DeriveNameKey(sk)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}

	for _, affected := range []string{"İstanbul/dosya.txt", "ΟΔΥΣΣΕΑΣ/f.txt"} {
		canonical, legacy := PathTokenOptionJSON(nameKey, []string{affected})
		if canonical == "" {
			t.Errorf("canonical empty for affected path %q", affected)
		}
		if legacy == "" {
			t.Errorf("legacy empty for affected path %q", affected)
		}
	}

	if _, legacy := PathTokenOptionJSON(nameKey, []string{"Documents/Report.PDF"}); legacy != "" {
		t.Errorf("legacy non-empty for non-affected path: %s", legacy)
	}
	if c, l := PathTokenOptionJSON(nameKey, nil); c != "" || l != "" {
		t.Errorf("expected empty maps for no paths, got %q / %q", c, l)
	}
}

func TestProperty_SealDisplayNameRoundTrip(t *testing.T) {
	pk, sk := mustGenKeyPair(t)
	cases := []string{
		"simple.txt",
		"with spaces.pdf",
		"unicode-äöü-名前.txt",
		"emoji-🐷.png",
		"very-long-" + string(make([]byte, 200)),
	}
	for _, name := range cases {
		t.Run(name[:min(len(name), 30)], func(t *testing.T) {
			sealed, err := SealDisplayName(name, pk)
			if err != nil {
				t.Fatalf("SealDisplayName: %v", err)
			}
			got, err := UnsealDisplayName(sealed, sk)
			if err != nil {
				t.Fatalf("UnsealDisplayName: %v", err)
			}
			if got != name {
				t.Errorf("name round-trip: got %q, want %q", got, name)
			}
		})
	}
}
