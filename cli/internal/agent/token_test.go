package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"pigcloud/internal/crypto"
	"strings"
	"testing"
)

func TestGenerateTokenProducesUnpredictable32ByteTokens(t *testing.T) {
	const draws = 2000

	seen := make(map[string]struct{}, draws)
	byteValues := make(map[byte]struct{}, 256)
	var perPosition []map[rune]struct{}

	for i := range draws {
		tok, err := generateToken()
		if err != nil {
			t.Fatalf("generateToken: %v", err)
		}
		if len(tok) != 64 {
			t.Fatalf("token is %d characters, want 64 (32 bytes hex)", len(tok))
		}
		if tok != strings.ToLower(tok) {
			t.Fatalf("token is not lowercase hex: clients compare it byte for byte")
		}
		raw, err := hex.DecodeString(tok)
		if err != nil {
			t.Fatalf("token is not hex: %v", err)
		}
		if len(raw) != 32 {
			t.Fatalf("token decodes to %d bytes, want 32", len(raw))
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("generateToken repeated a token after %d draws", i)
		}
		seen[tok] = struct{}{}

		if perPosition == nil {
			perPosition = make([]map[rune]struct{}, len(tok))
			for j := range perPosition {
				perPosition[j] = make(map[rune]struct{}, 16)
			}
		}
		for pos, c := range tok {
			perPosition[pos][c] = struct{}{}
		}
		for _, b := range raw {
			byteValues[b] = struct{}{}
		}
	}

	if len(byteValues) != 256 {
		t.Errorf("tokens spanned %d of 256 byte values across %d draws", len(byteValues), draws)
	}
	for pos, chars := range perPosition {
		if len(chars) < 10 {
			t.Errorf("hex position %d took only %d distinct values across %d draws", pos, len(chars), draws)
		}
	}
}

func TestDecodeHexKeyRejectsAnythingButExactLengthHex(t *testing.T) {
	valid := []byte{0xde, 0xad, 0xbe, 0xef}
	validHex := hex.EncodeToString(valid)

	rejected := []struct {
		name        string
		in          string
		expectedLen int
	}{
		{"empty string", "", len(valid)},
		{"odd digit count", validHex[:len(validHex)-1], len(valid)},
		{"non-hex characters", "zzzzzzzz", len(valid)},
		{"leading whitespace", " " + validHex, len(valid)},
		{"trailing newline", validHex + "\n", len(valid)},
		{"0x prefix", "0x" + validHex, len(valid)},
		{"one byte short", hex.EncodeToString(valid[:3]), len(valid)},
		{"one byte long", hex.EncodeToString(append(valid, 0x11)), len(valid)},
		{"expected length zero", validHex, 0},
		{"expected length mismatch", validHex, 32},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if got := crypto.DecodeHexKey(tc.in, tc.expectedLen); got != nil {
				t.Errorf("crypto.DecodeHexKey(%q, %d) returned %d bytes, want nil", tc.in, tc.expectedLen, len(got))
			}
		})
	}

	t.Run("exact length hex", func(t *testing.T) {
		got := crypto.DecodeHexKey(validHex, len(valid))
		if !bytes.Equal(got, valid) {
			t.Errorf("crypto.DecodeHexKey(%q, %d) = %x, want %x", validHex, len(valid), got, valid)
		}
	})

	t.Run("uppercase hex", func(t *testing.T) {
		got := crypto.DecodeHexKey(strings.ToUpper(validHex), len(valid))
		if !bytes.Equal(got, valid) {
			t.Errorf("uppercase hex decoded to %x, want %x", got, valid)
		}
	})
}

func TestDecodeHexKeyRoundTripsOnlyAtTheExpectedLength(t *testing.T) {
	pick := make([]byte, 1)
	for range 300 {
		if _, err := rand.Read(pick); err != nil {
			t.Fatalf("crypto/rand: %v", err)
		}
		n := 1 + int(pick[0])%64
		want := randBytes(t, n)
		encoded := hex.EncodeToString(want)

		if got := crypto.DecodeHexKey(encoded, n); !bytes.Equal(got, want) {
			t.Fatalf("%d-byte field did not round-trip: got %d bytes", n, len(got))
		}
		if got := crypto.DecodeHexKey(encoded, n+1); got != nil {
			t.Fatalf("%d-byte field accepted at expected length %d, returning %d bytes", n, n+1, len(got))
		}
		if n > 1 {
			if got := crypto.DecodeHexKey(encoded, n-1); got != nil {
				t.Fatalf("%d-byte field accepted at expected length %d, returning %d bytes", n, n-1, len(got))
			}
		}
		if got := crypto.DecodeHexKey(encoded[:len(encoded)-1], n); got != nil {
			t.Fatalf("truncated hex accepted at length %d, returning %d bytes", n, len(got))
		}
		if got := crypto.DecodeHexKey("g"+encoded[1:], n); got != nil {
			t.Fatalf("non-hex digit accepted at length %d, returning %d bytes", n, len(got))
		}
	}
}
