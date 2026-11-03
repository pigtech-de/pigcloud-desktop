package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRecoveryKeyFormatConformance(t *testing.T) {
	raw, err := os.ReadFile(vectorPath(t, "recovery_key_format_v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v recoveryKeyFormatVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.VectorKind != "recovery_key_format" || len(v.Cases) == 0 {
		t.Fatalf("unexpected vector: kind=%q cases=%d", v.VectorKind, len(v.Cases))
	}
	for _, c := range v.Cases {
		key, err := hex.DecodeString(c.KeyHex)
		if err != nil {
			t.Fatalf("%s: key_hex: %v", c.Label, err)
		}
		if got := FormatRecoveryKey(key); got != c.Formatted {
			t.Errorf("%s: FormatRecoveryKey = %q, want %q", c.Label, got, c.Formatted)
		}
	}
}
