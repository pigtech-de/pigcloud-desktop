package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"pigcloud/internal/crypto"
)

func TestAddE2eeNameFieldsSealsNameAndTokensThePath(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)

	const fileName = "Q3 forecast.numbers"
	const fullPath = "docs/reports/Q3 forecast.numbers"

	options := map[string]string{}
	AddE2eeNameFields(options, fileName, fullPath, func() { t.Fatal("name-field shaping signalled failure") })

	sealedB64, ok := options["e2ee_display_name"]
	if !ok {
		t.Fatal("e2ee_display_name was not set")
	}
	sealed, err := decodeB64Required(sealedB64, "e2ee_display_name")
	if err != nil {
		t.Fatalf("display name is not base64: %v", err)
	}
	name, err := crypto.UnsealDisplayName(sealed, f.priv)
	if err != nil {
		t.Fatalf("sealed display name does not open with the account key: %v", err)
	}
	if name != fileName {
		t.Fatalf("display name round trip returned %q, want %q", name, fileName)
	}

	tokenHex, ok := options["e2ee_path_token"]
	if !ok {
		t.Fatal("e2ee_path_token was not set")
	}
	want, err := crypto.ComputePathToken(f.nameKey, fullPath)
	if err != nil {
		t.Fatalf("reference path token: %v", err)
	}
	if tokenHex != hex.EncodeToString(want) {
		t.Fatal("path token was not computed under this account's name key over the full path")
	}
}

func TestAddE2eeNameFieldsPathTokenDeterministicNameSealNonDeterministic(t *testing.T) {
	isolateKeyEnv(t)
	unlockFixture(t)

	const fileName = "invoice.pdf"
	const fullPath = "billing/invoice.pdf"

	first := map[string]string{}
	second := map[string]string{}
	AddE2eeNameFields(first, fileName, fullPath, func() { t.Fatal("first shaping signalled failure") })
	AddE2eeNameFields(second, fileName, fullPath, func() { t.Fatal("second shaping signalled failure") })

	if first["e2ee_path_token"] != second["e2ee_path_token"] {
		t.Fatal("path token is not deterministic for a fixed path")
	}
	if first["e2ee_display_name"] == second["e2ee_display_name"] {
		t.Fatal("two seals of the same name are byte-identical; the ephemeral key is not random")
	}
}

func TestAddE2eeNameFieldsWithoutKeysEmitsNothing(t *testing.T) {
	isolateKeyEnv(t)

	options := map[string]string{}
	AddE2eeNameFields(options, "notes.txt", "docs/notes.txt", func() {
		t.Error("keyless shaping signalled failure")
	})
	if len(options) != 0 {
		t.Fatalf("keyless account populated name fields: %v", options)
	}
}

func TestAddE2eeNameFieldsForMkParentsBuildsAccumulatedSegments(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)

	segmentsIn := []string{"projects", "2026", "q3 plans"}

	options := map[string]string{}
	AddE2eeNameFieldsForMkParents(options, segmentsIn, func() { t.Fatal("mkparents shaping signalled failure") })

	raw, ok := options["e2ee_path_segments"]
	if !ok {
		t.Fatal("e2ee_path_segments was not set")
	}
	var out []struct {
		DisplayName string `json:"e2ee_display_name"`
		PathToken   string `json:"e2ee_path_token"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("segments payload is not JSON: %v", err)
	}
	if len(out) != len(segmentsIn) {
		t.Fatalf("emitted %d segments, want %d", len(out), len(segmentsIn))
	}

	accumulated := ""
	for i, seg := range segmentsIn {
		if accumulated == "" {
			accumulated = seg
		} else {
			accumulated = accumulated + "/" + seg
		}

		sealed, err := decodeB64Required(out[i].DisplayName, "segment display name")
		if err != nil {
			t.Fatalf("segment %d display name not base64: %v", i, err)
		}
		name, err := crypto.UnsealDisplayName(sealed, f.priv)
		if err != nil {
			t.Fatalf("segment %d name does not open: %v", i, err)
		}
		if name != seg {
			t.Fatalf("segment %d name is %q, want %q", i, name, seg)
		}

		want, err := crypto.ComputePathToken(f.nameKey, accumulated)
		if err != nil {
			t.Fatalf("segment %d reference token: %v", i, err)
		}
		if out[i].PathToken != hex.EncodeToString(want) {
			t.Fatalf("segment %d token is not keyed by the accumulated path %q", i, accumulated)
		}
	}
}

func TestAddE2eeNameFieldsForMkParentsEmitsNothingForEmptyOrKeyless(t *testing.T) {
	t.Run("no keys", func(t *testing.T) {
		isolateKeyEnv(t)
		options := map[string]string{}
		AddE2eeNameFieldsForMkParents(options, []string{"a", "b"}, func() {
			t.Error("keyless mkparents signalled failure")
		})
		if len(options) != 0 {
			t.Fatalf("keyless account populated segments: %v", options)
		}
	})

	t.Run("no segments", func(t *testing.T) {
		isolateKeyEnv(t)
		unlockFixture(t)
		options := map[string]string{}
		AddE2eeNameFieldsForMkParents(options, nil, func() { t.Fatal("empty mkparents signalled failure") })
		if _, ok := options["e2ee_path_segments"]; ok {
			t.Fatal("an empty segment list still set e2ee_path_segments")
		}
	})
}

func TestDecryptE2EENameUnsealsViaAgentWhenCacheEmpty(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	const plaintextName = "board deck.key"
	sealed, err := crypto.SealDisplayName(plaintextName, f.pub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	startTestAgent(t, f.agentMaterial(), time.Minute)
	resetKeyCaches()

	if got := DecryptE2EEName(b64(sealed)); got != plaintextName {
		t.Fatalf("agent-served decrypt returned %q, want %q", got, plaintextName)
	}
	if cachedPriv == nil || !bytes.Equal(cachedNameKey, f.nameKey) {
		t.Fatal("agent-served decrypt did not populate the key caches")
	}
}
