package crypto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/text/unicode/norm"
)

const nameKeyContext = "pigcloud-e2ee-name-key-v2"

const NameKeySize = 32

func DeriveNameKey(priv *PrivateKeySet) ([]byte, error) {
	h, err := blake2b.New256([]byte(nameKeyContext))
	if err != nil {
		return nil, err
	}
	h.Write(priv.X25519[:])
	h.Write(priv.Kyber)
	return h.Sum(nil), nil
}

func ComputePathToken(nameKey []byte, canonicalPath string) ([]byte, error) {
	return pathTokenOver(nameKey, normalizeLower(canonicalPath))
}

func ComputePathTokenLegacy(nameKey []byte, canonicalPath string) ([]byte, error) {
	return pathTokenOver(nameKey, normalizeLowerSimple(canonicalPath))
}

func PathTokenNeedsLegacy(canonicalPath string) bool {
	return normalizeLower(canonicalPath) != normalizeLowerSimple(canonicalPath)
}

type PathTokenDepth int

const (
	PathTokenSelfOnly PathTokenDepth = iota
	PathTokenSelfAndParent
	PathTokenSelfAndAncestors
)

func PathTokenPaths(remotePath string, depth PathTokenDepth) []string {
	trimmed := strings.TrimLeft(strings.ReplaceAll(remotePath, "\\", "/"), "/")
	if trimmed == "" {
		return nil
	}
	paths := []string{trimmed}
	if depth == PathTokenSelfOnly {
		return paths
	}
	for parent := path.Dir(trimmed); parent != "." && parent != "" && parent != "/"; parent = path.Dir(parent) {
		paths = append(paths, parent)
		if depth == PathTokenSelfAndParent {
			break
		}
	}
	return paths
}

func AddPathTokenOptions(options map[string]string, nameKey []byte, paths []string) {
	canonical, legacy := PathTokenOptionJSON(nameKey, paths)
	if canonical != "" {
		options["path_tokens"] = canonical
	}
	if legacy != "" {
		options["path_tokens_legacy"] = legacy
	}
}

func PathTokenOptionJSON(nameKey []byte, paths []string) (canonicalJSON, legacyJSON string) {
	if len(nameKey) == 0 || len(paths) == 0 {
		return "", ""
	}
	canonical := make(map[string]string, len(paths))
	legacy := map[string]string{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		token, err := ComputePathToken(nameKey, p)
		if err != nil {
			continue
		}
		canonical[p] = hex.EncodeToString(token)
		if PathTokenNeedsLegacy(p) {
			if legacyToken, err := ComputePathTokenLegacy(nameKey, p); err == nil {
				legacy[p] = hex.EncodeToString(legacyToken)
			}
		}
	}
	return marshalHexTokenMap(canonical), marshalHexTokenMap(legacy)
}

func marshalHexTokenMap(tokens map[string]string) string {
	if len(tokens) == 0 {
		return ""
	}
	data, err := json.Marshal(tokens)
	if err != nil {
		return ""
	}
	return string(data)
}

func pathTokenOver(nameKey []byte, normalized string) ([]byte, error) {
	h, err := blake2b.New256(nameKey)
	if err != nil {
		return nil, err
	}
	h.Write([]byte(normalized))
	return h.Sum(nil), nil
}

var displayNamePadBuckets = [...]int{64, 128, 256, 512, 888}

const (
	displayNamePadMarker  = 0xff
	displayNamePadVersion = 0x01
	displayNamePadHeader  = 4
)

func padDisplayName(name []byte) []byte {
	total := displayNamePadHeader + len(name)
	bucket := 0
	for _, b := range displayNamePadBuckets {
		if total <= b {
			bucket = b
			break
		}
	}
	if bucket == 0 {
		if name[0] != displayNamePadMarker {
			return name
		}
		bucket = total
	}
	out := make([]byte, bucket)
	out[0] = displayNamePadMarker
	out[1] = displayNamePadVersion
	out[2] = byte(len(name) >> 8)
	out[3] = byte(len(name))
	copy(out[displayNamePadHeader:], name)
	return out
}

func unpadDisplayName(plain []byte) ([]byte, error) {
	if len(plain) < displayNamePadHeader || plain[0] != displayNamePadMarker {
		return plain, nil
	}
	if plain[1] != displayNamePadVersion {
		return nil, errors.New("unknown display-name pad version")
	}
	n := int(plain[2])<<8 | int(plain[3])
	if displayNamePadHeader+n > len(plain) {
		return nil, errors.New("display-name pad length out of bounds")
	}
	return plain[displayNamePadHeader : displayNamePadHeader+n], nil
}

func SealDisplayName(name string, recipient *PublicKeySet) ([]byte, error) {
	return HybridSeal(padDisplayName([]byte(name)), recipient)
}

func UnsealDisplayName(sealed []byte, priv *PrivateKeySet) (string, error) {
	plaintext, err := HybridUnseal(sealed, priv)
	if err != nil {
		return "", err
	}
	nameBytes, err := unpadDisplayName(plaintext)
	if err != nil {
		return "", err
	}
	return string(nameBytes), nil
}

func normalizePathShape(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.Trim(path, "/")
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	return norm.NFC.String(path)
}

func normalizeLower(path string) string {
	return cases.Lower(language.Und).String(normalizePathShape(path))
}

func normalizeLowerSimple(path string) string {
	return strings.ToLower(normalizePathShape(path))
}

func DecodeHexKey(hexStr string, size int) []byte {
	if hexStr == "" {
		return nil
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != size {
		return nil
	}
	return b
}
