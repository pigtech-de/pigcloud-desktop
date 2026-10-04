package e2ee

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/fsutil"
)

func deriveSigningEdPub(priv *crypto.SigningPrivateKeySet) []byte {
	if priv == nil || len(priv.Ed25519) != crypto.Ed25519SKSize {
		return nil
	}
	pub, ok := priv.Ed25519.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	return pub
}

func deriveSigningPubs(priv *crypto.SigningPrivateKeySet) (edPub []byte, mldsaPub []byte) {
	edPub = deriveSigningEdPub(priv)
	if pub, err := crypto.DeriveSigningPublic(priv); err == nil {
		mldsaPub = pub.Mldsa
	}
	return edPub, mldsaPub
}

func (s *Session) resolveOwnSigningPubs() ([]byte, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolveOwnSigningPubsLocked()
}

func (s *Session) resolveOwnSigningPubsLocked() ([]byte, []byte) {
	if s.signingPriv == nil {
		s.signingKeysIfAvailableLocked()
	}
	return deriveSigningPubs(s.signingPriv)
}

const ownSigningPksMax = 16

const ownSigningPinVersion = 2

var ownSigningPins = ownerSidecar[[]string]{name: "signing_pks.json", version: ownSigningPinVersion}

type ownerSidecar[T any] struct {
	name    string
	version int
}

type sidecarFile[T any] struct {
	V      int          `json:"v"`
	Owners map[string]T `json:"owners"`
}

func (s ownerSidecar[T]) path() string {
	dir := config.Dir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, s.name)
}

func (s ownerSidecar[T]) empty() *sidecarFile[T] {
	return &sidecarFile[T]{V: s.version, Owners: map[string]T{}}
}

func (s ownerSidecar[T]) decode(raw []byte) (*sidecarFile[T], bool) {
	var f sidecarFile[T]
	if json.Unmarshal(raw, &f) != nil || f.V != s.version || f.Owners == nil {
		return nil, false
	}
	return &f, true
}

func (s ownerSidecar[T]) load() *sidecarFile[T] {
	raw, err := os.ReadFile(s.path())
	if err != nil {
		return s.empty()
	}
	if f, ok := s.decode(raw); ok {
		return f
	}
	return s.empty()
}

func (s ownerSidecar[T]) store(f *sidecarFile[T]) error {
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	path := s.path()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0600)
}

func signingPinOwner() string {
	raw, err := base64.StdEncoding.DecodeString(config.Get().PublicKey)
	if err != nil {
		return ""
	}
	return crypto.AccountFingerprint(raw)
}

func loadSigningPkFile() *sidecarFile[[]string] {
	raw, err := os.ReadFile(ownSigningPins.path())
	if err != nil {
		return ownSigningPins.empty()
	}
	if f, ok := ownSigningPins.decode(raw); ok {
		return f
	}
	f := ownSigningPins.empty()
	var legacy []string
	if json.Unmarshal(raw, &legacy) == nil && len(legacy) > 0 {
		if owner := signingPinOwner(); owner != "" {
			f.Owners[owner] = legacy
		}
	}
	return f
}

func loadSigningPkSet() []string {
	owner := signingPinOwner()
	if owner == "" {
		return nil
	}
	return loadSigningPkFile().Owners[owner]
}

func rememberSigningEdPub(pub []byte) {
	owner := signingPinOwner()
	if ownSigningPins.path() == "" || owner == "" {
		return
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	f := loadSigningPkFile()
	set := f.Owners[owner]
	if slices.Contains(set, b64) {
		return
	}
	set = append(set, b64)
	if len(set) > ownSigningPksMax {
		set = set[len(set)-ownSigningPksMax:]
	}
	f.Owners[owner] = set
	_ = ownSigningPins.store(f)
}

func SigningPinCount() int {
	return len(loadSigningPkSet())
}

func signingEdPubTrusted(pub []byte) bool {
	b64 := base64.StdEncoding.EncodeToString(pub)
	return slices.Contains(loadSigningPkSet(), b64)
}

const signingPkHistoryDomain = "pigcloud-signing-pk-history-v1"

type signingPkHistoryBlob struct {
	V     int      `json:"v"`
	Eds   []string `json:"eds"`
	SigEd string   `json:"sig_ed"`
	SigMl string   `json:"sig_ml"`
}

func verifySigningPkHistory(blobJSON, ownEdPub, ownMldsaPub []byte) [][]byte {
	var blob signingPkHistoryBlob
	if json.Unmarshal(blobJSON, &blob) != nil || blob.V != 1 || len(blob.Eds) == 0 || blob.SigEd == "" || blob.SigMl == "" {
		return nil
	}
	input := []byte(signingPkHistoryDomain)
	decoded := make([][]byte, 0, len(blob.Eds))
	for _, edB64 := range blob.Eds {
		raw, err := base64.StdEncoding.DecodeString(edB64)
		if err != nil {
			return nil
		}
		input = append(input, raw...)
		decoded = append(decoded, raw)
	}
	sigEd, err := base64.StdEncoding.DecodeString(blob.SigEd)
	if err != nil || len(ownEdPub) != ed25519.PublicKeySize {
		return nil
	}
	if !ed25519.Verify(ed25519.PublicKey(ownEdPub), input, sigEd) {
		return nil
	}
	sigMl, err := base64.StdEncoding.DecodeString(blob.SigMl)
	if err != nil || len(ownMldsaPub) != crypto.Mldsa44PKSize {
		return nil
	}
	var mlPub mldsa44.PublicKey
	if mlPub.UnmarshalBinary(ownMldsaPub) != nil || !mldsa44.Verify(&mlPub, input, nil, sigMl) {
		return nil
	}
	return decoded
}

var (
	ownSigningHistoryMu      sync.Mutex
	ownSigningHistorySeeded  bool
	ownSigningHistoryNextTry time.Time
	ownSigningHistoryRetryAfter = time.Minute
)

func seedOwnSigningPkHistory(ownEdPub, ownMldsaPub []byte) {
	ownSigningHistoryMu.Lock()
	defer ownSigningHistoryMu.Unlock()
	if ownSigningHistorySeeded || time.Now().Before(ownSigningHistoryNextTry) {
		return
	}
	ownSigningHistoryNextTry = time.Now().Add(ownSigningHistoryRetryAfter)

	resp, err := api.NewClient().FetchEncryptionKeys(context.Background())
	if err != nil || resp == nil || !resp.Success {
		return
	}
	var payload api.E2EEKeysPayload
	if json.Unmarshal(resp.Raw, &payload) != nil {
		return
	}
	if payload.SigningPkHistory == "" {
		ownSigningHistorySeeded = true
		return
	}
	blobJSON, err := base64.StdEncoding.DecodeString(payload.SigningPkHistory)
	if err != nil {
		return
	}
	for _, ed := range verifySigningPkHistory(blobJSON, ownEdPub, ownMldsaPub) {
		rememberSigningEdPub(ed)
	}
	ownSigningHistorySeeded = true
}
