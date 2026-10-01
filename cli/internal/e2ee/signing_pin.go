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

func resolveOwnSigningPubsInteractive() ([]byte, []byte) {
	if cachedSigningPriv == nil {
		GetSigningKeysIfAvailable(func() {})
	}
	return deriveSigningPubs(cachedSigningPriv)
}

const ownSigningPksMax = 16

func signingPksPath() string {
	dir := config.Dir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "signing_pks.json")
}

func signingPinOwner() string {
	raw, err := base64.StdEncoding.DecodeString(config.Get().PublicKey)
	if err != nil {
		return ""
	}
	return crypto.AccountFingerprint(raw)
}

type signingPksFile struct {
	V      int                 `json:"v"`
	Owners map[string][]string `json:"owners"`
}

func loadSigningPkFile() *signingPksFile {
	empty := &signingPksFile{V: 2, Owners: map[string][]string{}}
	path := signingPksPath()
	if path == "" {
		return empty
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return empty
	}
	var f signingPksFile
	if json.Unmarshal(raw, &f) == nil && f.V == 2 && f.Owners != nil {
		return &f
	}
	var legacy []string
	if json.Unmarshal(raw, &legacy) == nil && len(legacy) > 0 {
		if owner := signingPinOwner(); owner != "" {
			return &signingPksFile{V: 2, Owners: map[string][]string{owner: legacy}}
		}
	}
	return empty
}

func loadSigningPkSet() []string {
	owner := signingPinOwner()
	if owner == "" {
		return nil
	}
	return loadSigningPkFile().Owners[owner]
}

func rememberSigningEdPub(pub []byte) {
	path := signingPksPath()
	owner := signingPinOwner()
	if path == "" || owner == "" {
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
	data, err := json.Marshal(f)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = fsutil.WriteFileAtomic(path, data, 0600)
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
