package e2ee

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/fsutil"
)

const peerSealPinVersion = 1

func peerSealPksPath() string {
	dir := config.Dir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "peer_seal_pks.json")
}

type peerSealPk struct {
	Fp string `json:"fp"`
	Ed string `json:"ed,omitempty"`
	Ml string `json:"ml,omitempty"`
}

func (r peerSealPk) anchored() bool { return r.Ed != "" && r.Ml != "" }

type peerSealPksFile struct {
	V      int                              `json:"v"`
	Owners map[string]map[string]peerSealPk `json:"owners"`
}

type PeerKeyBundle struct {
	X25519    []byte
	Kyber     []byte
	Ed25519   []byte
	Mldsa     []byte
	BundleSig []byte
}

type SealPinError struct {
	Reason string
	Peer   string
	Pinned string
	Served string
	Detail string
}

func (e *SealPinError) Error() string {
	msg := e.Reason + ": " + e.Detail
	if e.Pinned != "" || e.Served != "" {
		msg += " (pinned " + FingerprintDisplay(e.Pinned) + ", now offered " + FingerprintDisplay(e.Served) + ")"
	}
	return msg
}

func IsSealPinFailure(err error) bool {
	var p *SealPinError
	return errors.As(err, &p)
}

func sealStoreFailure(peer string, err error) error {
	return &SealPinError{
		Reason: "peer_seal_pk_store_unusable", Peer: peer,
		Detail: "the seal pin store could not be used, so nothing was sealed to " + peer + ": " + err.Error() +
			". Confirm each covered contact's key with them out of band first, and only then move the file aside by hand, since starting over re-accepts whatever key the server offers next",
	}
}

var peerSealFileMu sync.Mutex

func loadPeerSealPkFile() (*peerSealPksFile, error) {
	path := peerSealPksPath()
	if path == "" {
		return nil, errors.New("no CLI config directory, so there is nowhere to keep the seal pins")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &peerSealPksFile{V: peerSealPinVersion, Owners: map[string]map[string]peerSealPk{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f peerSealPksFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s is not readable as a pin store: %w", path, err)
	}
	if f.V != peerSealPinVersion || f.Owners == nil {
		return nil, fmt.Errorf("%s carries pin-store version %d, which this build does not understand", path, f.V)
	}
	return &f, nil
}

func peerSealRecord(peer string) (peerSealPk, bool, error) {
	owner := signingPinOwner()
	if owner == "" || !validPeerName(peer) {
		return peerSealPk{}, false, errors.New("no account key set is configured, so there is no pin bucket to read")
	}
	f, err := loadPeerSealPkFile()
	if err != nil {
		return peerSealPk{}, false, err
	}
	bucket := f.Owners[owner]
	if bucket == nil {
		return peerSealPk{}, false, nil
	}
	rec, ok := bucket[peer]
	return rec, ok && rec.Fp != "", nil
}

func writePeerSealRecord(peer string, rec peerSealPk) error {
	path := peerSealPksPath()
	owner := signingPinOwner()
	if path == "" || owner == "" || !validPeerName(peer) {
		return errors.New("no account key set is configured, so there is no pin bucket to write")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	peerSealFileMu.Lock()
	defer peerSealFileMu.Unlock()
	return fsutil.WithFileLock(path, func() error {
		f, err := loadPeerSealPkFile()
		if err != nil {
			return err
		}
		if f.Owners[owner] == nil {
			f.Owners[owner] = map[string]peerSealPk{}
		}
		f.Owners[owner][peer] = rec
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		return fsutil.WriteFileAtomic(path, data, 0600)
	})
}

func PeerSealPinCount() (int, error) {
	owner := signingPinOwner()
	if owner == "" {
		return 0, nil
	}
	f, err := loadPeerSealPkFile()
	if err != nil {
		return 0, err
	}
	return len(f.Owners[owner]), nil
}

func PeerSealPinStorePath() string { return peerSealPksPath() }

func PinnedPeerSealFingerprint(peer string) string {
	rec, _, err := peerSealRecord(peer)
	if err != nil {
		return ""
	}
	return rec.Fp
}

func sealKeyFingerprint(x25519, kyber []byte) string {
	sum := sha256.Sum256(append(append([]byte{}, x25519...), kyber...))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func FingerprintDisplay(fpB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(fpB64)
	if err != nil || len(raw) == 0 {
		return "none"
	}
	hexed := hex.EncodeToString(raw)
	groups := make([]string, 0, len(hexed)/4)
	for i := 0; i+4 <= len(hexed); i += 4 {
		groups = append(groups, hexed[i:i+4])
	}
	return strings.Join(groups, " ")
}

func PeerSafetyNumber(peer *PeerKeyBundle) (string, error) {
	if !peer.usableSealKey() {
		return "", errors.New("the served key set has no usable X25519 + ML-KEM pair")
	}
	mine, err := decodePublicKeySet(config.Get())
	if err != nil {
		return "", err
	}
	myParts := [][]byte{mine.X25519[:], mine.Kyber}
	theirParts := [][]byte{peer.X25519, peer.Kyber}
	myEd, myMl := resolveOwnSigningPubsInteractive()
	if len(myEd) > 0 && len(myMl) > 0 && len(peer.Ed25519) > 0 && len(peer.Mldsa) > 0 {
		myParts = append(myParts, myEd, myMl)
		theirParts = append(theirParts, peer.Ed25519, peer.Mldsa)
	}
	a, b := bytes.Join(myParts, nil), bytes.Join(theirParts, nil)
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	sum := sha256.Sum256(append(a, b...))
	groups := make([]string, 0, 8)
	for i := 0; i+4 <= len(sum); i += 4 {
		groups = append(groups, fmt.Sprintf("%05d", binary.BigEndian.Uint32(sum[i:i+4])%100000))
	}
	return strings.Join(groups, " "), nil
}

func (b *PeerKeyBundle) Fingerprint() string {
	if !b.usableSealKey() {
		return ""
	}
	return sealKeyFingerprint(b.X25519, b.Kyber)
}

func (b *PeerKeyBundle) usableSealKey() bool {
	return b != nil && len(b.X25519) == 32 && len(b.Kyber) == crypto.KyberPublicKeySize
}

func (b *PeerKeyBundle) signingAnchors() (edB64, mlB64 string) {
	if len(b.Ed25519) == crypto.Ed25519PKSize && len(b.Mldsa) == crypto.Mldsa44PKSize {
		return base64.StdEncoding.EncodeToString(b.Ed25519), base64.StdEncoding.EncodeToString(b.Mldsa)
	}
	return "", ""
}

func (b *PeerKeyBundle) SealKeySet() (*crypto.PublicKeySet, error) {
	if !b.usableSealKey() {
		return nil, errors.New("peer_seal_pk_missing: the served key set has no usable X25519 + ML-KEM pair")
	}
	var x [32]byte
	copy(x[:], b.X25519)
	return &crypto.PublicKeySet{X25519: x, Kyber: b.Kyber}, nil
}

type keyBundleSigBlob struct {
	V     int    `json:"v"`
	SigEd string `json:"sig_ed"`
	SigMl string `json:"sig_ml"`
}

func (b *PeerKeyBundle) bundleSelfSigned() bool {
	if !b.usableSealKey() || len(b.Ed25519) != crypto.Ed25519PKSize || len(b.Mldsa) != crypto.Mldsa44PKSize || len(b.BundleSig) == 0 {
		return false
	}
	var blob keyBundleSigBlob
	if json.Unmarshal(b.BundleSig, &blob) != nil || blob.V != 1 {
		return false
	}
	sigEd, err := base64.StdEncoding.DecodeString(blob.SigEd)
	if err != nil {
		return false
	}
	sigMl, err := base64.StdEncoding.DecodeString(blob.SigMl)
	if err != nil {
		return false
	}
	return crypto.VerifyKeyBundle(&crypto.KeyBundle{
		X25519: b.X25519, Kyber: b.Kyber, Ed25519: b.Ed25519, Mldsa: b.Mldsa,
	}, sigEd, sigMl)
}

func sealRotationAttributable(rec peerSealPk, bundle *PeerKeyBundle) bool {
	if !rec.anchored() {
		return false
	}
	edB64, mlB64 := bundle.signingAnchors()
	if edB64 != rec.Ed || mlB64 != rec.Ml {
		return false
	}
	return bundle.bundleSelfSigned()
}

func repinHint(peer string) string {
	return "If " + peer + " deliberately rotated their keys, compare the safety number with them out of band and run `pc fr repin " + peer + "` to move the pin"
}

func PinPeerSealKey(peer string, bundle *PeerKeyBundle) error {
	if !validPeerName(peer) {
		return &SealPinError{Reason: "peer_seal_pk_missing", Peer: peer,
			Detail: "the server named a recipient that cannot be pinned"}
	}
	if !bundle.usableSealKey() {
		return &SealPinError{Reason: "peer_seal_pk_missing", Peer: peer,
			Detail: "the key set served for " + peer + " has no usable X25519 + ML-KEM pair to seal to"}
	}
	fp := sealKeyFingerprint(bundle.X25519, bundle.Kyber)
	edB64, mlB64 := bundle.signingAnchors()

	rec, have, err := peerSealRecord(peer)
	if err != nil {
		return sealStoreFailure(peer, err)
	}
	switch {
	case !have:
		if err := writePeerSealRecord(peer, peerSealPk{Fp: fp, Ed: edB64, Ml: mlB64}); err != nil {
			return sealStoreFailure(peer, err)
		}
		return nil
	case rec.Fp == fp:
		return nil
	case sealRotationAttributable(rec, bundle):
		if err := writePeerSealRecord(peer, peerSealPk{Fp: fp, Ed: edB64, Ml: mlB64}); err != nil {
			return sealStoreFailure(peer, err)
		}
		return nil
	}
	detail := "the encryption key published for " + peer + " differs from the one this account pinned, and the new key carries no valid signature from the signing keys the pin was taken under, so nothing was sealed to it. "
	if !rec.anchored() {
		detail = "the encryption key published for " + peer + " differs from the one this account pinned, and that pin predates the signing anchor a rotation is checked against, so no change can be attributed to " + peer + " and nothing was sealed. "
	}
	return &SealPinError{
		Reason: "peer_seal_pk_changed", Peer: peer, Pinned: rec.Fp, Served: fp,
		Detail: detail + repinHint(peer),
	}
}

func RepinPeerSealKey(peer string, bundle *PeerKeyBundle) error {
	if !validPeerName(peer) {
		return errors.New("that username cannot be pinned")
	}
	if !bundle.usableSealKey() {
		return errors.New("the server offered no usable X25519 + ML-KEM key pair for " + peer)
	}
	fp := sealKeyFingerprint(bundle.X25519, bundle.Kyber)
	rec, have, err := peerSealRecord(peer)
	if err != nil {
		return sealStoreFailure(peer, err)
	}
	if have && rec.Fp == fp {
		return errors.New("that key is already the pinned one")
	}
	edB64, mlB64 := bundle.signingAnchors()
	if err := writePeerSealRecord(peer, peerSealPk{Fp: fp, Ed: edB64, Ml: mlB64}); err != nil {
		return sealStoreFailure(peer, err)
	}
	return nil
}

func bundleFromPubkeyPayload(p *api.E2EEPubkeyPayload) *PeerKeyBundle {
	decode := func(s string) []byte {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		return raw
	}
	return &PeerKeyBundle{
		X25519:    decode(p.PublicKey),
		Kyber:     decode(p.PublicKeyKyber),
		Ed25519:   decode(p.SigningPublicKeyEd25519),
		Mldsa:     decode(p.SigningPublicKeyMldsa),
		BundleSig: decode(p.KeyBundleSig),
	}
}

func FetchPeerKeyBundle(ctx context.Context, peer string) (*PeerKeyBundle, error) {
	resp, err := api.NewClient().FetchPublicKey(ctx, peer)
	if err != nil {
		return nil, err
	}
	if resp == nil || !resp.Success {
		return nil, errors.New("the server did not answer with " + peer + "'s public keys")
	}
	var payload api.E2EEPubkeyPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return nil, fmt.Errorf("parse %s's public keys: %w", peer, err)
	}
	bundle := bundleFromPubkeyPayload(&payload)
	if !bundle.usableSealKey() {
		return nil, errors.New(peer + " has no usable encryption key set")
	}
	return bundle, nil
}

func PinPeerSealKeyFromPubkey(peer string, payload *api.E2EEPubkeyPayload) (*crypto.PublicKeySet, error) {
	bundle := bundleFromPubkeyPayload(payload)
	if err := PinPeerSealKey(peer, bundle); err != nil {
		return nil, err
	}
	return bundle.SealKeySet()
}

var (
	peerBundleMu         sync.Mutex
	peerBundles          map[string]*PeerKeyBundle
	peerBundleNextTry    map[string]time.Time
	peerBundleRetryAfter = time.Minute
)

func peerSigningIdentity(ctx context.Context, peer string) *PeerKeyBundle {
	peerBundleMu.Lock()
	defer peerBundleMu.Unlock()
	if b, ok := peerBundles[peer]; ok {
		return b
	}
	if until, ok := peerBundleNextTry[peer]; ok && time.Now().Before(until) {
		return nil
	}
	bundle, err := FetchPeerKeyBundle(ctx, peer)
	if err != nil {
		if peerBundleNextTry == nil {
			peerBundleNextTry = map[string]time.Time{}
		}
		peerBundleNextTry[peer] = time.Now().Add(peerBundleRetryAfter)
		return nil
	}
	if peerBundles == nil {
		peerBundles = map[string]*PeerKeyBundle{}
	}
	peerBundles[peer] = bundle
	delete(peerBundleNextTry, peer)
	return bundle
}

func PinShareRecipientSealKey(ctx context.Context, r api.ShareRecipientWithKey) (*crypto.PublicKeySet, error) {
	keys, err := decodeRecipient(r)
	if err != nil {
		return nil, err
	}
	bundle := &PeerKeyBundle{X25519: keys.X25519[:], Kyber: keys.Kyber}
	if identity := peerSigningIdentity(ctx, r.Username); identity != nil {
		bundle.Ed25519 = identity.Ed25519
		bundle.Mldsa = identity.Mldsa
		bundle.BundleSig = identity.BundleSig
	}
	if err := PinPeerSealKey(r.Username, bundle); err != nil {
		return nil, err
	}
	return keys, nil
}
