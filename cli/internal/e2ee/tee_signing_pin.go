package e2ee

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/output"
)

const teeSigningPinVersion = 1

var ErrTeeAttestationUnavailable = errors.New("tee_signing_pk_unattested")

func IsTeeAttestationUnavailable(err error) bool {
	return errors.Is(err, ErrTeeAttestationUnavailable)
}

var teeSigningPins = ownerSidecar[teeSigningPk]{name: "tee_signing_pks.json", version: teeSigningPinVersion}

const teeRetiredPkLimit = 8

type teeSigningPk struct {
	Ed      string                 `json:"ed25519"`
	Ml      string                 `json:"mldsa"`
	Posture *teeAttestationPosture `json:"posture,omitempty"`
	Retired []retiredTeeSigningPk  `json:"retired,omitempty"`
}

type retiredTeeSigningPk struct {
	Ed        string `json:"ed25519"`
	Ml        string `json:"mldsa"`
	RetiredAt string `json:"retired_at,omitempty"`
}

type TeeSigningKey struct {
	Ed25519   string `json:"ed25519"`
	Mldsa     string `json:"mldsa"`
	RetiredAt string `json:"retired_at,omitempty"`
}

func (k TeeSigningKey) Fingerprint() string {
	return TeeSigningKeyFingerprint(k.Ed25519, k.Mldsa)
}

func TeeSigningKeyFingerprint(edB64, mlB64 string) string {
	ed, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil {
		return ""
	}
	ml, err := base64.StdEncoding.DecodeString(mlB64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append(append([]byte{}, ed...), ml...))
	hexed := hex.EncodeToString(sum[:])
	groups := make([]string, 0, len(hexed)/4)
	for i := 0; i+4 <= len(hexed); i += 4 {
		groups = append(groups, hexed[i:i+4])
	}
	return strings.Join(groups, " ")
}

type teeAttestationPosture struct {
	Mode           string `json:"mode"`
	Mrenclave      string `json:"mrenclave,omitempty"`
	SealingPk      string `json:"sealing_pk,omitempty"`
	SealingPkKyber string `json:"sealing_pk_kyber,omitempty"`
}

func loadTeeSigningPkFile() (*sidecarFile[teeSigningPk], error) {
	path := teeSigningPins.path()
	if path == "" {
		return teeSigningPins.empty(), nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return teeSigningPins.empty(), nil
	}
	if err != nil {
		return nil, errTeePinStoreUnreadable(path, err.Error())
	}
	var f sidecarFile[teeSigningPk]
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, errTeePinStoreUnreadable(path, "it is not valid JSON")
	}
	if f.V != teeSigningPinVersion {
		return nil, errTeePinStoreUnreadable(path, fmt.Sprintf("it is format version %d and this build reads version %d", f.V, teeSigningPinVersion))
	}
	if f.Owners == nil {
		f.Owners = map[string]teeSigningPk{}
	}
	return &f, nil
}

func errTeePinStoreUnreadable(path, why string) error {
	return fmt.Errorf("tee_pin_store_unreadable: %s exists but cannot be used (%s), so nothing it pins can be checked and it was left untouched. Run `pc te repin` to set it aside and pin what the server offers after comparing fingerprints, or inspect or remove the file yourself", path, why)
}

func teeSigningRecord() (teeSigningPk, error) {
	owner := signingPinOwner()
	if owner == "" {
		return teeSigningPk{}, nil
	}
	f, err := loadTeeSigningPkFile()
	if err != nil {
		return teeSigningPk{}, err
	}
	return f.Owners[owner], nil
}

func (r teeSigningPk) pinned() bool {
	return r.Ed != "" && r.Ml != ""
}

func (r teeSigningPk) accepts(edB64, mlB64 string) bool {
	if r.pinned() && r.Ed == edB64 && r.Ml == mlB64 {
		return true
	}
	for _, retired := range r.Retired {
		if retired.Ed == edB64 && retired.Ml == mlB64 {
			return true
		}
	}
	return false
}

func pinnedTeeSigningPk() (teeSigningPk, bool) {
	rec, _ := teeSigningRecord()
	return rec, rec.pinned()
}

func teeSigningPkPinned() bool {
	rec, _ := teeSigningRecord()
	return rec.pinned()
}

func TeeSigningPins() (*TeeSigningKey, []TeeSigningKey) {
	rec, _ := teeSigningRecord()
	var pinned *TeeSigningKey
	if rec.pinned() {
		pinned = &TeeSigningKey{Ed25519: rec.Ed, Mldsa: rec.Ml}
	}
	retired := make([]TeeSigningKey, 0, len(rec.Retired))
	for _, r := range rec.Retired {
		retired = append(retired, TeeSigningKey{Ed25519: r.Ed, Mldsa: r.Ml, RetiredAt: r.RetiredAt})
	}
	return pinned, retired
}

func dropRetired(list []retiredTeeSigningPk, edB64, mlB64 string) []retiredTeeSigningPk {
	kept := make([]retiredTeeSigningPk, 0, len(list))
	for _, r := range list {
		if r.Ed == edB64 && r.Ml == mlB64 {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

type TeeAttestationOffer struct {
	Ed25519 string
	Mldsa   string
	posture teeAttestationPosture
}

func (o *TeeAttestationOffer) Fingerprint() string {
	return TeeSigningKeyFingerprint(o.Ed25519, o.Mldsa)
}

func (o *TeeAttestationOffer) PostureLabel() string { return o.posture.label() }

func (p teeAttestationPosture) label() string {
	keys := shortSealingFingerprint(p.SealingPk, p.SealingPkKyber)
	switch {
	case p.Mode == "epid" && p.Mrenclave != "":
		return "SGX measurement " + p.Mrenclave + ", sealing key " + keys
	case p.SealingPk != "":
		return "unattested sealing key " + keys
	default:
		return ""
	}
}

func shortSealingFingerprint(pkB64, kyberB64 string) string {
	raw, err := base64.StdEncoding.DecodeString(pkB64)
	if err != nil {
		return ""
	}
	kyber, err := base64.StdEncoding.DecodeString(kyberB64)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append(raw, kyber...))
	hexed := hex.EncodeToString(sum[:])
	return hexed[0:4] + " " + hexed[4:8] + " " + hexed[8:12] + " " + hexed[12:16]
}

func PinnedTeeAttestationLabel() string {
	p, err := pinnedTeeAttestationPosture()
	if err != nil || p == nil {
		return ""
	}
	return p.label()
}

func validateTeeSigningPair(edB64, mlB64 string) error {
	ed, err := base64.StdEncoding.DecodeString(edB64)
	if err != nil || len(ed) != crypto.Ed25519PKSize {
		return errors.New("tee_signing_pk_wrong_size: the offered Ed25519 signing key is not a valid " + fmt.Sprint(crypto.Ed25519PKSize) + "-byte key")
	}
	ml, err := base64.StdEncoding.DecodeString(mlB64)
	if err != nil || len(ml) != crypto.Mldsa44PKSize {
		return errors.New("tee_signing_pk_wrong_size: the offered ML-DSA signing key is not a valid " + fmt.Sprint(crypto.Mldsa44PKSize) + "-byte key")
	}
	return nil
}

func RepinTeeSigningPk(offer *TeeAttestationOffer) error {
	return defaultSession.RepinTeeSigningPk(offer)
}

func (s *Session) RepinTeeSigningPk(offer *TeeAttestationOffer) error {
	path := teeSigningPins.path()
	owner := signingPinOwner()
	if path == "" || owner == "" {
		return errors.New("no account key set is configured, so there is no pin to move")
	}
	if offer == nil {
		return errors.New("no attestation answer to pin")
	}
	if err := validateTeeSigningPair(offer.Ed25519, offer.Mldsa); err != nil {
		return err
	}
	if offer.Fingerprint() == "" {
		return errors.New("tee_signing_pk_unfingerprintable: the offered key set has no fingerprint to show")
	}
	teeSigningFileMu.Lock()
	f, err := loadTeeSigningPkFile()
	if err != nil {
		if renameErr := os.Rename(path, path+".unreadable"); renameErr != nil {
			teeSigningFileMu.Unlock()
			return fmt.Errorf("%w; setting it aside failed: %v", err, renameErr)
		}
		f = teeSigningPins.empty()
	}
	rec := f.Owners[owner]
	keySame := rec.Ed == offer.Ed25519 && rec.Ml == offer.Mldsa
	postureSame := rec.Posture != nil && *rec.Posture == offer.posture
	if keySame && postureSame {
		teeSigningFileMu.Unlock()
		return errors.New("that attestation is already the pinned one")
	}
	if !keySame {
		if rec.Ed != "" && rec.Ml != "" {
			superseded := retiredTeeSigningPk{Ed: rec.Ed, Ml: rec.Ml, RetiredAt: time.Now().UTC().Format(time.RFC3339)}
			rec.Retired = append(dropRetired(rec.Retired, rec.Ed, rec.Ml), superseded)
		}
		rec.Retired = dropRetired(rec.Retired, offer.Ed25519, offer.Mldsa)
		if len(rec.Retired) > teeRetiredPkLimit {
			rec.Retired = rec.Retired[len(rec.Retired)-teeRetiredPkLimit:]
		}
		rec.Ed, rec.Ml = offer.Ed25519, offer.Mldsa
	}
	next := offer.posture
	rec.Posture = &next
	f.Owners[owner] = rec
	_ = teeSigningPins.store(f)
	teeSigningFileMu.Unlock()

	s.forgetTeeAttestationMemos()
	return nil
}

func (s *Session) forgetTeeAttestationMemos() {
	teeSigningAttMu.Lock()
	teeSigningAtt = nil
	teeSigningAttNextTry = time.Time{}
	teeSigningAttMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.teeEnclaveKeySet = nil
	s.teeEnclaveKeyRefusal = nil
	s.teeKeysEpoch++
	s.teeKeysFetch = nil
}

func ForgetRetiredTeeSigningPk(fingerprint string) bool {
	path := teeSigningPins.path()
	owner := signingPinOwner()
	if path == "" || owner == "" || fingerprint == "" {
		return false
	}
	teeSigningFileMu.Lock()
	defer teeSigningFileMu.Unlock()
	f, err := loadTeeSigningPkFile()
	if err != nil {
		return false
	}
	rec := f.Owners[owner]
	kept := make([]retiredTeeSigningPk, 0, len(rec.Retired))
	for _, r := range rec.Retired {
		if TeeSigningKeyFingerprint(r.Ed, r.Ml) == fingerprint {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) == len(rec.Retired) {
		return false
	}
	rec.Retired = kept
	f.Owners[owner] = rec
	_ = teeSigningPins.store(f)
	return true
}

var teeSigningFileMu sync.Mutex

func recordTeeSigningPk(edB64, mlB64 string) {
	path := teeSigningPins.path()
	owner := signingPinOwner()
	if path == "" || owner == "" || edB64 == "" || mlB64 == "" {
		return
	}
	teeSigningFileMu.Lock()
	defer teeSigningFileMu.Unlock()
	f, err := loadTeeSigningPkFile()
	if err != nil {
		return
	}
	rec := f.Owners[owner]
	rec.Ed, rec.Ml = edB64, mlB64
	f.Owners[owner] = rec
	_ = teeSigningPins.store(f)
}

func pinnedTeeAttestationPosture() (*teeAttestationPosture, error) {
	owner := signingPinOwner()
	if owner == "" {
		return nil, nil
	}
	f, err := loadTeeSigningPkFile()
	if err != nil {
		return nil, err
	}
	rec, ok := f.Owners[owner]
	if !ok || rec.Posture == nil {
		return nil, nil
	}
	if rec.Posture.Mode != "epid" && rec.Posture.Mode != "none" {
		return nil, errTeePinStoreUnreadable(teeSigningPins.path(), fmt.Sprintf("this account's scanner posture has mode %q, which this build does not know", rec.Posture.Mode))
	}
	return rec.Posture, nil
}

func recordTeeAttestationPosture(p teeAttestationPosture) {
	path := teeSigningPins.path()
	owner := signingPinOwner()
	if path == "" || owner == "" || p.Mode == "" {
		return
	}
	teeSigningFileMu.Lock()
	defer teeSigningFileMu.Unlock()
	f, err := loadTeeSigningPkFile()
	if err != nil {
		return
	}
	rec := f.Owners[owner]
	rec.Posture = &p
	f.Owners[owner] = rec
	_ = teeSigningPins.store(f)
}

type servedAttestation struct {
	Mode, Mrenclave, Quote, Status, SealingPk, SealingPkKyber string
}

func (a servedAttestation) sgx() bool {
	return a.Mode == "epid" && a.Mrenclave != "" && a.Quote != ""
}

func teeRepinSidecarNote(path string) string {
	return "deleting " + path + " instead accepts the next one offered, which is also what an attacker needs, and drops every retired signing key with it"
}

func checkTeeAttestationPosture(att servedAttestation) (func(), error) {
	path := teeSigningPins.path()
	if att.Status == "untrusted" {
		return nil, errors.New("tee_attestation_untrusted: the server reports its own enclave attestation as untrusted")
	}
	if att.sgx() && att.Status != "trusted" {
		return nil, errors.New("tee_attestation_unverified: the server reports SGX mode without a verified quote")
	}
	offered, err := postureFor(att)
	if err != nil {
		return nil, err
	}
	commit := func() { recordTeeAttestationPosture(offered) }
	pinned, err := pinnedTeeAttestationPosture()
	if err != nil {
		return nil, err
	}
	switch {
	case pinned == nil:
		return commit, nil
	case pinned.Mode == "epid" && offered.Mode != "epid":
		return nil, fmt.Errorf("tee_attestation_downgraded: this account last saw an SGX enclave and the server now offers an unattested key. If the deployment deliberately left SGX, `pc te repin` shows both postures and moves the pin; %s", teeRepinSidecarNote(path))
	case pinned.Mode != offered.Mode:
		return nil, fmt.Errorf("tee_attestation_mode_changed: the server now claims an SGX enclave where this account pinned an unattested key, and this client cannot verify that claim. If the deployment deliberately moved to SGX, `pc te repin` shows both postures and moves the pin; %s", teeRepinSidecarNote(path))
	case offered.Mode == "epid" && offered.Mrenclave != pinned.Mrenclave:
		return nil, fmt.Errorf("tee_mrenclave_changed: the enclave measurement differs from the one pinned for this account. If the scanner was deliberately rebuilt, `pc te repin` shows both measurements and moves the pin; %s", teeRepinSidecarNote(path))
	case offered.SealingPk != pinned.SealingPk:
		return nil, errTeeEnclavePkChanged()
	case pinned.SealingPkKyber == "":
		return func() {
			commit()
			teeNotice("the scanner's post-quantum (ML-KEM) sealing key was pinned on this contact because this account's pin predates it; run `pc te repin` from a trusted network to re-establish it")
		}, nil
	case offered.SealingPkKyber != pinned.SealingPkKyber:
		return nil, errTeeEnclavePkChanged()
	default:
		return func() {}, nil
	}
}

var teeNotice = output.PrintWarning

func errTeeEnclavePkChanged() error {
	return fmt.Errorf("tee_enclave_pk_changed: the enclave sealing key differs from the one pinned for this account. If the scanner was deliberately rekeyed, `pc te repin` shows both keys and moves the pin; %s", teeRepinSidecarNote(teeSigningPins.path()))
}

func teeKeySetMatchesPin(set *crypto.PublicKeySet) bool {
	pinned, err := pinnedTeeAttestationPosture()
	if err != nil || set == nil || pinned == nil {
		return false
	}
	return pinned.SealingPk == base64.StdEncoding.EncodeToString(set.X25519[:]) &&
		pinned.SealingPkKyber == base64.StdEncoding.EncodeToString(set.Kyber)
}

var (
	teeSigningAttMu       sync.Mutex
	teeSigningAtt         *teeSigningPk
	teeSigningAttNextTry  time.Time
	teeSigningAttThrottle = time.Minute
)

func attestedTeeSigningPk() *teeSigningPk {
	teeSigningAttMu.Lock()
	defer teeSigningAttMu.Unlock()
	if teeSigningAtt != nil {
		return teeSigningAtt
	}
	if time.Now().Before(teeSigningAttNextTry) {
		return nil
	}
	teeSigningAttNextTry = time.Now().Add(teeSigningAttThrottle)
	pk, err := fetchTeeSigningPk()
	if err != nil {
		return nil
	}
	teeSigningAtt = pk
	return teeSigningAtt
}

func fetchTeeSigningPk() (*teeSigningPk, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := api.NewClient().FetchTeeAttestation(ctx)
	if err != nil {
		return nil, err
	}
	if err := teeAttestationAnswerable(resp); err != nil {
		return nil, err
	}
	att := resp.Attestation
	return &teeSigningPk{Ed: att.EnclaveSigningPkEd25519, Ml: att.EnclaveSigningPkMldsa}, nil
}

func teeAttestationAnswerable(resp *api.TeeAttestationResponse) error {
	if resp == nil || !resp.Success {
		return errors.New("tee_attestation_unanswered: the server did not answer the attestation probe")
	}
	if !resp.Enabled {
		return errors.New("tee_scanner_disabled: this deployment runs no scanner, so there is no signing key to pin")
	}
	if !resp.Available {
		return errors.New("tee_attestation_unavailable: the server reports the scanner as unavailable")
	}
	att := resp.Attestation
	if att.VerificationStatus == "untrusted" {
		return errors.New("tee_attestation_untrusted: the server reports its own enclave attestation as untrusted")
	}
	if att.AttestationMode == "epid" && att.Mrenclave != "" && att.SgxQuote != "" && att.VerificationStatus != "trusted" {
		return errors.New("tee_attestation_unverified: the server reports SGX mode without a verified quote")
	}
	if att.EnclaveSigningPkEd25519 == "" || att.EnclaveSigningPkMldsa == "" {
		return errors.New("tee_signing_pk_absent: the attestation carries no enclave signing key set")
	}
	return nil
}

func OfferedTeeSigningPk() (*TeeAttestationOffer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := api.NewClient().FetchTeeAttestation(ctx)
	if err != nil {
		return nil, err
	}
	if err := teeAttestationAnswerable(resp); err != nil {
		return nil, err
	}
	att := resp.Attestation
	if err := validateTeeSigningPair(att.EnclaveSigningPkEd25519, att.EnclaveSigningPkMldsa); err != nil {
		return nil, err
	}
	served := servedAttestation{
		Mode: att.AttestationMode, Mrenclave: att.Mrenclave, Quote: att.SgxQuote,
		Status: att.VerificationStatus, SealingPk: att.EnclavePublicKey,
		SealingPkKyber: att.EnclavePublicKeyKyber,
	}
	posture, err := postureFor(served)
	if err != nil {
		return nil, err
	}
	return &TeeAttestationOffer{
		Ed25519: att.EnclaveSigningPkEd25519,
		Mldsa:   att.EnclaveSigningPkMldsa,
		posture: posture,
	}, nil
}

func postureFor(att servedAttestation) (teeAttestationPosture, error) {
	raw, err := base64.StdEncoding.DecodeString(att.SealingPk)
	if err != nil || len(raw) != 32 {
		return teeAttestationPosture{}, errors.New("tee_enclave_key_malformed: the server answered with an X25519 sealing key that is not 32 bytes")
	}
	kyber, err := base64.StdEncoding.DecodeString(att.SealingPkKyber)
	if err != nil || len(kyber) != crypto.KyberPublicKeySize {
		return teeAttestationPosture{}, errors.New("tee_enclave_key_malformed: the server answered with an ML-KEM sealing key of the wrong size")
	}
	p := teeAttestationPosture{Mode: "none", SealingPk: att.SealingPk, SealingPkKyber: att.SealingPkKyber}
	if att.sgx() {
		p.Mode, p.Mrenclave = "epid", att.Mrenclave
	}
	return p, nil
}

func checkTeeSigningPks(edB64, mlB64 string) (func(), error) {
	rec, err := teeSigningRecord()
	if err != nil {
		return nil, err
	}
	if rec.pinned() {
		if rec.accepts(edB64, mlB64) {
			return func() {}, nil
		}
		return nil, fmt.Errorf("tee_signing_pk_changed: the enclave signing key differs from the one pinned for this account. If the enclave was deliberately rekeyed, `pc te repin` shows both fingerprints and moves the pin, keeping the files the old key signed readable; deleting %s instead accepts the next key it is offered, which is also what an attacker needs, and refuses every file the old key signed", teeSigningPins.path())
	}
	att := attestedTeeSigningPk()
	if att == nil {
		return nil, ErrTeeAttestationUnavailable
	}
	if att.Ed != edB64 || att.Ml != mlB64 {
		return nil, errors.New("tee_signing_pk_untrusted: the served enclave signing key is not the attested one")
	}
	return func() { recordTeeSigningPk(edB64, mlB64) }, nil
}
