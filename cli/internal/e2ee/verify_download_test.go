package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func neutralizeHistorySeed() {
	markOwnSigningHistorySeeded()
}

func signingPair(t *testing.T) (*crypto.SigningPublicKeySet, *crypto.SigningPrivateKeySet) {
	t.Helper()
	pub, priv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyDownloadInteractiveUsesCachedSigningKey(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))
	neutralizeHistorySeed()

	pub, priv := signingPair(t)
	ct := randKey(t, 2048)
	edSig, mlSig := signCiphertext(t, priv, ct)
	dl := ownerDownload(pub, edSig, mlSig)

	defaultSession.signingPriv = priv
	if err := VerifyDownloadIntegrity(bytes.NewReader(ct), dl); err != nil {
		t.Fatalf("valid download rejected on the interactive path: %v", err)
	}

	otherPub, otherPriv := signingPair(t)
	edSig2, mlSig2 := signCiphertext(t, otherPriv, ct)
	err := VerifyDownloadIntegrity(bytes.NewReader(ct), ownerDownload(otherPub, edSig2, mlSig2))
	if err == nil || err.Error() != "owner_signing_pk_untrusted" {
		t.Fatalf("foreign signer accepted interactively: %v", err)
	}
}

func TestVerifyDownloadWithoutOwnKeySkipsPinButVerifies(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	pub, priv := signingPair(t)
	ct := randKey(t, 512)
	edSig, mlSig := signCiphertext(t, priv, ct)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), ownerDownload(pub, edSig, mlSig), nil); err != nil {
		t.Fatalf("pin-less verify failed: %v", err)
	}

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 1
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), ownerDownload(pub, edSig, mlSig), nil); err == nil {
		t.Fatal("pin-less path skipped signature verification entirely")
	}
}

func TestVerifyDownloadOwnerFieldErrors(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	pub, priv := signingPair(t)
	ct := []byte("payload")
	edSig, mlSig := signCiphertext(t, priv, ct)
	base := func() *api.DownloadResult { return ownerDownload(pub, edSig, mlSig) }

	blank := []struct {
		mutate func(*api.DownloadResult)
		want   string
	}{
		{func(d *api.DownloadResult) { d.SignatureEd25519 = "" }, "signature_ed25519_missing"},
		{func(d *api.DownloadResult) { d.SignatureMldsa = "" }, "signature_mldsa_missing"},
		{func(d *api.DownloadResult) { d.SigningPkEd25519 = "" }, "signing_pk_ed25519_missing"},
		{func(d *api.DownloadResult) { d.SigningPkMldsa = "" }, "signing_pk_mldsa_missing"},
		{func(d *api.DownloadResult) { d.SignatureEd25519 = "!bad!" }, "signature_ed25519_invalid"},
		{func(d *api.DownloadResult) { d.SigningPkMldsa = "!bad!" }, "signing_pk_mldsa_invalid"},
		{func(d *api.DownloadResult) { d.SigningPkEd25519 = b64(randKey(t, 5)) }, "signing_public_key_wrong_size"},
		{func(d *api.DownloadResult) { d.SigningPkMldsa = b64(randKey(t, 7)) }, "signing_public_key_wrong_size"},
	}
	for _, c := range blank {
		dl := base()
		c.mutate(dl)
		err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("want %s, got %v", c.want, err)
		}
	}
}

func TestVerifyDownloadStrictANDRejectsMixedSignatures(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	pub, priv := signingPair(t)
	_, otherPriv := signingPair(t)
	ct := randKey(t, 1024)
	edSig, mlSig := signCiphertext(t, priv, ct)
	_, otherMl := signCiphertext(t, otherPriv, ct)
	otherEd, _ := signCiphertext(t, otherPriv, ct)

	dl := ownerDownload(pub, edSig, otherMl)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv); err == nil {
		t.Error("wrong ML-DSA signature accepted")
	}
	dl = ownerDownload(pub, otherEd, mlSig)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv); err == nil {
		t.Error("wrong Ed25519 signature accepted")
	}
}

func TestProperty_VerifyDownloadRoundTripAndTamperRejection(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	pub, priv := signingPair(t)
	for i := range 200 {
		n := 1 + i*17%4096
		ct := make([]byte, n)
		if _, err := rand.Read(ct); err != nil {
			t.Fatal(err)
		}
		edSig, mlSig := signCiphertext(t, priv, ct)
		dl := ownerDownload(pub, edSig, mlSig)

		if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv); err != nil {
			t.Fatalf("iter %d: valid signature rejected: %v", i, err)
		}

		tampered := append([]byte(nil), ct...)
		var pos [4]byte
		rand.Read(pos[:])
		idx := int(uint32(pos[0])|uint32(pos[1])<<8|uint32(pos[2])<<16) % len(tampered)
		tampered[idx] ^= 1 << (pos[3] % 8)
		if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), dl, priv); err == nil {
			t.Fatalf("iter %d: bit flip at %d not detected", i, idx)
		}
	}
}

func TestVerifyDownloadForeignSignerNamed(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t)

	_, ownPriv := signingPair(t)
	peerPub, peerPriv := signingPair(t)
	ct := []byte("share recipient's upload")
	edSig, mlSig := signCiphertext(t, peerPriv, ct)
	dl := ownerDownload(peerPub, edSig, mlSig)
	dl.SignedBy = "mallory"

	err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv)
	if err == nil || !IsPeerPinFailure(err) || !strings.Contains(err.Error(), "mallory") {
		t.Fatalf("named foreign signer: %v", err)
	}
}

func TestVerifyDownloadTrustsPinnedRotationKey(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()

	oldPub, oldPriv := signingPair(t)
	_, curPriv := signingPair(t)
	ct := []byte("pre-rotation file")
	edSig, mlSig := signCiphertext(t, oldPriv, ct)
	dl := ownerDownload(oldPub, edSig, mlSig)

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, curPriv); err == nil {
		t.Fatal("unpinned old key accepted")
	}
	rememberSigningEdPub(oldPub.Ed25519[:])
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, curPriv); err != nil {
		t.Fatalf("pinned rotation key rejected: %v", err)
	}
}

type signatureVector struct {
	SigningPub struct {
		Ed25519 string `json:"ed25519_b64"`
		Mldsa   string `json:"mldsa44_b64"`
	} `json:"signing_pub"`
	Ciphertext string `json:"ciphertext_b64"`
	Owner      struct {
		SigEd string `json:"sig_ed25519_b64"`
		SigMl string `json:"sig_mldsa44_b64"`
	} `json:"owner"`
	TEE struct {
		SigEd string `json:"sig_ed25519_b64"`
		SigMl string `json:"sig_mldsa44_b64"`
	} `json:"tee"`
}

func loadSignatureVector(t *testing.T) (*signatureVector, []byte) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", "file_signature_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("vector: %v", err)
	}
	var v signatureVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	ct, err := base64.StdEncoding.DecodeString(v.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return &v, ct
}

func TestVerifyDownloadTEEHappyPathFromVector(t *testing.T) {
	withIsolatedPinStore(t)
	v, ct := loadSignatureVector(t)
	pinTeeKey(t, v.SigningPub.Ed25519, v.SigningPub.Mldsa)
	dl := &api.DownloadResult{
		TEESignatureEd25519: v.TEE.SigEd,
		TEESignatureMldsa:   v.TEE.SigMl,
		TEESigningPkEd25519: v.SigningPub.Ed25519,
		TEESigningPkMldsa:   v.SigningPub.Mldsa,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil); err != nil {
		t.Fatalf("vector TEE signatures rejected: %v", err)
	}

	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 1
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), dl, nil); err == nil {
		t.Fatal("tampered TEE download accepted")
	}
}

func TestVerifyDownloadOwnerHappyPathFromVector(t *testing.T) {
	isolateKeyEnv(t)
	v, ct := loadSignatureVector(t)
	dl := &api.DownloadResult{
		SignatureEd25519: v.Owner.SigEd,
		SignatureMldsa:   v.Owner.SigMl,
		SigningPkEd25519: v.SigningPub.Ed25519,
		SigningPkMldsa:   v.SigningPub.Mldsa,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil); err != nil {
		t.Fatalf("vector owner signatures rejected: %v", err)
	}
}

func TestVerifyDownloadDomainSeparation(t *testing.T) {
	withIsolatedPinStore(t)
	v, ct := loadSignatureVector(t)
	pinTeeKey(t, v.SigningPub.Ed25519, v.SigningPub.Mldsa)

	asTEE := &api.DownloadResult{
		TEESignatureEd25519: v.Owner.SigEd,
		TEESignatureMldsa:   v.Owner.SigMl,
		TEESigningPkEd25519: v.SigningPub.Ed25519,
		TEESigningPkMldsa:   v.SigningPub.Mldsa,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), asTEE, nil); err == nil {
		t.Fatal("owner-domain signatures verified under the TEE domain")
	}

	asOwner := &api.DownloadResult{
		SignatureEd25519: v.TEE.SigEd,
		SignatureMldsa:   v.TEE.SigMl,
		SigningPkEd25519: v.SigningPub.Ed25519,
		SigningPkMldsa:   v.SigningPub.Mldsa,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), asOwner, nil); err == nil {
		t.Fatal("TEE-domain signatures verified under the owner domain")
	}
}

func TestVerifyDownloadTEEFieldErrors(t *testing.T) {
	withIsolatedPinStore(t)
	v, ct := loadSignatureVector(t)
	pinTeeKey(t, v.SigningPub.Ed25519, v.SigningPub.Mldsa)
	base := func() *api.DownloadResult {
		return &api.DownloadResult{
			TEESignatureEd25519: v.TEE.SigEd,
			TEESignatureMldsa:   v.TEE.SigMl,
			TEESigningPkEd25519: v.SigningPub.Ed25519,
			TEESigningPkMldsa:   v.SigningPub.Mldsa,
		}
	}
	cases := []struct {
		mutate func(*api.DownloadResult)
		want   string
	}{
		{func(d *api.DownloadResult) { d.TEESignatureMldsa = "" }, "tee_signature_mldsa_missing"},
		{func(d *api.DownloadResult) { d.TEESigningPkEd25519 = "" }, "tee_signing_pk_ed25519_missing"},
		{func(d *api.DownloadResult) { d.TEESigningPkEd25519 = b64(randKey(t, 3)) }, "tee_signing_public_key_wrong_size"},
	}
	for _, c := range cases {
		dl := base()
		c.mutate(dl)
		err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil)
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("want %s, got %v", c.want, err)
		}
	}
}

func buildHistoryBlob(t *testing.T, signWith *crypto.SigningPrivateKeySet, eds ...[]byte) []byte {
	t.Helper()
	input := []byte(signingPkHistoryDomain)
	var edB64 []string
	for _, e := range eds {
		input = append(input, e...)
		edB64 = append(edB64, b64(e))
	}
	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(signWith.Mldsa); err != nil {
		t.Fatal(err)
	}
	sigMl := make([]byte, crypto.Mldsa44SigSize)
	if err := mldsa44.SignTo(&mlPriv, input, nil, false, sigMl); err != nil {
		t.Fatal(err)
	}
	blob := signingPkHistoryBlob{
		V:     1,
		Eds:   edB64,
		SigEd: b64(ed25519.Sign(signWith.Ed25519, input)),
		SigMl: b64(sigMl),
	}
	raw, err := json.Marshal(blob)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifySigningPkHistory(t *testing.T) {
	pub, priv := signingPair(t)
	edPub := pub.Ed25519[:]
	mldsaPub := pub.Mldsa
	oldKey := randKey(t, ed25519.PublicKeySize)

	valid := buildHistoryBlob(t, priv, oldKey, edPub)
	got := verifySigningPkHistory(valid, edPub, mldsaPub)
	if len(got) != 2 || !bytes.Equal(got[0], oldKey) || !bytes.Equal(got[1], edPub) {
		t.Fatalf("valid blob: %v", got)
	}

	if verifySigningPkHistory(valid, randKey(t, ed25519.PublicKeySize), mldsaPub) != nil {
		t.Error("blob verified against the wrong ed25519 anchor key")
	}
	if verifySigningPkHistory(valid, edPub, nil) != nil {
		t.Error("blob verified with no ML-DSA anchor")
	}
	wrongMl := append([]byte(nil), mldsaPub...)
	wrongMl[0] ^= 0x01
	if verifySigningPkHistory(valid, edPub, wrongMl) != nil {
		t.Error("blob verified against the wrong ML-DSA anchor key")
	}
	if verifySigningPkHistory([]byte("not json"), edPub, mldsaPub) != nil {
		t.Error("garbage blob accepted")
	}

	var blob signingPkHistoryBlob
	json.Unmarshal(valid, &blob)
	blob.V = 2
	raw, _ := json.Marshal(blob)
	if verifySigningPkHistory(raw, edPub, mldsaPub) != nil {
		t.Error("unknown version accepted")
	}

	json.Unmarshal(valid, &blob)
	blob.Eds = append(blob.Eds, b64(randKey(t, ed25519.PublicKeySize)))
	raw, _ = json.Marshal(blob)
	if verifySigningPkHistory(raw, edPub, mldsaPub) != nil {
		t.Error("extended key list accepted under the old signature")
	}

	json.Unmarshal(valid, &blob)
	blob.Eds[0] = "!!not-b64!!"
	raw, _ = json.Marshal(blob)
	if verifySigningPkHistory(raw, edPub, mldsaPub) != nil {
		t.Error("undecodable key entry accepted")
	}

	json.Unmarshal(valid, &blob)
	sm, _ := base64.StdEncoding.DecodeString(blob.SigMl)
	sm[0] ^= 0x01
	blob.SigMl = base64.StdEncoding.EncodeToString(sm)
	raw, _ = json.Marshal(blob)
	if verifySigningPkHistory(raw, edPub, mldsaPub) != nil {
		t.Error("tampered ML-DSA signature accepted")
	}
}

func TestSeedOwnSigningPkHistoryEndToEnd(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	oldPub, oldPriv := signingPair(t)
	curPub, curPriv := signingPair(t)

	blob := buildHistoryBlob(t, curPriv, oldPub.Ed25519[:], curPub.Ed25519[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"signing_pk_history":%q}`, b64(blob))
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "seed-test"

	resetOwnSigningHistorySeed()
	t.Cleanup(neutralizeHistorySeed)

	ct := []byte("file signed before the rotation")
	edSig, mlSig := signCiphertext(t, oldPriv, ct)
	dl := ownerDownload(oldPub, edSig, mlSig)

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, curPriv); err != nil {
		t.Fatalf("history-seeded key still untrusted: %v", err)
	}
	if !signingEdPubTrusted(oldPub.Ed25519[:]) {
		t.Error("old key not pinned after the seed")
	}
}

func TestSeedOwnSigningPkHistoryRejectsForgedBlob(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	evilPub, evilPriv := signingPair(t)
	_, curPriv := signingPair(t)

	blob := buildHistoryBlob(t, evilPriv, evilPub.Ed25519[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"signing_pk_history":%q}`, b64(blob))
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "seed-test"

	resetOwnSigningHistorySeed()
	t.Cleanup(neutralizeHistorySeed)

	ct := []byte("attacker file")
	edSig, mlSig := signCiphertext(t, evilPriv, ct)
	dl := ownerDownload(evilPub, edSig, mlSig)

	err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, curPriv)
	if err == nil || err.Error() != "owner_signing_pk_untrusted" {
		t.Fatalf("forged history blob smuggled a key: %v", err)
	}
	if signingEdPubTrusted(evilPub.Ed25519[:]) {
		t.Error("forged key landed in the trust set")
	}
}

func signTEECiphertext(t *testing.T, priv *crypto.SigningPrivateKeySet, ct []byte) (string, string) {
	t.Helper()
	digest := sha256.Sum256(ct)
	input := append([]byte(crypto.TEESignatureDomain), digest[:]...)
	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(priv.Mldsa); err != nil {
		t.Fatal(err)
	}
	mlSig := make([]byte, crypto.Mldsa44SigSize)
	if err := mldsa44.SignTo(&mlPriv, input, nil, false, mlSig); err != nil {
		t.Fatal(err)
	}
	return b64(ed25519.Sign(priv.Ed25519, input)), b64(mlSig)
}

func teeDownload(pub *crypto.SigningPublicKeySet, edSig, mlSig string) *api.DownloadResult {
	return &api.DownloadResult{
		TEESignatureEd25519: edSig,
		TEESignatureMldsa:   mlSig,
		TEESigningPkEd25519: b64(pub.Ed25519[:]),
		TEESigningPkMldsa:   b64(pub.Mldsa),
	}
}

func TestServerCannotPickTheTeeFamilyToSkipTheOwnKeyPin(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()

	ownPub, ownPriv := signingPair(t)
	ct := []byte("a file the user signed with their own key")
	edSig, mlSig := signCiphertext(t, ownPriv, ct)

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), ownerDownload(ownPub, edSig, mlSig), ownPriv); err != nil {
		t.Fatalf("honest owner-signed download rejected: %v", err)
	}

	evilPub, evilPriv := signingPair(t)
	teeEd, teeMl := signTEECiphertext(t, evilPriv, ct)

	forged := teeDownload(evilPub, teeEd, teeMl)
	err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), forged, ownPriv)
	if err == nil {
		t.Fatal("a self-signed TEE bundle was accepted: the TEE branch verifies a served key against itself")
	}
	if !strings.Contains(err.Error(), "tee_signing_pk") {
		t.Errorf("TEE refusal should name the key, got %v", err)
	}

	both := ownerDownload(ownPub, edSig, mlSig)
	both.TEESignatureEd25519 = teeEd
	both.TEESignatureMldsa = teeMl
	both.TEESigningPkEd25519 = b64(evilPub.Ed25519[:])
	both.TEESigningPkMldsa = b64(evilPub.Mldsa)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), both, ownPriv); err != nil {
		t.Fatalf("owner family present but not used: %v", err)
	}
	if teeSigningPkPinned() {
		t.Error("the attacker's TEE key was pinned off a response that never needed the TEE branch")
	}
}

func pinTeeKey(t *testing.T, edB64, mlB64 string) {
	t.Helper()
	recordTeeSigningPk(edB64, mlB64)
	if !teeSigningPkPinned() {
		t.Fatal("pin fixture did not take; the test would prove nothing")
	}
}

func resetTeeAttestationCache(t *testing.T) {
	t.Helper()
	teeSigningAttMu.Lock()
	teeSigningAtt = nil
	teeSigningAttNextTry = time.Time{}
	teeSigningAttMu.Unlock()
	t.Cleanup(func() {
		teeSigningAttMu.Lock()
		teeSigningAtt = nil
		teeSigningAttNextTry = time.Time{}
		teeSigningAttMu.Unlock()
	})
}

func serveAttestation(t *testing.T, edB64, mlB64 string) *int32 {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"enabled":true,"available":true,"attestation":{"enclave_signing_pk_ed25519":%q,"enclave_signing_pk_mldsa":%q,"attestation_mode":"none","verification_status":"unverified"}}`, edB64, mlB64)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "att-test"
	return &calls
}

func TestTeeSigningKeyIsAttestedOnceThenPinned(t *testing.T) {
	withIsolatedPinStore(t)
	resetTeeAttestationCache(t)
	v, ct := loadSignatureVector(t)

	calls := serveAttestation(t, v.SigningPub.Ed25519, v.SigningPub.Mldsa)
	dl := &api.DownloadResult{
		TEESignatureEd25519: v.TEE.SigEd,
		TEESignatureMldsa:   v.TEE.SigMl,
		TEESigningPkEd25519: v.SigningPub.Ed25519,
		TEESigningPkMldsa:   v.SigningPub.Mldsa,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil); err != nil {
		t.Fatalf("attested enclave key rejected on first contact: %v", err)
	}
	if !teeSigningPkPinned() {
		t.Fatal("first attested contact did not pin the enclave key")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("attestation asked %d times on first contact, want 1", got)
	}

	_, evilPriv := signingPair(t)
	evilPub, err := crypto.DeriveSigningPublic(evilPriv)
	if err != nil {
		t.Fatal(err)
	}
	teeEd, teeMl := signTEECiphertext(t, evilPriv, ct)
	teeSigningAttMu.Lock()
	teeSigningAtt = nil
	teeSigningAttNextTry = time.Time{}
	teeSigningAttMu.Unlock()
	serveAttestation(t, b64(evilPub.Ed25519[:]), b64(evilPub.Mldsa))

	rotated := teeDownload(evilPub, teeEd, teeMl)
	err = VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), rotated, nil)
	if err == nil || !strings.Contains(err.Error(), "tee_signing_pk_changed") {
		t.Fatalf("a re-attested enclave key overrode the pin: %v", err)
	}

	config.Get().Endpoint = "http://127.0.0.1:1"
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil); err != nil {
		t.Errorf("a pinned enclave key needs the network: %v", err)
	}
}

func TestUnattestedTeeKeyIsRefusedButRetryable(t *testing.T) {
	withIsolatedPinStore(t)
	resetTeeAttestationCache(t)
	v, ct := loadSignatureVector(t)
	config.Get().Endpoint = "http://127.0.0.1:1"

	dl := &api.DownloadResult{
		TEESignatureEd25519: v.TEE.SigEd,
		TEESignatureMldsa:   v.TEE.SigMl,
		TEESigningPkEd25519: v.SigningPub.Ed25519,
		TEESigningPkMldsa:   v.SigningPub.Mldsa,
	}
	err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil)
	if err == nil {
		t.Fatal("an enclave key nothing vouches for was accepted")
	}
	if !IsTeeAttestationUnavailable(err) {
		t.Fatalf("unattested refusal is not the retryable kind: %v", err)
	}
	if teeSigningPkPinned() {
		t.Error("an unattested key was pinned anyway")
	}
}

func TestServedTeeKeyMustMatchTheAttestedOne(t *testing.T) {
	withIsolatedPinStore(t)
	resetTeeAttestationCache(t)
	v, ct := loadSignatureVector(t)
	serveAttestation(t, v.SigningPub.Ed25519, v.SigningPub.Mldsa)

	_, evilPriv := signingPair(t)
	evilPub, err := crypto.DeriveSigningPublic(evilPriv)
	if err != nil {
		t.Fatal(err)
	}
	teeEd, teeMl := signTEECiphertext(t, evilPriv, ct)

	err = VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), teeDownload(evilPub, teeEd, teeMl), nil)
	if err == nil || !strings.Contains(err.Error(), "tee_signing_pk_untrusted") {
		t.Fatalf("a key the enclave never attested was accepted: %v", err)
	}
	if teeSigningPkPinned() {
		t.Error("the unattested key was pinned")
	}

	dl := &api.DownloadResult{
		TEESignatureEd25519: v.TEE.SigEd,
		TEESignatureMldsa:   v.TEE.SigMl,
		TEESigningPkEd25519: v.SigningPub.Ed25519,
		TEESigningPkMldsa:   v.SigningPub.Mldsa,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil); err != nil {
		t.Fatalf("attested enclave key rejected: %v", err)
	}
}

func TestAFailedTeeVerifyLeavesNoPin(t *testing.T) {
	withIsolatedPinStore(t)
	resetTeeAttestationCache(t)
	v, ct := loadSignatureVector(t)
	serveAttestation(t, v.SigningPub.Ed25519, v.SigningPub.Mldsa)

	dl := &api.DownloadResult{
		TEESignatureEd25519: v.TEE.SigEd,
		TEESignatureMldsa:   v.TEE.SigMl,
		TEESigningPkEd25519: v.SigningPub.Ed25519,
		TEESigningPkMldsa:   v.SigningPub.Mldsa,
	}
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 1
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), dl, nil); err == nil {
		t.Fatal("tampered TEE download accepted")
	}
	if teeSigningPkPinned() {
		t.Fatal("a key was pinned off a response whose signatures did not verify")
	}

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, nil); err != nil {
		t.Fatalf("clean download rejected: %v", err)
	}
	if !teeSigningPkPinned() {
		t.Error("a verified download left no pin")
	}
}
