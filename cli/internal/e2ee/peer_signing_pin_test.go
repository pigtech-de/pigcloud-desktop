package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func resetFriendCache(t *testing.T) {
	t.Helper()
	friendSetMu.Lock()
	friendSet = nil
	friendSetAt = time.Time{}
	friendSetNextTry = time.Time{}
	friendSetMu.Unlock()
	t.Cleanup(func() {
		friendSetMu.Lock()
		friendSet = nil
		friendSetAt = time.Time{}
		friendSetNextTry = time.Time{}
		friendSetMu.Unlock()
	})
}

func serveFriendList(t *testing.T, usernames ...string) *int32 {
	t.Helper()
	var calls int32
	friends := make([]map[string]string, 0, len(usernames))
	for _, u := range usernames {
		friends = append(friends, map[string]string{"username": u})
	}
	body, err := json.Marshal(map[string]any{"success": true, "friends": friends})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "peer-pin-test"
	return &calls
}

func peerSignedDownload(t *testing.T, peer string, pub *crypto.SigningPublicKeySet, ct []byte, priv *crypto.SigningPrivateKeySet) *api.DownloadResult {
	t.Helper()
	edSig, mlSig := signCiphertext(t, priv, ct)
	dl := ownerDownload(pub, edSig, mlSig)
	dl.SignedBy = peer
	return dl
}

func TestPeerPinRefusesUnfriendedSigner(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t)

	_, ownPriv := signingPair(t)
	peerPub, peerPriv := signingPair(t)
	ct := []byte("a stranger's upload into your folder")
	dl := peerSignedDownload(t, "mallory", peerPub, ct, peerPriv)

	err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv)
	if err == nil {
		t.Fatal("an unfriended peer's signing key was accepted")
	}
	if !IsPeerPinFailure(err) || !strings.Contains(err.Error(), "owner_signing_pk_untrusted") {
		t.Fatalf("want owner_signing_pk_untrusted peer-pin failure, got %v", err)
	}
	if _, seen := peerSigningPkSeen("mallory"); seen {
		t.Error("a refused signer was still written to the pin sidecar")
	}
	if n := PeerSigningPinCount(); n != 0 {
		t.Errorf("pin count = %d after a refusal, want 0", n)
	}
}

func TestPeerPinFriendFirstSeenWins(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	calls := serveFriendList(t, "bob")

	_, ownPriv := signingPair(t)
	bobPub, bobPriv := signingPair(t)
	ct := []byte("bob's upload into your shared folder")
	dl := peerSignedDownload(t, "bob", bobPub, ct, bobPriv)

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv); err != nil {
		t.Fatalf("a friend's signed upload was rejected: %v", err)
	}
	pinned, seen := peerSigningPkSeen("bob")
	if !seen || pinned != b64(bobPub.Ed25519[:]) {
		t.Fatalf("friend's key not pinned: seen=%v pinned=%q", seen, pinned)
	}

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv); err != nil {
		t.Fatalf("pinned peer key rejected on re-verify: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Errorf("friend list fetched %d times, want 1 (per-file fetches drain the cli bucket)", got)
	}

	evilPub, evilPriv := signingPair(t)
	swapped := peerSignedDownload(t, "bob", evilPub, ct, evilPriv)
	err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), swapped, ownPriv)
	if err == nil || !strings.Contains(err.Error(), "owner_signing_pk_changed") {
		t.Fatalf("a swapped peer key was accepted: %v", err)
	}
	if now, _ := peerSigningPkSeen("bob"); now != pinned {
		t.Error("the refused key overwrote the first-seen pin")
	}
}

func TestPeerPinRecordSurvivesUnfriend(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t)

	_, ownPriv := signingPair(t)
	bobPub, bobPriv := signingPair(t)
	ct := []byte("uploaded back when you were friends")
	recordPeerSigningPk("bob", b64(bobPub.Ed25519[:]))

	dl := peerSignedDownload(t, "bob", bobPub, ct, bobPriv)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv); err != nil {
		t.Fatalf("unfriending bricked a file already in your own tree: %v", err)
	}

	otherPub, otherPriv := signingPair(t)
	swapped := peerSignedDownload(t, "bob", otherPub, ct, otherPriv)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), swapped, ownPriv); err == nil {
		t.Fatal("a record from a dead friendship accepted a different key")
	}
}

func TestPeerPinDoesNotReplaceSignatureCheck(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t, "bob")

	_, ownPriv := signingPair(t)
	bobPub, bobPriv := signingPair(t)
	ct := []byte("bob's upload into your shared folder")
	dl := peerSignedDownload(t, "bob", bobPub, ct, bobPriv)

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 1
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), dl, ownPriv); err == nil {
		t.Fatal("a passing peer pin let forged bytes through unverified")
	}
}

func TestPeerPinRecordsOnlyAfterTheSignatureVerifies(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t, "bob")

	_, ownPriv := signingPair(t)
	evilPub, evilPriv := signingPair(t)
	ct := []byte("bob's upload into your shared folder")
	dl := peerSignedDownload(t, "bob", evilPub, ct, evilPriv)

	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 1
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), dl, ownPriv); err == nil {
		t.Fatal("forged bytes accepted")
	}
	if _, seen := peerSigningPkSeen("bob"); seen {
		t.Fatal("a key whose signature failed was pinned; bob's real files are refused from now on")
	}

	realPub, realPriv := signingPair(t)
	good := peerSignedDownload(t, "bob", realPub, ct, realPriv)
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), good, ownPriv); err != nil {
		t.Fatalf("genuine upload rejected: %v", err)
	}
	if pinned, _ := peerSigningPkSeen("bob"); pinned != b64(realPub.Ed25519[:]) {
		t.Errorf("pinned %q, want the key that actually verified", pinned)
	}
}

func TestPeerPinRejectsHostileSignerNames(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t, "bob")

	for _, name := range []string{"../../etc/passwd", "bob\n", strings.Repeat("a", maxPeerNameLen+1), ""} {
		if validPeerName(name) {
			t.Errorf("validPeerName(%q) = true", name)
		}
		if _, err := checkForeignSignerOnOwnNode(name, []byte("k")); err == nil {
			t.Errorf("checkForeignSignerOnOwnNode(%q) accepted", name)
		}
	}
	if n := PeerSigningPinCount(); n != 0 {
		t.Errorf("hostile names wrote %d sidecar entries", n)
	}
}

func TestPeerPinRefusesWhenFriendListUnreachable(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `{"success":false,"message":"upstream down"}`)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "peer-pin-test"

	for range 3 {
		if _, err := checkForeignSignerOnOwnNode("bob", []byte("served-key")); err == nil {
			t.Fatal("an unreachable friend list granted trust")
		}
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("friend list re-fetched %d times inside the cooldown, want 1", got)
	}
}

func TestIsPeerPinFailureClassification(t *testing.T) {
	pin := &PeerPinError{Reason: "owner_signing_pk_untrusted", Peer: "bob"}
	if !IsPeerPinFailure(fmt.Errorf("verify x: %w", pin)) {
		t.Error("peer-pin failure lost through fmt.Errorf")
	}
	if IsPeerPinFailure(errors.New("owner_signing_pk_untrusted")) {
		t.Error("the no-signer own-key refusal was classified as a peer pin")
	}
	if IsPeerPinFailure(nil) {
		t.Error("nil classified as a peer-pin failure")
	}
}

func TestPeerPinCorruptSidecarRepins(t *testing.T) {
	withIsolatedPinStore(t)
	neutralizeHistorySeed()
	resetFriendCache(t)
	serveFriendList(t, "bob")

	if err := os.WriteFile(peerSigningPins.path(), []byte("garbage-not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	_, ownPriv := signingPair(t)
	bobPub, bobPriv := signingPair(t)
	ct := []byte("still readable over a corrupt sidecar")
	dl := peerSignedDownload(t, "bob", bobPub, ct, bobPriv)

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv); err != nil {
		t.Fatalf("corrupt sidecar bricked a friend's file: %v", err)
	}
	if n := PeerSigningPinCount(); n != 1 {
		t.Errorf("corrupt sidecar not replaced by a real pin: count = %d", n)
	}
}
