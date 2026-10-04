package e2ee

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
)

type PeerPinError struct {
	Reason string
	Peer   string
}

func (e *PeerPinError) Error() string {
	return fmt.Sprintf("%s: file signed by %q", e.Reason, e.Peer)
}

func IsPeerPinFailure(err error) bool {
	var p *PeerPinError
	return errors.As(err, &p)
}

const peerSigningPinVersion = 1

const maxPeerNameLen = 64

var peerSigningPins = ownerSidecar[map[string]string]{name: "peer_signing_pks.json", version: peerSigningPinVersion}

func validPeerName(peer string) bool {
	if peer == "" || len(peer) > maxPeerNameLen {
		return false
	}
	for _, r := range peer {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return !strings.ContainsAny(peer, "/\\")
}

func peerSigningPkSeen(peer string) (string, bool) {
	owner := signingPinOwner()
	if owner == "" || !validPeerName(peer) {
		return "", false
	}
	bucket := peerSigningPins.load().Owners[owner]
	if bucket == nil {
		return "", false
	}
	v, ok := bucket[peer]
	return v, ok
}

func recordPeerSigningPk(peer, edB64 string) {
	owner := signingPinOwner()
	if peerSigningPins.path() == "" || owner == "" || !validPeerName(peer) {
		return
	}
	f := peerSigningPins.load()
	if f.Owners[owner] == nil {
		f.Owners[owner] = map[string]string{}
	}
	f.Owners[owner][peer] = edB64
	_ = peerSigningPins.store(f)
}

func PeerSigningPinCount() int {
	owner := signingPinOwner()
	if owner == "" {
		return 0
	}
	return len(peerSigningPins.load().Owners[owner])
}

var (
	friendSetMu      sync.Mutex
	friendSet        map[string]bool
	friendSetAt      time.Time
	friendSetNextTry time.Time
	friendSetRetryAfter = time.Minute
	friendSetTTL = 5 * time.Minute
)

func peerHasFriendEdge(peer string) bool {
	friendSetMu.Lock()
	defer friendSetMu.Unlock()

	if friendSet != nil && time.Since(friendSetAt) < friendSetTTL {
		return friendSet[peer]
	}
	if time.Now().Before(friendSetNextTry) {
		return friendSet[peer]
	}
	friendSetNextTry = time.Now().Add(friendSetRetryAfter)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := api.NewClient().Execute(ctx, "fr", map[string]string{"mode": "list"})
	if err != nil || resp == nil || !resp.Success {
		return friendSet[peer]
	}
	var payload api.FriendListPayload
	if json.Unmarshal(resp.Raw, &payload) != nil {
		return friendSet[peer]
	}
	set := make(map[string]bool, len(payload.Friends))
	for _, f := range payload.Friends {
		if f.Username != "" {
			set[f.Username] = true
		}
	}
	friendSet = set
	friendSetAt = time.Now()
	return friendSet[peer]
}

func checkForeignSignerOnOwnNode(signedBy string, servedEd []byte) (func(), error) {
	noop := func() {}
	if !validPeerName(signedBy) {
		return noop, &PeerPinError{Reason: "owner_signing_pk_untrusted", Peer: signedBy}
	}
	servedB64 := base64.StdEncoding.EncodeToString(servedEd)
	seen, haveRecord := peerSigningPkSeen(signedBy)

	if !haveRecord {
		if !peerHasFriendEdge(signedBy) {
			return noop, &PeerPinError{Reason: "owner_signing_pk_untrusted", Peer: signedBy}
		}
		return func() { recordPeerSigningPk(signedBy, servedB64) }, nil
	}
	if seen != servedB64 {
		return noop, &PeerPinError{Reason: "owner_signing_pk_changed", Peer: signedBy}
	}
	return noop, nil
}
