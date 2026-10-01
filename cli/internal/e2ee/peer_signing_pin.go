package e2ee

import (
	"context"
	"encoding/base64"
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
	"pigcloud/internal/fsutil"
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

func peerSigningPksPath() string {
	dir := config.Dir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "peer_signing_pks.json")
}

type peerSigningPksFile struct {
	V      int                          `json:"v"`
	Owners map[string]map[string]string `json:"owners"`
}

func loadPeerSigningPkFile() *peerSigningPksFile {
	empty := &peerSigningPksFile{V: peerSigningPinVersion, Owners: map[string]map[string]string{}}
	path := peerSigningPksPath()
	if path == "" {
		return empty
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return empty
	}
	var f peerSigningPksFile
	if json.Unmarshal(raw, &f) != nil || f.V != peerSigningPinVersion || f.Owners == nil {
		return empty
	}
	return &f
}

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
	bucket := loadPeerSigningPkFile().Owners[owner]
	if bucket == nil {
		return "", false
	}
	v, ok := bucket[peer]
	return v, ok
}

func recordPeerSigningPk(peer, edB64 string) {
	path := peerSigningPksPath()
	owner := signingPinOwner()
	if path == "" || owner == "" || !validPeerName(peer) {
		return
	}
	f := loadPeerSigningPkFile()
	if f.Owners[owner] == nil {
		f.Owners[owner] = map[string]string{}
	}
	f.Owners[owner][peer] = edB64
	data, err := json.Marshal(f)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0700)
	_ = fsutil.WriteFileAtomic(path, data, 0600)
}

func PeerSigningPinCount() int {
	owner := signingPinOwner()
	if owner == "" {
		return 0
	}
	return len(loadPeerSigningPkFile().Owners[owner])
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
