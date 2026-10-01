package agent

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

type wantHex struct {
	fields map[string]string
}

func snapshotWant(keys *KeyMaterial) wantHex {
	return wantHex{fields: map[string]string{
		"PublicKey":                hex.EncodeToString(keys.PublicKey[:]),
		"PrivateKey":               hex.EncodeToString(keys.PrivateKey[:]),
		"KyberPublicKey":           hex.EncodeToString(keys.KyberPublicKey),
		"KyberSeed":                hex.EncodeToString(keys.KyberSeed),
		"NameKey":                  hex.EncodeToString(keys.NameKey),
		"SigningPublicKeyEd25519":  hex.EncodeToString(keys.SigningPublicKeyEd25519),
		"SigningPrivateKeyEd25519": hex.EncodeToString(keys.SigningPrivateKeyEd25519),
		"SigningPublicKeyMldsa":    hex.EncodeToString(keys.SigningPublicKeyMldsa),
		"SigningPrivateKeyMldsa":   hex.EncodeToString(keys.SigningPrivateKeyMldsa),
	}}
}

func (w wantHex) mismatches(resp *Response) []string {
	got := map[string]string{
		"PublicKey":                resp.PublicKey,
		"PrivateKey":               resp.PrivateKey,
		"KyberPublicKey":           resp.KyberPublicKey,
		"KyberSeed":                resp.KyberSeed,
		"NameKey":                  resp.NameKey,
		"SigningPublicKeyEd25519":  resp.SigningPublicKeyEd25519,
		"SigningPrivateKeyEd25519": resp.SigningPrivateKeyEd25519,
		"SigningPublicKeyMldsa":    resp.SigningPublicKeyMldsa,
		"SigningPrivateKeyMldsa":   resp.SigningPrivateKeyMldsa,
	}
	var bad []string
	for name, want := range w.fields {
		if got[name] != want {
			bad = append(bad, name)
		}
	}
	return bad
}

func TestKeysRequestOverlappingExpiryIsAllOrNothing(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	want := snapshotWant(keys)

	done := serveInBackground(t, keys, 400*time.Millisecond)
	info := waitForAgent(t)

	var (
		mu       sync.Mutex
		served   int
		refused  int
		partials []string
	)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := sendRequest(info, "keys")
				mu.Lock()
				switch {
				case err != nil || resp == nil || !resp.OK:
					refused++
				default:
					served++
					if bad := want.mismatches(resp); len(bad) > 0 {
						partials = append(partials, bad...)
					}
				}
				mu.Unlock()
			}
		})
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(stop)
		wg.Wait()
		t.Fatal("Serve did not return after its TTL elapsed")
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if served == 0 {
		t.Fatal("no keys request succeeded before expiry; the all-or-nothing assertion would be vacuous")
	}
	if refused == 0 {
		t.Fatal("no keys request was refused after expiry; the requests never crossed the wipe")
	}
	if len(partials) > 0 {
		t.Errorf("agent served corrupted key material on %d field(s) across the TTL wipe: %v",
			len(partials), partials)
	}
}

func TestKeysRequestAfterTheWipeIsRefusedWithoutMaterial(t *testing.T) {
	keys := testKeys(t)
	before := snapshotWant(keys)

	guard := newKeyGuard(keys)
	guard.wipe()

	timer := time.NewTimer(time.Hour)
	t.Cleanup(func() { timer.Stop() })

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	go handleConn(server, guard, fixtureToken, timer, func(string) {})

	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(client, `{"token":"`+fixtureToken+`","action":"keys"}`); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var raw json.RawMessage
	if err := json.NewDecoder(client).Decode(&raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response %s: %v", raw, err)
	}

	if resp.OK {
		t.Error("agent served keys after its material was wiped")
	}
	if resp.Error == "" {
		t.Error("a refused keys request carried no error for the client to fail closed on")
	}
	assertNoKeyFields(t, "post-wipe keys request", resp)

	for name, hexVal := range before.fields {
		if hexVal == "" {
			continue
		}
		if bytes.Contains(raw, []byte(hexVal)) {
			t.Errorf("post-wipe response leaked %s", name)
		}
	}
}

func TestWipeZeroesEverySecretAndSparesThePublicHalves(t *testing.T) {
	keys := testKeys(t)
	wantPub := keys.PublicKey
	wantKyberPub := append([]byte(nil), keys.KyberPublicKey...)

	newKeyGuard(keys).wipe()

	if keys.PrivateKey != ([32]byte{}) {
		t.Error("x25519 private key survived the wipe")
	}
	assertZeroed(t, "ml-kem seed", keys.KyberSeed)
	assertZeroed(t, "name key", keys.NameKey)
	assertZeroed(t, "ed25519 signing private key", keys.SigningPrivateKeyEd25519)
	assertZeroed(t, "ml-dsa signing private key", keys.SigningPrivateKeyMldsa)

	if keys.PublicKey != wantPub {
		t.Error("x25519 public key was wiped; only secret material should be zeroed")
	}
	if !bytes.Equal(keys.KyberPublicKey, wantKyberPub) {
		t.Error("ml-kem public key was wiped; only secret material should be zeroed")
	}
}

func TestHungConnectionDoesNotHoldTheAgentPastItsTTL(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	const ttl = 500 * time.Millisecond
	done := serveInBackground(t, keys, ttl)
	info := waitForAgent(t)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, `{"token":"`+info.Token+`","action":`); err != nil {
		t.Fatalf("send partial request: %v", err)
	}

	start := time.Now()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("a connection stalled mid-request kept the agent alive past its TTL")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("expiry waited %v on a hung connection; the TTL wipe must not depend on connection lifetime", elapsed)
	}
	if keys.PrivateKey != ([32]byte{}) {
		t.Error("a hung connection prevented the private key from being zeroed on expiry")
	}
}
