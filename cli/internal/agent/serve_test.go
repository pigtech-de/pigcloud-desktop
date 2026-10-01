package agent

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"pigcloud/internal/netutil"
)

func serveInBackground(t *testing.T, keys *KeyMaterial, ttl time.Duration) chan struct{} {
	t.Helper()
	ln, err := net.Listen("tcp", netutil.LoopbackAny)
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = serveListener(ln, keys, ttl)
	}()
	t.Cleanup(func() {
		_ = Shutdown()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("agent goroutine outlived the test; listener leaked")
		}
	})
	return done
}

func waitForAgent(t *testing.T) *AgentInfo {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info := ReadAgentFile(); info != nil && info.Port != 0 {
			return info
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("agent published no usable agent file within 5s")
	return nil
}

func assertZeroed(t *testing.T, label string, b []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Errorf("%s is empty; the wipe assertion would be vacuous", label)
		return
	}
	for i, v := range b {
		if v != 0 {
			t.Errorf("%s still holds a non-zero byte at offset %d after shutdown", label, i)
			return
		}
	}
}

func TestServeRevokesKeysWhenTheTTLExpires(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	wantPub := keys.PublicKey
	wantPriv := keys.PrivateKey
	wantSeed := append([]byte(nil), keys.KyberSeed...)
	wantName := append([]byte(nil), keys.NameKey...)

	done := serveInBackground(t, keys, 1500*time.Millisecond)
	info := waitForAgent(t)

	live := RequestKeys()
	if live == nil {
		t.Fatal("agent served no keys while its TTL was live")
	}
	if live.PrivateKey != wantPriv {
		t.Fatal("agent served the wrong private key")
	}
	if !bytes.Equal(live.KyberSeed, wantSeed) {
		t.Error("agent served the wrong ML-KEM seed")
	}
	if !bytes.Equal(live.NameKey, wantName) {
		t.Error("agent served the wrong name key")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after its TTL elapsed")
	}

	if got := ReadAgentFile(); got != nil {
		t.Error("agent file survived TTL expiry")
	}
	if RequestKeys() != nil {
		t.Error("agent still served keys after TTL expiry")
	}
	if Ping() {
		t.Error("agent still answered ping after TTL expiry")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(info.Port)), 2*time.Second)
	if err == nil {
		conn.Close()
		t.Errorf("port %d still accepts connections after TTL expiry", info.Port)
	}

	if keys.PrivateKey != ([32]byte{}) {
		t.Error("x25519 private key was not zeroed on expiry")
	}
	assertZeroed(t, "ml-kem seed", keys.KyberSeed)
	assertZeroed(t, "name key", keys.NameKey)
	assertZeroed(t, "ed25519 signing private key", keys.SigningPrivateKeyEd25519)
	assertZeroed(t, "ml-dsa signing private key", keys.SigningPrivateKeyMldsa)

	if keys.PublicKey != wantPub {
		t.Error("public key was wiped too; only secret material should be zeroed")
	}
}

func firstNonLoopbackIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if v4 := ipNet.IP.To4(); v4 != nil {
			return v4.String()
		}
	}
	return ""
}

func TestServeBindsLoopbackOnly(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	serveInBackground(t, keys, 30*time.Second)
	info := waitForAgent(t)
	port := strconv.Itoa(info.Port)

	loop, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
	if err != nil {
		t.Fatalf("agent unreachable on loopback: %v", err)
	}
	loop.Close()

	ip := firstNonLoopbackIPv4()
	if ip == "" {
		t.Skip("host has no non-loopback IPv4 address to probe from")
	}

	if conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 2*time.Second); err == nil {
		conn.Close()
		t.Fatalf("agent answered on %s:%s; the key agent must bind 127.0.0.1 only", ip, port)
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		t.Fatalf("cannot bind %s:%s while the agent runs, so the agent holds the wildcard address: %v", ip, port, err)
	}
	ln.Close()
}

func TestRequestKeysRoundTripsEveryField(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	want := *keys
	want.KyberPublicKey = append([]byte(nil), keys.KyberPublicKey...)
	want.KyberSeed = append([]byte(nil), keys.KyberSeed...)
	want.NameKey = append([]byte(nil), keys.NameKey...)
	want.SigningPublicKeyEd25519 = append([]byte(nil), keys.SigningPublicKeyEd25519...)
	want.SigningPrivateKeyEd25519 = append([]byte(nil), keys.SigningPrivateKeyEd25519...)
	want.SigningPublicKeyMldsa = append([]byte(nil), keys.SigningPublicKeyMldsa...)
	want.SigningPrivateKeyMldsa = append([]byte(nil), keys.SigningPrivateKeyMldsa...)

	serveInBackground(t, keys, 30*time.Second)
	waitForAgent(t)

	got := RequestKeys()
	if got == nil {
		t.Fatal("RequestKeys got nothing from a live agent")
	}
	if got.PublicKey != want.PublicKey {
		t.Error("x25519 public key did not round-trip")
	}
	if got.PrivateKey != want.PrivateKey {
		t.Error("x25519 private key did not round-trip")
	}
	for _, f := range []struct {
		label     string
		got, want []byte
	}{
		{"ml-kem public key", got.KyberPublicKey, want.KyberPublicKey},
		{"ml-kem seed", got.KyberSeed, want.KyberSeed},
		{"name key", got.NameKey, want.NameKey},
		{"ed25519 signing public key", got.SigningPublicKeyEd25519, want.SigningPublicKeyEd25519},
		{"ed25519 signing private key", got.SigningPrivateKeyEd25519, want.SigningPrivateKeyEd25519},
		{"ml-dsa signing public key", got.SigningPublicKeyMldsa, want.SigningPublicKeyMldsa},
		{"ml-dsa signing private key", got.SigningPrivateKeyMldsa, want.SigningPrivateKeyMldsa},
	} {
		if !bytes.Equal(f.got, f.want) {
			t.Errorf("%s did not round-trip (%d bytes back, %d expected)", f.label, len(f.got), len(f.want))
		}
	}
}

func TestRequestKeysAcceptsAnAgentWithoutSigningKeys(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	keys.SigningPublicKeyEd25519 = nil
	keys.SigningPrivateKeyEd25519 = nil
	keys.SigningPublicKeyMldsa = nil
	keys.SigningPrivateKeyMldsa = nil

	serveInBackground(t, keys, 30*time.Second)
	waitForAgent(t)

	got := RequestKeys()
	if got == nil {
		t.Fatal("a pre-signing-rollout agent must still serve its encryption keys")
	}
	for _, f := range []struct {
		label string
		b     []byte
	}{
		{"ed25519 signing public key", got.SigningPublicKeyEd25519},
		{"ed25519 signing private key", got.SigningPrivateKeyEd25519},
		{"ml-dsa signing public key", got.SigningPublicKeyMldsa},
		{"ml-dsa signing private key", got.SigningPrivateKeyMldsa},
	} {
		if f.b != nil {
			t.Errorf("%s came back as %d bytes; callers detect an unsigned agent by a nil field", f.label, len(f.b))
		}
	}
	if len(got.KyberSeed) != kyberSeedLen {
		t.Errorf("ml-kem seed = %d bytes, want %d", len(got.KyberSeed), kyberSeedLen)
	}
}

func TestRequestKeysRejectsWrongSizedMaterial(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*KeyMaterial)
	}{
		{"ml-kem public key one byte short", func(k *KeyMaterial) { k.KyberPublicKey = k.KyberPublicKey[:kyberPubLen-1] }},
		{"ml-kem public key one byte long", func(k *KeyMaterial) { k.KyberPublicKey = append(k.KyberPublicKey, 0) }},
		{"ml-kem public key absent", func(k *KeyMaterial) { k.KyberPublicKey = nil }},
		{"ml-kem seed one byte short", func(k *KeyMaterial) { k.KyberSeed = k.KyberSeed[:kyberSeedLen-1] }},
		{"ml-kem seed one byte long", func(k *KeyMaterial) { k.KyberSeed = append(k.KyberSeed, 0) }},
		{"ml-kem seed absent", func(k *KeyMaterial) { k.KyberSeed = nil }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAgentDir(t)
			keys := testKeys(t)
			tc.corrupt(keys)

			serveInBackground(t, keys, 30*time.Second)
			waitForAgent(t)

			if got := RequestKeys(); got != nil {
				t.Errorf("RequestKeys built key material from a malformed agent response (%s)", tc.name)
			}
		})
	}
}

func TestRequestKeysRejectsAForgedAgentToken(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	serveInBackground(t, keys, 30*time.Second)
	real := waitForAgent(t)

	forged := *real
	forged.Token = strings.Repeat("0", len(real.Token))
	if err := writeAgentFile(&forged); err != nil {
		t.Fatalf("writeAgentFile: %v", err)
	}

	if got := RequestKeys(); got != nil {
		t.Error("agent served keys to a client holding the wrong token")
	}
	if Ping() {
		t.Error("agent answered ping for a client holding the wrong token")
	}

	if err := writeAgentFile(real); err != nil {
		t.Fatalf("restore agent file: %v", err)
	}
	if RequestKeys() == nil {
		t.Fatal("agent stopped serving the correct token; the rejections above prove nothing")
	}
}

func TestForgedShutdownDoesNotStopTheAgent(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	serveInBackground(t, keys, 30*time.Second)
	real := waitForAgent(t)

	forged := *real
	forged.Token = strings.Repeat("0", len(real.Token))
	if err := writeAgentFile(&forged); err != nil {
		t.Fatalf("writeAgentFile: %v", err)
	}
	_ = Shutdown()
	time.Sleep(500 * time.Millisecond)

	if err := writeAgentFile(real); err != nil {
		t.Fatalf("restore agent file: %v", err)
	}
	if !Ping() {
		t.Error("a shutdown request carrying the wrong token stopped the agent")
	}
}
