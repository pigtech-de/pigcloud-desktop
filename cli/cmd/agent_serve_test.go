package cmd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/crypto"
)

const agentServeHelperEnv = "PIGCLOUD_AGENT_SERVE_HELPER"

func agentSpawnFixture() (agent.SpawnKeys, agent.KeyMaterial) {
	var km agent.KeyMaterial
	priv := bytes.Repeat([]byte{0xa1}, 32)
	pub := bytes.Repeat([]byte{0x11}, 32)
	copy(km.PublicKey[:], pub)
	copy(km.PrivateKey[:], priv)
	km.KyberPublicKey = bytes.Repeat([]byte{0x22}, crypto.KyberPublicKeySize)
	km.KyberSeed = bytes.Repeat([]byte{0xb2}, crypto.KyberSeedSize)
	km.NameKey = bytes.Repeat([]byte{0xc3}, crypto.NameKeySize)
	km.SigningPublicKeyEd25519 = bytes.Repeat([]byte{0x33}, crypto.Ed25519PKSize)
	km.SigningPrivateKeyEd25519 = bytes.Repeat([]byte{0xd4}, crypto.Ed25519SKSize)
	km.SigningPublicKeyMldsa = bytes.Repeat([]byte{0x44}, crypto.Mldsa44PKSize)
	km.SigningPrivateKeyMldsa = bytes.Repeat([]byte{0xe5}, crypto.Mldsa44SKSize)

	return agent.SpawnKeys{
		PubHex:        hex.EncodeToString(km.PublicKey[:]),
		PrivHex:       hex.EncodeToString(km.PrivateKey[:]),
		KyberPubHex:   hex.EncodeToString(km.KyberPublicKey),
		KyberSeedHex:  hex.EncodeToString(km.KyberSeed),
		NameKeyHex:    hex.EncodeToString(km.NameKey),
		SignPubEdHex:  hex.EncodeToString(km.SigningPublicKeyEd25519),
		SignPrivEdHex: hex.EncodeToString(km.SigningPrivateKeyEd25519),
		SignPubMlHex:  hex.EncodeToString(km.SigningPublicKeyMldsa),
		SignPrivMlHex: hex.EncodeToString(km.SigningPrivateKeyMldsa),
	}, km
}

func TestAgentServeHelperProcess(t *testing.T) {
	if os.Getenv(agentServeHelperEnv) != "1" {
		t.Skip("child half of TestAgentServeReadsKeysFromStdin")
	}
	rootCmd.SetArgs([]string{"__agent-serve", "--ttl", "20"})
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestAgentServeReadsKeysFromStdin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Cleanup(agent.RemoveAgentFile)

	spawn, want := agentSpawnFixture()
	payload, err := json.Marshal(spawn)
	if err != nil {
		t.Fatalf("marshal spawn keys: %v", err)
	}

	child := exec.Command(os.Args[0], "-test.run=TestAgentServeHelperProcess", "-test.timeout=60s")
	child.Env = append(os.Environ(),
		agentServeHelperEnv+"=1",
		"XDG_CONFIG_HOME="+dir,
		"APPDATA="+dir,
		"HOME="+dir,
		"USERPROFILE="+dir,
	)
	child.Stdin = bytes.NewReader(payload)
	var childErr bytes.Buffer
	child.Stderr = &childErr

	if err := child.Start(); err != nil {
		t.Fatalf("start agent child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})

	deadline := time.Now().Add(20 * time.Second)
	var got *agent.KeyMaterial
	for time.Now().Before(deadline) {
		if got = agent.RequestKeys(); got != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got == nil {
		t.Fatalf("agent never served the keys handed to it on stdin; child stderr: %s", childErr.String())
	}

	if got.PublicKey != want.PublicKey {
		t.Error("x25519 public key did not survive the stdin handoff")
	}
	if got.PrivateKey != want.PrivateKey {
		t.Error("x25519 private key did not survive the stdin handoff")
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
			t.Errorf("%s did not survive the stdin handoff (%d bytes back, %d expected)",
				f.label, len(f.got), len(f.want))
		}
	}

	if !agent.Ping() {
		t.Error("agent did not answer ping after the stdin handoff")
	}
}

func TestAgentServeAcceptsAPayloadWithoutSigningKeys(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Cleanup(agent.RemoveAgentFile)

	spawn, want := agentSpawnFixture()
	spawn.SignPubEdHex = ""
	spawn.SignPrivEdHex = ""
	spawn.SignPubMlHex = ""
	spawn.SignPrivMlHex = ""
	payload, err := json.Marshal(spawn)
	if err != nil {
		t.Fatalf("marshal spawn keys: %v", err)
	}

	child := exec.Command(os.Args[0], "-test.run=TestAgentServeHelperProcess", "-test.timeout=60s")
	child.Env = append(os.Environ(),
		agentServeHelperEnv+"=1",
		"XDG_CONFIG_HOME="+dir,
		"APPDATA="+dir,
		"HOME="+dir,
		"USERPROFILE="+dir,
	)
	child.Stdin = bytes.NewReader(payload)
	var childErr bytes.Buffer
	child.Stderr = &childErr

	if err := child.Start(); err != nil {
		t.Fatalf("start agent child: %v", err)
	}
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})

	deadline := time.Now().Add(20 * time.Second)
	var got *agent.KeyMaterial
	for time.Now().Before(deadline) {
		if got = agent.RequestKeys(); got != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got == nil {
		t.Fatalf("a legacy payload without signing keys was refused; child stderr: %s", childErr.String())
	}
	if !bytes.Equal(got.KyberSeed, want.KyberSeed) {
		t.Error("ml-kem seed did not survive a legacy stdin handoff")
	}
	if got.SigningPrivateKeyEd25519 != nil || got.SigningPrivateKeyMldsa != nil {
		t.Error("agent invented signing keys the payload did not carry")
	}
}

func TestAgentServeRejectsMalformedStdin(t *testing.T) {
	cases := []struct {
		name    string
		payload func(agent.SpawnKeys) []byte
	}{
		{"not json", func(agent.SpawnKeys) []byte { return []byte("garbage") }},
		{"empty", func(agent.SpawnKeys) []byte { return nil }},
		{"short private key", func(s agent.SpawnKeys) []byte {
			s.PrivHex = strings.Repeat("a1", 31)
			b, _ := json.Marshal(s)
			return b
		}},
		{"short name key", func(s agent.SpawnKeys) []byte {
			s.NameKeyHex = strings.Repeat("c3", 16)
			b, _ := json.Marshal(s)
			return b
		}},
		{"non-hex seed", func(s agent.SpawnKeys) []byte {
			s.KyberSeedHex = strings.Repeat("zz", crypto.KyberSeedSize)
			b, _ := json.Marshal(s)
			return b
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			spawn, _ := agentSpawnFixture()

			child := exec.Command(os.Args[0], "-test.run=TestAgentServeHelperProcess", "-test.timeout=60s")
			child.Env = append(os.Environ(),
				agentServeHelperEnv+"=1",
				"XDG_CONFIG_HOME="+dir,
				"APPDATA="+dir,
				"HOME="+dir,
				"USERPROFILE="+dir,
			)
			child.Stdin = bytes.NewReader(tc.payload(spawn))

			err := child.Run()
			if err == nil {
				t.Errorf("agent started on a %s payload instead of exiting non-zero", tc.name)
			}
		})
	}
}
