package agent

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func spawnSecrets() map[string]string {
	return map[string]string{
		"x25519 private key":          strings.Repeat("a1", 32),
		"ml-kem seed":                 strings.Repeat("b2", 64),
		"name key":                    strings.Repeat("c3", 32),
		"ed25519 signing private key": strings.Repeat("d4", 64),
		"ml-dsa signing private key":  strings.Repeat("e5", 2560),
	}
}

func spawnFixture() SpawnKeys {
	s := spawnSecrets()
	return SpawnKeys{
		PubHex:        strings.Repeat("11", 32),
		PrivHex:       s["x25519 private key"],
		KyberPubHex:   strings.Repeat("22", 1184),
		KyberSeedHex:  s["ml-kem seed"],
		NameKeyHex:    s["name key"],
		SignPubEdHex:  strings.Repeat("33", 32),
		SignPrivEdHex: s["ed25519 signing private key"],
		SignPubMlHex:  strings.Repeat("44", 1312),
		SignPrivMlHex: s["ml-dsa signing private key"],
	}
}

func TestSpawnArgvCarriesNoKeyMaterial(t *testing.T) {
	keys := spawnFixture()
	cmd, payload := buildSpawnCmd("/nonexistent/pc", keys, 3600)

	argv := strings.Join(cmd.Args, " ")
	for label, secret := range spawnSecrets() {
		if strings.Contains(argv, secret) {
			t.Errorf("argv carries the %s; any local user can read it from /proc/<pid>/cmdline", label)
		}
	}

	if payload == nil {
		t.Fatal("no private channel payload; the key material has to reach the child some other way")
	}
	var got SpawnKeys
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("payload is not the documented JSON: %v", err)
	}
	if got != keys {
		t.Error("payload does not round-trip the key material handed to the child")
	}
}

func TestSpawnArgvStillCarriesTheNonSecretConfig(t *testing.T) {
	cmd, _ := buildSpawnCmd("/nonexistent/pc", spawnFixture(), 1800)

	argv := cmd.Args
	if len(argv) == 0 || argv[0] != "/nonexistent/pc" {
		t.Fatalf("argv[0] = %q, want the executable path", argv)
	}
	if len(argv) < 2 || argv[1] != "__agent-serve" {
		t.Errorf("argv = %v, want the __agent-serve subcommand", argv)
	}
	if !containsPair(argv, "--ttl", "1800") {
		t.Errorf("argv = %v, want --ttl 1800; the TTL is not secret and stays on the command line", argv)
	}
}

func containsPair(argv []string, flag, value string) bool {
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == flag && argv[i+1] == value {
			return true
		}
	}
	return false
}

func TestSpawnedProcessCmdlineExposesNoKeyMaterial(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc/<pid>/cmdline is Linux-specific")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no shell to host the stand-in agent: %v", err)
	}
	script := filepath.Join(t.TempDir(), "stand-in-agent")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 5\n"), 0o700); err != nil {
		t.Fatalf("write stand-in: %v", err)
	}

	keys := spawnFixture()
	cmd, payload := buildSpawnCmd(script, keys, 3600)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stand-in child: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	if payload != nil {
		if _, err := stdin.Write(payload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
	}
	stdin.Close()

	cmdlinePath := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cmdline"
	var raw []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, rerr := os.ReadFile(cmdlinePath)
		if rerr == nil && len(b) > 0 {
			raw = b
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(raw) == 0 {
		t.Fatal("child cmdline stayed empty; this guard would be vacuous")
	}
	for label, secret := range spawnSecrets() {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("/proc/%d/cmdline exposes the %s to every local user", cmd.Process.Pid, label)
		}
	}
}

func TestSpawnDeliversThePayloadOnChildStdin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-in is POSIX-only")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("no shell to host the stand-in agent: %v", err)
	}

	dir := t.TempDir()
	sink := filepath.Join(dir, "received.json")
	script := filepath.Join(dir, "stand-in-agent")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat > "+sink+"\n"), 0o700); err != nil {
		t.Fatalf("write stand-in: %v", err)
	}

	keys := spawnFixture()
	if err := spawnWithExecutable(script, keys, 3600); err != nil {
		t.Fatalf("spawn: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var raw []byte
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(sink)
		if err == nil && len(b) > 0 {
			raw = b
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(raw) == 0 {
		t.Fatal("child received nothing on stdin; the key material never reaches the agent")
	}

	var got SpawnKeys
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("child received %d bytes that are not the documented JSON: %v", len(raw), err)
	}
	if got != keys {
		t.Error("child received key material that differs from what the parent was given")
	}
}

func TestAgentFileStaysTheOnlyPrivilegedChannel(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	serveInBackground(t, keys, 30*time.Second)
	info := waitForAgent(t)

	fi, err := os.Stat(agentFilePath())
	if err != nil {
		t.Fatalf("stat agent file: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("agent.json mode %04o, want 0600", perm)
		}
	}
	if info.Token == "" {
		t.Error("agent published no token; the file would not be a privileged channel")
	}
}
