package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
)

type SpawnKeys struct {
	PubHex        string `json:"pub"`
	PrivHex       string `json:"priv"`
	KyberPubHex   string `json:"kyber_pub"`
	KyberSeedHex  string `json:"kyber_seed"`
	NameKeyHex    string `json:"name_key"`
	SignPubEdHex  string `json:"sign_pub_ed"`
	SignPrivEdHex string `json:"sign_priv_ed"`
	SignPubMlHex  string `json:"sign_pub_ml"`
	SignPrivMlHex string `json:"sign_priv_ml"`
}

func buildSpawnCmd(exePath string, keys SpawnKeys, ttlSeconds int) (*exec.Cmd, []byte) {
	cmd := exec.Command(exePath, "__agent-serve", "--ttl", strconv.Itoa(ttlSeconds))
	payload, err := json.Marshal(keys)
	if err != nil {
		return cmd, nil
	}
	return cmd, payload
}

func SpawnBackground(keys SpawnKeys, ttlSeconds int) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	return spawnWithExecutable(exePath, keys, ttlSeconds)
}

func spawnWithExecutable(exePath string, keys SpawnKeys, ttlSeconds int) error {
	cmd, payload := buildSpawnCmd(exePath, keys, ttlSeconds)
	if payload == nil {
		return fmt.Errorf("marshal spawn keys")
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("create stdin pipe: %w", err)
	}
	cmd.Stdout = nil

	cmd.Stderr = nil
	if lf, lerr := openAgentLog(agentFatalLogPath()); lerr == nil {
		cmd.Stderr = lf
		defer lf.Close()
	}

	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = windowsDetachAttr()
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		return fmt.Errorf("start agent: %w", err)
	}

	if _, err := stdin.Write(payload); err != nil {
		stdin.Close()
		return fmt.Errorf("write spawn keys: %w", err)
	}
	stdin.Close()

	cmd.Process.Release()
	return nil
}
