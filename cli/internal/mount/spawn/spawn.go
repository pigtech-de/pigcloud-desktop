package spawn

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"pigcloud/internal/agent"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount"
	"pigcloud/internal/mount/mlog"
)

type Keys = agent.SpawnKeys

func mountServeArgs(remotePath, mountPoint string, cacheSizeBytes int64,
	pollSeconds int, mode string, readOnly bool, logLevel string) []string {

	args := []string{"__mount-serve",
		"--remote", remotePath,
		"--mountpoint", mountPoint,
		"--cache-size", fmt.Sprintf("%d", cacheSizeBytes),
		"--poll", fmt.Sprintf("%d", pollSeconds),
		"--mode", mode,
	}
	if readOnly {
		args = append(args, "--read-only")
	}
	if logLevel != "" {
		args = append(args, "--log-level", logLevel)
	}
	return args
}

func FatalSinkPath(ownerFingerprint, remotePath string) string {
	return mlog.FatalLogPath(mount.MountLogPath(ownerFingerprint, remotePath))
}

func fatalSinkFor(keys Keys, remotePath string) string {
	pubBytes, err := hex.DecodeString(keys.PubHex)
	if err != nil {
		return ""
	}
	return FatalSinkPath(crypto.AccountFingerprint(pubBytes), remotePath)
}

func Background(remotePath, mountPoint string, keys Keys,
	cacheSizeBytes int64, pollSeconds int, mode string, readOnly bool, logLevel string) error {

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	return backgroundWithExecutable(exePath, remotePath, mountPoint, keys,
		cacheSizeBytes, pollSeconds, mode, readOnly, logLevel)
}

func backgroundWithExecutable(exePath, remotePath, mountPoint string, keys Keys,
	cacheSizeBytes int64, pollSeconds int, mode string, readOnly bool, logLevel string) error {

	payload, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("marshal spawn keys: %w", err)
	}

	args := mountServeArgs(remotePath, mountPoint, cacheSizeBytes, pollSeconds, mode, readOnly, logLevel)
	cmd := exec.Command(exePath, args...)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("create stdin pipe: %w", err)
	}
	cmd.Stdout = nil

	cmd.Stderr = nil
	if sink := fatalSinkFor(keys, remotePath); sink != "" {
		if lf, lerr := mlog.OpenLog(sink); lerr == nil {
			cmd.Stderr = lf
			defer lf.Close()
		}
	}

	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = mountDetachAttr()
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		return fmt.Errorf("start mount daemon: %w", err)
	}

	if _, err := stdin.Write(payload); err != nil {
		stdin.Close()
		return fmt.Errorf("write spawn keys: %w", err)
	}
	stdin.Close()

	cmd.Process.Release()
	return nil
}
