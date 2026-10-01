package agent

import (
	"log"
	"os"
	"path/filepath"

	"pigcloud/internal/mount/mlog"
)

const maxAgentLogSize = 1 << 20

func agentLogPath() string {
	return filepath.Join(filepath.Dir(agentFilePath()), "agent.log")
}

func openAgentLog(path string) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > maxAgentLogSize {
		os.Rename(path, path+".1")
	}
	os.MkdirAll(filepath.Dir(path), 0700)
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
}

func agentFatalLogPath() string {
	return mlog.FatalLogPath(agentLogPath())
}

func startLogging() func() {
	path := agentLogPath()
	lf, err := openAgentLog(path)
	if err != nil {
		return func() {}
	}
	rotating := mlog.Rotating(path, lf, maxAgentLogSize)
	log.SetOutput(rotating)
	return func() { rotating.Close() }
}
