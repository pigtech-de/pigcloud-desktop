package mount

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"pigcloud/internal/netutil"
	"runtime"
	"strconv"
	"time"
)

const FlushBudget = 30 * time.Second

const FlushDeadline = FlushBudget + 5*time.Second

const (
	ModeSync    = "sync"
	ModeVirtual = "virtual"
)

type MountInfo struct {
	Port       int       `json:"port"`
	Token      string    `json:"token"`
	PID        int       `json:"pid"`
	MountPoint string    `json:"mount_point"`
	RemotePath string    `json:"remote_path"`
	CacheDir   string    `json:"cache_dir"`
	SyncDir    string    `json:"sync_dir,omitempty"`
	Mode       string    `json:"mode"`
	Owner      string    `json:"owner,omitempty"`
	Endpoint   string    `json:"endpoint,omitempty"`
	StartedAt  time.Time `json:"started_at"`

	Source string `json:"-"`
}

type DaemonRequest struct {
	Token  string `json:"token"`
	Action string `json:"action"`
	Path   string `json:"path,omitempty"`
	Choice string `json:"choice,omitempty"`
}

type FileEntry struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Dirty  bool   `json:"dirty,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Pinned bool   `json:"pinned,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type DaemonResponse struct {
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
	Online         bool   `json:"online,omitempty"`
	MountPoint     string `json:"mount_point,omitempty"`
	RemotePath     string `json:"remote_path,omitempty"`
	Mode           string `json:"mode,omitempty"`
	SyncDir        string `json:"sync_dir,omitempty"`
	CacheUsed      int64  `json:"cache_used,omitempty"`
	CacheMax       int64  `json:"cache_max,omitempty"`
	PendingCount   int    `json:"pending_count,omitempty"`
	FailedCount    int    `json:"failed_count,omitempty"`
	DeferredCount  int    `json:"deferred_count,omitempty"`
	NextDueSeconds int    `json:"next_due_seconds,omitempty"`
	Retried        int    `json:"retried,omitempty"`
	FailedDownloadCount int    `json:"failed_download_count,omitempty"`
	LastPoll            string `json:"last_poll,omitempty"`
	Uptime              string `json:"uptime,omitempty"`
	Cleaned             int    `json:"cleaned,omitempty"`

	Files    []FileEntry     `json:"files,omitempty"`
	Activity []ActivityEvent `json:"activity,omitempty"`
}

func mountFilePath() string {
	return filepath.Join(ConfigDir(), "mount.json")
}

func ConfigDir() string {
	if runtime.GOOS == "windows" {
		dir := os.Getenv("APPDATA")
		if dir == "" {
			dir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		return filepath.Join(dir, "pigcloud")
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "pigcloud")
}

func DataDir() string {
	if runtime.GOOS == "windows" {
		dir := os.Getenv("LOCALAPPDATA")
		if dir == "" {
			dir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local")
		}
		return filepath.Join(dir, "pigcloud")
	}
	return ConfigDir()
}

func CleanStaleMountCaches(current string) {
	root := filepath.Join(DataDir(), "mount-cache")
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if p := filepath.Join(root, e.Name()); p != current {
			os.RemoveAll(p)
		}
	}
}

func ReadMountFile() *MountInfo {
	data, err := os.ReadFile(mountFilePath())
	if err != nil {
		return nil
	}
	var info MountInfo
	if json.Unmarshal(data, &info) != nil {
		return nil
	}
	return &info
}

func SendRequest(info *MountInfo, action string) (*DaemonResponse, error) {
	return SendRequestWithPath(info, action, "")
}

func SendRequestNoEvict(info *MountInfo, action string) (*DaemonResponse, error) {
	return sendRequestOpts(DaemonRequest{Token: info.Token, Action: action}, info, false)
}

func SendRequestWithPath(info *MountInfo, action, path string) (*DaemonResponse, error) {
	return sendRequest(DaemonRequest{Token: info.Token, Action: action, Path: path}, info)
}

func SendRetry(info *MountInfo, path string) (*DaemonResponse, error) {
	return sendRequest(DaemonRequest{Token: info.Token, Action: "retry", Path: path}, info)
}

func SendResolve(info *MountInfo, path, choice string) (*DaemonResponse, error) {
	return sendRequest(DaemonRequest{Token: info.Token, Action: "resolve", Path: path, Choice: choice}, info)
}

func sendRequest(req DaemonRequest, info *MountInfo) (*DaemonResponse, error) {
	return sendRequestOpts(req, info, true)
}

func sendRequestOpts(req DaemonRequest, info *MountInfo, evictOnDialFail bool) (*DaemonResponse, error) {
	conn, err := net.DialTimeout("tcp", netutil.LoopbackHost+":"+strconv.Itoa(info.Port), netutil.LoopbackDialTimeout)
	if err != nil {
		if evictOnDialFail {
			EvictMountEntry(info)
		}
		return nil, err
	}
	defer conn.Close()
	deadline := 10 * time.Second
	if req.Action == "flush" {
		deadline = FlushDeadline
	}
	conn.SetDeadline(time.Now().Add(deadline))

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if err := enc.Encode(req); err != nil {
		return nil, err
	}

	var resp DaemonResponse
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
