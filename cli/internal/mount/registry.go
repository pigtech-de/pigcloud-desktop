package mount

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/mount/mlog"
	"sort"
)

const mountsDirName = "mounts.d"

func mountsDir() string {
	return filepath.Join(ConfigDir(), mountsDirName)
}

func mountKey(owner, remotePath string) string {
	sum := sha256.Sum256([]byte(owner + "|" + NormalizeRemotePath(remotePath)))
	return hex.EncodeToString(sum[:6])
}

func entryFileName(owner, remotePath string) string {
	return mountKey(owner, remotePath) + ".json"
}

func WriteMountEntry(info *MountInfo) error {
	dir := mountsDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, entryFileName(info.Owner, info.RemotePath))
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return err
	}
	info.Source = path
	return nil
}

func EvictMountEntry(info *MountInfo) {
	if info == nil || info.Source == "" {
		return
	}
	os.Remove(info.Source)
}

func ListMounts() []*MountInfo {
	var out []*MountInfo
	entries, err := os.ReadDir(mountsDir())
	if err == nil {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(mountsDir(), name)
			if info := readMountEntry(path); info != nil {
				out = append(out, info)
			}
		}
	}
	if legacy := ReadMountFile(); legacy != nil {
		legacy.Source = mountFilePath()
		out = append(out, legacy)
	}
	return out
}

func FindMount(owner, remotePath string) *MountInfo {
	want := NormalizeRemotePath(remotePath)
	for _, info := range ListMounts() {
		if NormalizeRemotePath(info.RemotePath) != want {
			continue
		}
		if info.Owner == owner || info.Owner == "" || owner == "" {
			return info
		}
	}
	return nil
}

func readMountEntry(path string) *MountInfo {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var info MountInfo
	if json.Unmarshal(data, &info) != nil {
		return nil
	}
	info.Source = path
	return &info
}

func IsMountReachable(info *MountInfo) bool {
	if info == nil {
		return false
	}
	resp, err := SendRequestNoEvict(info, "ping")
	return err == nil && resp != nil && resp.OK
}

func MountLogPath(owner, remotePath string) string {
	return filepath.Join(ConfigDir(), "mount-"+mountKey(owner, remotePath)+".log")
}

func RemoveFatalLog(owner, remotePath string) {
	fatal := mlog.FatalLogPath(MountLogPath(owner, remotePath))
	os.Remove(fatal)
	os.Remove(fatal + ".1")
}
