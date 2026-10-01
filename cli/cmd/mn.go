package cmd

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"pigcloud/internal/agent"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/spawn"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

func currentOwnerID() string {
	raw, err := base64.StdEncoding.DecodeString(config.Get().PublicKey)
	if err != nil {
		return ""
	}
	return crypto.AccountFingerprint(raw)
}

var (
	mnCacheSize    string
	mnPollInterval int
	mnReadOnly     bool
	mnLogLevel     string
	mnVirtual      bool
	mnSyncDir      string
)

var mnCmd = &cobra.Command{
	Use:     "mn",
	GroupID: GroupFiles,
	Aliases: []string{"mount"},
	Short:   "Mount cloud storage as a local drive",
	Long: `Mount your PigCloud storage as a local filesystem.

Run 'pc mn' to check mount status. Use 'pc mn start' to mount.

Sync mode (default): files are downloaded to a local folder and kept in sync
bidirectionally. The folder is mapped as a drive letter (Windows) or symlink
(Linux/macOS). Reads and writes are instant, with no network latency.

Virtual mode (--virtual): FUSE/WinFsp network-backed mount where files are
fetched on demand. Lower disk usage but higher latency.

Requires unlocked encryption keys (run 'pc uk' first).`,
	Example: `pc mn                        # Show mount status
pc mn start /Photos P:       # Sync /Photos to P: drive (fast, local files)
pc mn start /Photos P: --virtual  # Virtual mount (network-backed)
pc mn start                  # Sync root at default location
pc mn stop                   # Unmount and stop sync
pc mn files --tree           # Show synced files as a tree
pc mn files --issues         # Show files with sync problems
pc mn retry                  # Re-attempt transfers that gave up
pc mn conflicts              # List files changed on both sides
pc mn resolve <path> -k both # Settle a conflict, keeping both copies`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runMountStatus("")
	},
}

var mnStartCmd = &cobra.Command{
	Use:   "start [remote-path] [mount-point]",
	Short: "Start the mount daemon",
	Args:  cobra.MaximumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		remotePath := "/"
		mountPoint := defaultMountPoint()
		if len(args) >= 1 {
			remotePath = args[0]
		}
		if len(args) >= 2 {
			mountPoint = args[1]
		}
		runMountStart(remotePath, mountPoint)
	},
}

var mnStopAll bool

var mnStopCmd = &cobra.Command{
	Use:     "stop [remote-path]",
	Aliases: []string{"unmount"},
	Short:   "Stop a mount daemon and unmount",
	Example: `pc mn stop            # Stop the only mount
pc mn stop /Photos    # Stop one of several mounts
pc mn stop -a         # Stop every running mount`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountStop(hint)
	},
}

var mnStatusCmd = &cobra.Command{
	Use:   "status [remote-path]",
	Short: "Show mount status and cache statistics",
	Example: `pc mn status
pc mn status /Photos  # Detail for one of several mounts
pc mn status --json   # machine-readable: {"running", "mounts": [...]}`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountStatus(hint)
	},
}

var (
	mnFilesIssuesOnly bool
	mnFilesTree       bool
)

var mnFilesCmd = &cobra.Command{
	Use:   "files [remote-path]",
	Short: "Show per-file sync status",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountFiles(hint)
	},
}

var mnPinCmd = &cobra.Command{
	Use:   "pin <remote-path>",
	Short: "Pin a file or folder for offline access",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		list, _ := cmd.Flags().GetBool("list")
		remove, _ := cmd.Flags().GetString("remove")

		if list {
			runMountPinList()
		} else if remove != "" {
			runMountUnpin(remove)
		} else if len(args) == 1 {
			runMountPin(args[0])
		} else {
			cmd.Help()
		}
	},
}

var mnCleanCmd = &cobra.Command{
	Use:   "clean [remote-path]",
	Short: "Remove rejected (unsyncable) files from mount",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountClean(hint)
	},
}

var mnRetryCmd = &cobra.Command{
	Use:   "retry [remote-path]",
	Short: "Re-attempt transfers that gave up",
	Long: `Clear the give-up flag on files whose upload or download failed for good and
try them again.

Use it after fixing the cause: freeing quota, friending the collaborator whose
upload landed in your folder, or waiting out a scanner outage. Without a path it
retries every failed file in the mount; with one it retries that file only.`,
	Example: `pc mn retry
pc mn retry Docs/report.pdf`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountRetry(hint)
	},
}

var mnConflictsCmd = &cobra.Command{
	Use:   "conflicts [remote-path]",
	Short: "List files changed both locally and remotely",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountConflicts(hint)
	},
}

var (
	mnResolveKeep  string
	mnResolveForce bool
)

var mnResolveCmd = &cobra.Command{
	Use:   "resolve <remote-path>",
	Short: "Settle a sync conflict",
	Long: `Settle a conflict for a file that changed both locally and remotely.

--keep local   upload your local edit (the remote copy stays in version history)
--keep remote  discard your local edit and re-download the remote file
--keep both    keep the local edit as a "(conflict <date>)" copy and re-download`,
	Example: `pc mn resolve Docs/notes.txt -k both
pc mn resolve Docs/notes.txt -k remote -f`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runMountResolve(args[0])
	},
}

var (
	mnMvDest  string
	mnMvForce bool
)

var mnMvCmd = &cobra.Command{
	Use:   "mv [remote-path]",
	Short: "Move the sync folder to a different location",
	Long: `Move the local sync folder to a new directory. A running mount daemon is
stopped during the move; restart it afterward with 'pc mn start <remote-path>'.

Use -f to skip the confirmation prompt.`,
	Example: `pc mn mv -d D:\PigCloud
pc mn mv -d /mnt/data/pigcloud -f`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hint := ""
		if len(args) == 1 {
			hint = args[0]
		}
		runMountMv(hint)
	},
}

func init() {
	mnMvCmd.Flags().StringVarP(&mnMvDest, "dest", "d", "", "destination directory")
	mnMvCmd.MarkFlagRequired("dest")
	mnMvCmd.Flags().BoolVarP(&mnMvForce, "force", "f", false, "skip confirmation prompt")

	mnStartCmd.Flags().StringVar(&mnCacheSize, "cache-size", "5G", "maximum local cache size")
	mnStartCmd.Flags().IntVar(&mnPollInterval, "poll-interval", 30, "remote poll interval in seconds")
	mnStartCmd.Flags().BoolVar(&mnReadOnly, "read-only", false, "mount read-only (no write-back)")
	mnStartCmd.Flags().BoolVar(&mnVirtual, "virtual", false, "use virtual FUSE/WinFsp mount instead of sync mode")
	mnStartCmd.Flags().StringVar(&mnSyncDir, "sync-dir", "", "sync an existing local folder directly without a drive or symlink")
	mnStartCmd.Flags().StringVar(&mnLogLevel, "log-level", "", "daemon log detail: debug, info, warn, error (default info)")

	mnFilesCmd.Flags().BoolVar(&mnFilesIssuesOnly, "issues", false, "show only files with problems")
	mnFilesCmd.Flags().BoolVar(&mnFilesTree, "tree", false, "show files as a tree")

	mnPinCmd.Flags().Bool("list", false, "list pinned paths")
	mnPinCmd.Flags().String("remove", "", "unpin a path")

	mnResolveCmd.Flags().StringVarP(&mnResolveKeep, "keep", "k", "", "which side to keep: local, remote, or both")
	mnResolveCmd.MarkFlagRequired("keep")
	mnResolveCmd.Flags().BoolVarP(&mnResolveForce, "force", "f", false, "skip confirmation")

	mnStopCmd.Flags().BoolVarP(&mnStopAll, "all", "a", false, "stop every running mount")

	mnCmd.AddCommand(mnStartCmd)
	mnCmd.AddCommand(mnStopCmd)
	mnCmd.AddCommand(mnStatusCmd)
	mnCmd.AddCommand(mnFilesCmd)
	mnCmd.AddCommand(mnPinCmd)
	mnCmd.AddCommand(mnCleanCmd)
	mnCmd.AddCommand(mnRetryCmd)
	mnCmd.AddCommand(mnConflictsCmd)
	mnCmd.AddCommand(mnResolveCmd)
	mnCmd.AddCommand(mnMvCmd)
	rootCmd.AddCommand(mnCmd)
}

func resolveMode() string {
	if mnVirtual {
		return mount.ModeVirtual
	}
	return mount.ModeSync
}

func ownedMounts() []*mount.MountInfo {
	owner := currentOwnerID()
	var out []*mount.MountInfo
	for _, m := range mount.ListMounts() {
		if m.Owner == "" || owner == "" || m.Owner == owner {
			out = append(out, m)
		}
	}
	return out
}

func displayRemote(p string) string {
	if n := mount.NormalizeRemotePath(p); n != "" {
		return "/" + n
	}
	return "/"
}

func sameRemote(a, b string) bool {
	return mount.NormalizeRemotePath(a) == mount.NormalizeRemotePath(b)
}

func printMountChoices(mounts []*mount.MountInfo) {
	output.PrintInfo("Multiple mounts running; pass the remote path:")
	for _, m := range mounts {
		fmt.Printf("  %s -> %s (%s)\n", displayRemote(m.RemotePath), m.MountPoint, m.Mode)
	}
}

func withMount(hint string, fn func(info *mount.MountInfo)) {
	info := selectMount(hint)
	if info == nil {
		output.PrintInfo("Not mounted")
		return
	}
	fn(info)
}

func reportIPC(verb string, resp *mount.DaemonResponse, err error) {
	if err != nil {
		output.PrintError(verb + " failed: " + err.Error())
		ExitWithError()
	}
	if !resp.OK {
		output.PrintError(verb + " failed: " + resp.Error)
		ExitWithError()
	}
}

func selectMount(hint string) *mount.MountInfo {
	return selectMountIn(ownedMounts(), hint)
}

func selectMountIn(mounts []*mount.MountInfo, hint string) *mount.MountInfo {
	if len(mounts) == 0 {
		return nil
	}
	if hint == "" {
		if len(mounts) == 1 {
			return mounts[0]
		}
		printMountChoices(mounts)
		ExitWithError()
	}
	want := mount.NormalizeRemotePath(hint)
	var best *mount.MountInfo
	bestLen := -1
	for _, m := range mounts {
		mp := mount.NormalizeRemotePath(m.RemotePath)
		if mp == want {
			return m
		}
		if (mp == "" || strings.HasPrefix(want, mp+"/")) && len(mp) > bestLen {
			best = m
			bestLen = len(mp)
		}
	}
	if best == nil {
		output.PrintError("No mount matches " + hint)
		printMountChoices(mounts)
		ExitWithError()
	}
	return best
}

const (
	mountLogTailLines = 10
	mountLogTailBytes = 8 << 10
)

func tailLines(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil
	}
	start := int64(0)
	if fi.Size() > mountLogTailBytes {
		start = fi.Size() - mountLogTailBytes
	}
	buf := make([]byte, fi.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil
	}

	lines := strings.Split(string(buf), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

func printMountLogHint(logPath string) {
	tail := tailLines(logPath, mountLogTailLines)
	if len(tail) == 0 {
		output.PrintInfo("Daemon log (empty so far): " + logPath)
	} else {
		output.PrintInfo("Last lines of " + logPath + ":")
		for _, l := range tail {
			fmt.Fprintln(os.Stderr, "    "+l)
		}
	}
	fatalPath := mlog.FatalLogPath(logPath)
	fatalTail := tailLines(fatalPath, mountLogTailLines)
	if len(fatalTail) == 0 {
		return
	}
	output.PrintInfo("Last lines of " + fatalPath + " (runtime fatals):")
	for _, l := range fatalTail {
		fmt.Fprintln(os.Stderr, "    "+l)
	}
}

func runMountStart(remotePath, mountPoint string) {
	cmdutil.RequireLogin(ExitWithError)

	mode := resolveMode()
	if mnSyncDir != "" {
		if mode != mount.ModeSync {
			output.PrintError("--sync-dir requires sync mode")
			ExitWithError()
			return
		}
		if err := validateDirectSyncDir(mnSyncDir, mountPoint); err != nil {
			output.PrintError(err.Error())
			ExitWithError()
			return
		}
	}

	if mode == mount.ModeVirtual {
		if !mount.IsWinFspInstalled() {
			output.PrintError(mount.WinFspInstallHint())
			ExitWithError()
		}
		if runtime.GOOS != "windows" && !mount.IsFuseAvailable() {
			output.PrintError(mount.FuseInstallHint())
			ExitWithError()
		}
	}

	owner := currentOwnerID()

	for _, m := range mount.ListMounts() {
		if m.Owner != "" && owner != "" && m.Owner != owner {
			output.PrintInfo("Stopping mount started by a different account...")
			stopEntry(m)
		}
	}

	if mode == mount.ModeVirtual {
		for _, m := range ownedMounts() {
			if m.Mode == mount.ModeVirtual && !sameRemote(m.RemotePath, remotePath) {
				output.PrintInfo(fmt.Sprintf("Stopping existing virtual mount %s -> %s...", displayRemote(m.RemotePath), m.MountPoint))
				stopEntry(m)
			}
		}
	}

	if existing := mount.FindMount(owner, remotePath); existing != nil {
		if !mount.IsMountReachable(existing) {
			mount.EvictMountEntry(existing)
		} else if existing.MountPoint == mountPoint && existing.Mode == mode {
			output.PrintInfo(fmt.Sprintf("Already mounted: %s -> %s (%s mode)", existing.RemotePath, existing.MountPoint, existing.Mode))
			return
		} else {
			output.PrintInfo(fmt.Sprintf("Remounting %s (%s mode at %s)...", displayRemote(remotePath), mode, mountPoint))
			stopEntry(existing)
		}
	}

	for _, m := range ownedMounts() {
		if m.MountPoint == mountPoint && !sameRemote(m.RemotePath, remotePath) && mount.IsMountReachable(m) {
			output.PrintError(fmt.Sprintf("Mount point %s is already in use for %s. Run 'pc mn stop %s' first.", mountPoint, displayRemote(m.RemotePath), displayRemote(m.RemotePath)))
			ExitWithError()
		}
	}

	if !agent.IsRunning() {
		output.PrintError("Keys are locked. Run 'pc uk' first.")
		ExitWithError()
	}

	keys := agent.RequestKeys()
	if keys == nil {
		output.PrintError("Failed to retrieve keys from agent")
		ExitWithError()
	}

	cacheSizeBytes, err := cache.ParseCacheSize(mnCacheSize)
	if err != nil {
		output.PrintError("Invalid cache size: " + err.Error())
		ExitWithError()
	}

	ownerID := crypto.AccountFingerprint(keys.PublicKey[:])
	if mode == mount.ModeSync {
		syncPaths := mount.LoadSyncPaths()
		if mnSyncDir != "" {
			if err := configureDirectSyncDir(syncPaths, ownerID, remotePath, mnSyncDir, mountPoint); err != nil {
				reportDirectSyncError(err)
				ExitWithError()
				return
			}
		} else if !syncPaths.SyncDirExists(ownerID, remotePath) {
			defaultDir := mount.DefaultSyncDir(ownerID, mount.NormalizeRemotePath(remotePath))
			promptSyncDir(ownerID, remotePath, defaultDir, syncPaths)
		}
		syncDir := syncPaths.GetSyncDir(ownerID, remotePath)
		if err := mount.ClaimSyncDir(syncDir, ownerID); err != nil {
			output.PrintError(err.Error() + ". Pick a different folder (custom path prompt on next start) or move it away, then retry.")
			ExitWithError()
		}
	}

	if len(keys.SigningPrivateKeyEd25519) == 0 {
		output.PrintInfo("Warning: signing keys not loaded — uploads will be rejected. Open the web app to finish E2EE setup.")
	}

	spawnKeys := spawn.Keys{
		PubHex:        hex.EncodeToString(keys.PublicKey[:]),
		PrivHex:       hex.EncodeToString(keys.PrivateKey[:]),
		KyberPubHex:   hex.EncodeToString(keys.KyberPublicKey),
		KyberSeedHex:  hex.EncodeToString(keys.KyberSeed),
		NameKeyHex:    hex.EncodeToString(keys.NameKey),
		SignPubEdHex:  hex.EncodeToString(keys.SigningPublicKeyEd25519),
		SignPrivEdHex: hex.EncodeToString(keys.SigningPrivateKeyEd25519),
		SignPubMlHex:  hex.EncodeToString(keys.SigningPublicKeyMldsa),
		SignPrivMlHex: hex.EncodeToString(keys.SigningPrivateKeyMldsa),
	}

	logPath := mount.MountLogPath(ownerID, remotePath)

	if err := spawn.Background(remotePath, mountPoint, spawnKeys,
		cacheSizeBytes, mnPollInterval, mode, mnReadOnly, mnLogLevel); err != nil {
		output.PrintError("Failed to start mount daemon: " + err.Error() + " (log: " + logPath + ")")
		printMountLogHint(logPath)
		ExitWithError()
	}

	ready := false
	for range 30 {
		time.Sleep(200 * time.Millisecond)
		if e := mount.FindMount(owner, remotePath); e != nil && mount.IsMountReachable(e) {
			ready = true
			break
		}
	}

	if !ready {
		output.PrintError("Mount daemon failed to start; the cause is in the daemon log: " + logPath)
		printMountLogHint(logPath)
		ExitWithError()
	}

	modeLabel := "sync"
	if mode == mount.ModeVirtual {
		modeLabel = "virtual"
	}
	output.PrintSuccess(fmt.Sprintf("Mounted %s -> %s (%s mode, cache: %s)", remotePath, mountPoint, modeLabel, mnCacheSize))
}

func runMountStop(hint string) {
	if mnStopAll {
		if hint != "" {
			output.PrintError("Pass either a remote path or --all, not both")
			ExitWithError()
		}
		mounts := mount.ListMounts()
		if len(mounts) == 0 {
			output.PrintInfo("Not mounted")
			return
		}
		for _, m := range mounts {
			stopEntry(m)
		}
		return
	}
	info := selectMountIn(mount.ListMounts(), hint)
	if info == nil {
		output.PrintInfo("Not mounted")
		return
	}
	stopEntry(info)
}

func stopEntry(info *mount.MountInfo) {
	resp, err := mount.SendRequest(info, "shutdown")
	if err != nil {
		output.PrintInfo("Mount daemon not running (cleaned up)")
		return
	}
	if !resp.OK {
		output.PrintError("Shutdown failed: " + resp.Error)
		ExitWithError()
	}

	for range 30 {
		time.Sleep(200 * time.Millisecond)
		if !mount.IsMountReachable(info) {
			break
		}
	}

	output.PrintSuccess(fmt.Sprintf("Unmounted %s", info.MountPoint))
}

type mountStatusJSON struct {
	Running        bool   `json:"running"`
	Stale          bool   `json:"stale,omitempty"`
	Mode           string `json:"mode"`
	MountPoint     string `json:"mount_point"`
	RemotePath     string `json:"remote_path"`
	SyncDir        string `json:"sync_dir,omitempty"`
	Owner          string `json:"owner,omitempty"`
	Online         bool   `json:"online"`
	CacheUsed      int64  `json:"cache_used"`
	CacheMax       int64  `json:"cache_max"`
	Pending        int    `json:"pending"`
	Failed         int    `json:"failed"`
	Deferred       int    `json:"deferred,omitempty"`
	NextDueSeconds int    `json:"next_due_seconds,omitempty"`
	StalledDownloads int    `json:"stalled_downloads,omitempty"`
	LastPoll         string `json:"last_poll"`
	Uptime           string `json:"uptime"`
}

type mountStatusListJSON struct {
	Running bool              `json:"running"`
	Mounts  []mountStatusJSON `json:"mounts"`
}

func staleMountStatusJSON(info *mount.MountInfo) mountStatusJSON {
	m := mountStatusJSON{
		Stale:      true,
		Mode:       info.Mode,
		MountPoint: info.MountPoint,
		RemotePath: displayRemote(info.RemotePath),
		SyncDir:    info.SyncDir,
		Owner:      info.Owner,
	}
	if m.Mode == "" {
		m.Mode = mount.ModeVirtual
	}
	return m
}

func buildMountStatusJSON(info *mount.MountInfo, resp *mount.DaemonResponse) mountStatusJSON {
	m := mountStatusJSON{
		Running:          true,
		Mode:             resp.Mode,
		MountPoint:       resp.MountPoint,
		RemotePath:       resp.RemotePath,
		SyncDir:          resp.SyncDir,
		Online:           resp.Online,
		CacheUsed:        resp.CacheUsed,
		CacheMax:         resp.CacheMax,
		Pending:          resp.PendingCount,
		Failed:           resp.FailedCount,
		Deferred:         resp.DeferredCount,
		NextDueSeconds:   resp.NextDueSeconds,
		StalledDownloads: resp.FailedDownloadCount,
		LastPoll:         resp.LastPoll,
		Uptime:           resp.Uptime,
	}
	if m.Mode == "" {
		m.Mode = mount.ModeVirtual
	}
	if info != nil {
		m.Owner = info.Owner
	}
	return m
}

func runMountStatus(hint string) {
	if GetJSONOutput() {
		list := mountStatusListJSON{Mounts: []mountStatusJSON{}}
		for _, m := range mount.ListMounts() {
			resp, err := mount.SendRequestNoEvict(m, "status")
			if err != nil || resp == nil || !resp.OK {
				list.Mounts = append(list.Mounts, staleMountStatusJSON(m))
				continue
			}
			list.Running = true
			list.Mounts = append(list.Mounts, buildMountStatusJSON(m, resp))
		}
		cmdutil.PrintJSONOrContinue(true, list)
		return
	}

	mounts := mount.ListMounts()
	if len(mounts) == 0 {
		output.PrintInfo("Not mounted. Run 'pc mn start' to mount.")
		return
	}
	if hint == "" && len(mounts) > 1 {
		printMountTable(mounts)
		return
	}
	if hint == "" {
		printMountDetail(mounts[0])
		return
	}
	printMountDetail(selectMountIn(mounts, hint))
}

func printMountTable(mounts []*mount.MountInfo) {
	owner := currentOwnerID()
	foreign := false
	for _, m := range mounts {
		state := "stale"
		queue := ""
		if resp, err := mount.SendRequestNoEvict(m, "status"); err == nil && resp != nil && resp.OK {
			state = "offline"
			if resp.Online {
				state = "online"
			}
			queue = fmt.Sprintf(", %d pending, %d failed", resp.PendingCount, resp.FailedCount)
			if resp.FailedDownloadCount > 0 {
				queue += fmt.Sprintf(", %d downloads stalled", resp.FailedDownloadCount)
			}
		}
		marker := ""
		if m.Owner != "" && owner != "" && m.Owner != owner {
			marker = " [different account]"
			foreign = true
		}
		fmt.Printf("%s -> %s (%s, %s%s)%s\n", displayRemote(m.RemotePath), m.MountPoint, m.Mode, state, queue, marker)
	}
	fmt.Println()
	if foreign {
		output.PrintWarning("A mount was started by a different account. Stop it with 'pc mn stop <remote-path>'.")
	}
	output.PrintInfo("Detail with: pc mn status <remote-path>")
}

func printMountDetail(info *mount.MountInfo) {
	if info == nil {
		output.PrintInfo("Not mounted. Run 'pc mn start' to mount.")
		return
	}

	resp, err := mount.SendRequest(info, "status")
	if err != nil {
		output.PrintError("Mount daemon not reachable")
		ExitWithError()
	}
	if !resp.OK {
		output.PrintError("Status query failed: " + resp.Error)
		ExitWithError()
	}

	status := "online"
	if !resp.Online {
		status = "offline"
	}

	if owner := currentOwnerID(); info.Owner != "" && owner != "" && info.Owner != owner {
		output.PrintWarning("This mount was started by a different account. Run 'pc mn stop'.")
	}

	cacheUsedMB := resp.CacheUsed / (1024 * 1024)
	cacheMaxMB := resp.CacheMax / (1024 * 1024)

	modeLabel := resp.Mode
	if modeLabel == "" {
		modeLabel = mount.ModeVirtual
	}

	fmt.Printf("Mount:   %s -> %s\n", resp.RemotePath, resp.MountPoint)
	fmt.Printf("Mode:    %s\n", modeLabel)
	if resp.SyncDir != "" {
		fmt.Printf("Folder:  %s\n", resp.SyncDir)
	}
	fmt.Printf("Status:  %s\n", status)
	fmt.Printf("Cache:   %d MB / %d MB\n", cacheUsedMB, cacheMaxMB)
	deferred := ""
	if resp.DeferredCount > 0 {
		deferred = fmt.Sprintf(" (%d deferred, next due in %ds)", resp.DeferredCount, resp.NextDueSeconds)
	}
	fmt.Printf("Queue:   %d pending%s, %d failed\n", resp.PendingCount, deferred, resp.FailedCount)
	if resp.FailedDownloadCount > 0 {
		fmt.Printf("Downloads: %d stalled\n", resp.FailedDownloadCount)
	}
	if resp.LastPoll != "" {
		fmt.Printf("Poll:    %s\n", resp.LastPoll)
	}
	fmt.Printf("Uptime:  %s\n", resp.Uptime)
	if resp.FailedCount > 0 || resp.FailedDownloadCount > 0 {
		fmt.Println()
		output.PrintInfo("Inspect with: pc mn files --issues, re-attempt with: pc mn retry")
	}
}

func runMountFiles(hint string) {
	withMount(hint, func(info *mount.MountInfo) {
		cacheDB, err := cache.Open(info.CacheDir)
		if err != nil {
			output.PrintError("Failed to read cache: " + err.Error())
			ExitWithError()
		}
		defer cacheDB.Close()

		if mnFilesIssuesOnly {
			issues, err := cacheDB.ListIssues()
			if err != nil {
				output.PrintError("Failed to list issues: " + err.Error())
				ExitWithError()
			}

			if len(issues) == 0 {
				output.PrintSuccess("No sync issues")
				return
			}

			rejected := 0
			failed := 0
			conflicts := 0
			for _, inode := range issues {
				switch inode.SyncStatus {
				case cache.StatusRejected:
					rejected++
				case cache.StatusFailed:
					failed++
				case cache.StatusConflict:
					conflicts++
				}
			}

			var parts []string
			if rejected > 0 {
				parts = append(parts, fmt.Sprintf("%d rejected", rejected))
			}
			if failed > 0 {
				parts = append(parts, fmt.Sprintf("%d failed", failed))
			}
			if conflicts > 0 {
				parts = append(parts, fmt.Sprintf("%d conflicts", conflicts))
			}
			fmt.Printf("%s:\n\n", strings.Join(parts, ", "))
			printInodeList(issues, false)
			if failed > 0 {
				fmt.Println()
				output.PrintInfo("Re-attempt after fixing the cause: pc mn retry [path]")
			}
			return
		}

		all, err := cacheDB.AllInodes()
		if err != nil {
			output.PrintError("Failed to list files: " + err.Error())
			ExitWithError()
		}

		if len(all) == 0 {
			output.PrintInfo("No cached files")
			return
		}

		fmt.Printf("Mount: %s -> %s\n\n", info.RemotePath, info.MountPoint)

		if mnFilesTree {
			printInodeTree(all)
		} else {
			printInodeList(all, false)
		}
	})
}

func printInodeList(inodes []*cache.Inode, _ bool) {
	maxName := 0
	for _, inode := range inodes {
		nameLen := len(inode.DisplayName) + 2
		if nameLen > maxName {
			maxName = nameLen
		}
	}
	if maxName < 10 {
		maxName = 10
	}

	for _, inode := range inodes {
		prefix := "  "
		if inode.IsDir {
			prefix = "D "
		}
		name := prefix + inode.DisplayName
		status := string(inode.SyncStatus)
		if inode.StatusReason != "" {
			status += ": " + inode.StatusReason
		}
		fmt.Printf("%-*s  %s\n", maxName, name, status)
	}
}

func printInodeTree(inodes []*cache.Inode) {
	type treeEntry struct {
		inode    *cache.Inode
		children []*treeEntry
	}

	root := &treeEntry{}
	lookup := map[string]*treeEntry{"": root}

	for _, inode := range inodes {
		entry := &treeEntry{inode: inode}

		parentPath := parentOf(inode.RemotePath)
		parent, ok := lookup[parentPath]
		if !ok {
			parent = root
		}
		parent.children = append(parent.children, entry)

		if inode.IsDir {
			lookup[inode.RemotePath] = entry
		}
	}

	type treeLine struct {
		label  string
		status string
	}

	var lines []treeLine
	var walk func(entries []*treeEntry, prefix string)
	walk = func(entries []*treeEntry, prefix string) {
		for i, entry := range entries {
			isLast := i == len(entries)-1
			connector := "├── "
			childPrefix := prefix + "│   "
			if isLast {
				connector = "└── "
				childPrefix = prefix + "    "
			}

			name := entry.inode.DisplayName
			if entry.inode.IsDir {
				name += "/"
			}
			label := prefix + connector + name

			status := string(entry.inode.SyncStatus)
			if entry.inode.StatusReason != "" {
				status += ": " + entry.inode.StatusReason
			}

			lines = append(lines, treeLine{label: label, status: status})

			if entry.inode.IsDir {
				walk(entry.children, childPrefix)
			}
		}
	}
	walk(root.children, "")

	maxLabel := 0
	for _, l := range lines {
		w := utf8.RuneCountInString(l.label)
		if w > maxLabel {
			maxLabel = w
		}
	}

	for _, l := range lines {
		w := utf8.RuneCountInString(l.label)
		padding := max(maxLabel-w+2, 2)
		fmt.Printf("%s%*s%s\n", l.label, padding, "", l.status)
	}
}

func parentOf(remotePath string) string {
	idx := strings.LastIndex(remotePath, "/")
	if idx < 0 {
		return ""
	}
	return remotePath[:idx]
}

func runMountPin(p string) {
	withMount(p, func(info *mount.MountInfo) {
		p = strings.TrimPrefix(p, "/")

		resp, err := mount.SendRequestWithPath(info, "pin", p)
		reportIPC("Pin", resp, err)
		output.PrintSuccess(fmt.Sprintf("Pinned: %s", p))
	})
}

func runMountUnpin(p string) {
	withMount(p, func(info *mount.MountInfo) {
		p = strings.TrimPrefix(p, "/")

		resp, err := mount.SendRequestWithPath(info, "unpin", p)
		reportIPC("Unpin", resp, err)
		output.PrintSuccess(fmt.Sprintf("Unpinned: %s", p))
	})
}

func runMountPinList() {
	withMount("", func(info *mount.MountInfo) {
		cacheDB, err := cache.Open(info.CacheDir)
		if err != nil {
			output.PrintError("Failed to read cache: " + err.Error())
			ExitWithError()
		}
		defer cacheDB.Close()

		pinned, err := cacheDB.ListPinned()
		if err != nil {
			output.PrintError("Failed to list pinned: " + err.Error())
			ExitWithError()
		}

		if len(pinned) == 0 {
			output.PrintInfo("No pinned files")
			return
		}

		for _, inode := range pinned {
			fmt.Printf("  %s\n", inode.RemotePath)
		}
	})
}

func runMountConflicts(hint string) {
	withMount(hint, func(info *mount.MountInfo) {
		cacheDB, err := cache.Open(info.CacheDir)
		if err != nil {
			output.PrintError("Failed to read cache: " + err.Error())
			ExitWithError()
		}
		defer cacheDB.Close()

		issues, err := cacheDB.ListIssues()
		if err != nil {
			output.PrintError("Failed to list conflicts: " + err.Error())
			ExitWithError()
		}

		var conflicts []*cache.Inode
		for _, inode := range issues {
			if inode.SyncStatus == cache.StatusConflict {
				conflicts = append(conflicts, inode)
			}
		}

		if len(conflicts) == 0 {
			output.PrintSuccess("No conflicts")
			return
		}

		fmt.Printf("%d conflict(s): changed both locally and remotely\n\n", len(conflicts))
		printInodeList(conflicts, false)
		fmt.Println()
		output.PrintInfo("Settle with: pc mn resolve <path> -k local|remote|both")
	})
}

func runMountResolve(remotePath string) {
	withMount(remotePath, func(info *mount.MountInfo) {
		keep := strings.ToLower(mnResolveKeep)
		if keep != "local" && keep != "remote" && keep != "both" {
			output.PrintError("--keep must be local, remote, or both")
			ExitWithError()
		}

		remotePath = strings.TrimPrefix(remotePath, "/")

		if keep == "remote" && !mnResolveForce {
			fmt.Printf("Discard your local edit of %s and re-download the remote file? [y/N] ", remotePath)
			reader := bufio.NewReader(os.Stdin)
			line, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(line)) != "y" {
				output.PrintInfo("Cancelled")
				return
			}
		}

		resp, err := mount.SendResolve(info, remotePath, keep)
		reportIPC("Resolve", resp, err)

		switch keep {
		case "local":
			output.PrintSuccess(fmt.Sprintf("Kept local edit of %s; upload queued", remotePath))
		case "remote":
			output.PrintSuccess(fmt.Sprintf("Discarded local edit of %s; re-downloading", remotePath))
		case "both":
			output.PrintSuccess(fmt.Sprintf("Kept local edit as a conflict copy; re-downloading %s", remotePath))
		}
	})
}

func runMountClean(hint string) {
	withMount(hint, func(info *mount.MountInfo) {
		resp, err := mount.SendRequest(info, "clean")
		reportIPC("Clean", resp, err)
		mount.RemoveFatalLog(info.Owner, info.RemotePath)

		if resp.Cleaned == 0 {
			output.PrintInfo("No rejected files to clean")
		} else {
			output.PrintSuccess(fmt.Sprintf("Removed %d rejected file(s)", resp.Cleaned))
		}
	})
}

func runMountRetry(hint string) {
	withMount(hint, func(info *mount.MountInfo) {
		path := ""
		if hint != "" && !sameRemote(hint, info.RemotePath) {
			path = strings.TrimPrefix(hint, "/")
		}

		resp, err := mount.SendRetry(info, path)
		reportIPC("Retry", resp, err)

		switch {
		case resp.Retried == 0 && path != "":
			output.PrintInfo(path + " has no failed transfer to retry")
		case resp.Retried == 0:
			output.PrintInfo("No failed transfers to retry")
		default:
			output.PrintSuccess(fmt.Sprintf("Re-queued %d failed transfer(s)", resp.Retried))
		}
	})
}

func defaultMountPoint() string {
	if runtime.GOOS == "windows" {
		for _, letter := range "PQRSTUVWXYZ" {
			drive := string(letter) + ":"
			if _, err := os.Stat(drive + "\\"); os.IsNotExist(err) {
				return drive
			}
		}
		return "P:"
	}
	home, _ := os.UserHomeDir()
	return home + "/pigcloud"
}

func promptSyncDir(ownerID, remotePath, defaultDir string, syncPaths mount.SyncPaths) {
	label := remotePath
	if label == "/" || label == "" {
		label = "/ (root)"
	}

	fmt.Printf("First sync of %s\n", label)
	fmt.Printf("Default folder: %s\n", defaultDir)
	fmt.Print("Custom path (Enter to use default): ")

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return
	}

	input := strings.TrimSpace(line)
	if input == "" {
		return
	}

	absPath, err := filepath.Abs(input)
	if err != nil {
		output.PrintError("Invalid path: " + err.Error())
		ExitWithError()
	}

	if err := os.MkdirAll(absPath, 0700); err != nil {
		output.PrintError("Cannot create directory: " + err.Error())
		ExitWithError()
	}

	if o := mount.SyncDirOwner(absPath); o != "" && o != ownerID {
		output.PrintError("That folder is the sync folder of a different account. Pick another one.")
		ExitWithError()
	}

	syncPaths.SetSyncDir(ownerID, remotePath, absPath)
	if err := syncPaths.Save(); err != nil {
		output.PrintError("Failed to save sync config: " + err.Error())
		ExitWithError()
	}

	output.PrintSuccess(fmt.Sprintf("Sync folder set to %s", absPath))
}

func runMountMv(hint string) {
	syncPaths := mount.LoadSyncPaths()
	ownerID := currentOwnerID()

	mounts := ownedMounts()
	var info *mount.MountInfo
	remotePath := "/"
	switch {
	case hint != "":
		remotePath = hint
		info = mount.FindMount(ownerID, hint)
	case len(mounts) == 1:
		info = mounts[0]
		remotePath = info.RemotePath
	case len(mounts) > 1:
		printMountChoices(mounts)
		ExitWithError()
	}

	currentDir := syncPaths.GetSyncDir(ownerID, remotePath)
	destDir, err := filepath.Abs(mnMvDest)
	if err != nil {
		output.PrintError("Invalid destination: " + err.Error())
		ExitWithError()
	}

	if currentDir == destDir {
		output.PrintInfo("Source and destination are the same")
		return
	}

	srcInfo, err := os.Stat(currentDir)
	if err != nil {
		output.PrintError(fmt.Sprintf("Current sync folder not found: %s", currentDir))
		ExitWithError()
	}

	if !mnMvForce {
		size := dirSize(currentDir)
		sizeMB := size / (1024 * 1024)

		fmt.Printf("Move sync folder for %s\n", remotePath)
		fmt.Printf("  From: %s\n", currentDir)
		fmt.Printf("  To:   %s\n", destDir)
		if sizeMB > 0 {
			fmt.Printf("  Size: %d MB\n", sizeMB)
		}
		fmt.Print("\nProceed? [y/N] ")

		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			output.PrintInfo("Cancelled")
			return
		}
	}

	wasRunning := false
	if info != nil && mount.IsMountReachable(info) {
		output.PrintInfo("Stopping mount daemon...")
		stopEntry(info)
		wasRunning = true
	}

	if err := os.MkdirAll(filepath.Dir(destDir), 0700); err != nil {
		output.PrintError("Cannot create destination parent: " + err.Error())
		ExitWithError()
	}

	if _, err := os.Stat(destDir); err == nil {
		output.PrintError(fmt.Sprintf("Destination already exists: %s", destDir))
		ExitWithError()
	}

	_ = srcInfo
	if err := os.Rename(currentDir, destDir); err != nil {
		output.PrintInfo("Cross-device move, copying files...")
		if err := copyDir(currentDir, destDir); err != nil {
			output.PrintError("Copy failed: " + err.Error())
			ExitWithError()
		}
		os.RemoveAll(currentDir)
	}

	syncPaths.SetSyncDir(ownerID, remotePath, destDir)
	if err := syncPaths.Save(); err != nil {
		output.PrintError("Failed to save sync config: " + err.Error())
		ExitWithError()
	}

	mount.HideMetaDir(destDir)

	output.PrintSuccess(fmt.Sprintf("Moved sync folder to %s", destDir))

	if wasRunning {
		output.PrintInfo(fmt.Sprintf("Restart with 'pc mn start %s' to resume syncing", displayRemote(remotePath)))
	}
}

func dirSize(path string) int64 {
	var size int64
	filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			size += info.Size()
		}
		return nil
	})
	return size
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		destPath := filepath.Join(dst, rel)

		if d.IsDir() {
			return os.MkdirAll(destPath, 0700)
		}

		return copyFile(path, destPath)
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
