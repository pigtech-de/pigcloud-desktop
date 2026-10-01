package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/syncer"
	"pigcloud/internal/mount/vfs"
	"strings"
	"sync"
	"syscall"
	"time"
)

func isMutatingIPC(action string) bool {
	switch action {
	case "pin", "unpin", "flush", "clean", "resolve", "retry":
		return true
	}
	return false
}

func drainIPC(wg *sync.WaitGroup, name string) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(mount.FlushDeadline):
		mlog.Warnf("%s: IPC handlers still busy after %v; proceeding with shutdown", name, mount.FlushDeadline)
	}
}

type mutationGate struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func (g *mutationGate) begin() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.wg.Add(1)
	return true
}

func (g *mutationGate) end() { g.wg.Done() }

func (g *mutationGate) close() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

func (g *mutationGate) drain(name string) { drainIPC(&g.wg, name) }

func (g *mutationGate) run(fn func()) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	fn()
	return true
}

type Daemon struct {
	vfs       *vfs.VFS
	cacheDB   *cache.DB
	store     *cache.Store
	evictor   *cache.Evictor
	backend   mount.MountBackend
	poller    *syncer.Poller
	writeback *syncer.WritebackProcessor

	mountPoint string
	remotePath string
	cacheDir   string
	cacheMax   int64
	startedAt  time.Time
	token      string
	mountInfo  *mount.MountInfo

	shutdownOnce sync.Once
	shutdownCh   chan struct{}

	gate mutationGate
}

func (d *Daemon) beginMutation() bool { return d.gate.begin() }

type Config struct {
	MountPoint        string
	RemotePath        string
	CacheSize         int64
	PollInterval      time.Duration
	PublicKey         *crypto.PublicKeySet
	PrivateKey        *crypto.PrivateKeySet
	NameKey           []byte
	SigningPublicKey  *crypto.SigningPublicKeySet
	SigningPrivateKey *crypto.SigningPrivateKeySet
	Mode              string
	ReadOnly          bool
}

func (cfg *Config) ownerID() string {
	if cfg.PublicKey == nil {
		return ""
	}
	return crypto.AccountFingerprint(cfg.PublicKey.X25519[:])
}

var logFile string

func ServeVirtual(cfg *Config) error {
	logFile = mount.MountLogPath(cfg.ownerID(), cfg.RemotePath)
	if lf, err := mlog.NewRotatingLog(logFile); err == nil {
		mlog.SetOutput(lf)
		defer lf.Close()
	}
	mlog.Infof("mount daemon starting: remote=%s mountpoint=%s level=%s", cfg.RemotePath, cfg.MountPoint, mlog.CurrentLevel())

	defer mlog.RecoverPanic("mount daemon")

	mountID := make([]byte, 8)
	rand.Read(mountID)
	cacheDir := filepath.Join(mount.DataDir(), "mount-cache", hex.EncodeToString(mountID))
	mount.CleanStaleMountCaches(cacheDir)

	rt, err := openMountRuntime(cfg, cacheDir, "", "mount daemon")
	if err != nil {
		return err
	}

	backend := mount.NewBackend()

	d := &Daemon{
		vfs:        rt.vfs,
		cacheDB:    rt.cacheDB,
		store:      rt.store,
		evictor:    rt.evictor,
		backend:    backend,
		poller:     rt.poller,
		writeback:  rt.writeback,
		mountPoint: cfg.MountPoint,
		remotePath: cfg.RemotePath,
		cacheDir:   cacheDir,
		cacheMax:   cfg.CacheSize,
		startedAt:  time.Now(),
		shutdownCh: make(chan struct{}),
	}

	listener, token, port, err := listenIPC()
	if err != nil {
		d.cleanup()
		return err
	}
	d.token = token

	info := &mount.MountInfo{
		Port:       port,
		Token:      d.token,
		PID:        os.Getpid(),
		MountPoint: cfg.MountPoint,
		RemotePath: cfg.RemotePath,
		CacheDir:   cacheDir,
		Mode:       mount.ModeVirtual,
		Owner:      cfg.ownerID(),
		Endpoint:   rt.client.Endpoint(),
		StartedAt:  d.startedAt,
	}
	if err := mount.WriteMountEntry(info); err != nil {
		listener.Close()
		d.cleanup()
		return fmt.Errorf("write mount entry: %w", err)
	}
	d.mountInfo = info

	rt.poller.Start()
	rt.writeback.Start()

	go d.acceptIPC(listener)

	sigCtx, sigStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigStop()
	go func() {
		<-sigCtx.Done()
		mlog.Infof("mount daemon: shutdown signal received")
		d.shutdown()
	}()

	mlog.Infof("mount daemon ready: pid=%d port=%d mountpoint=%s", os.Getpid(), port, cfg.MountPoint)

	mountErr := backend.Mount(cfg.MountPoint, rt.vfs)

	if mountErr != nil {
		mlog.Errorf("mount returned error: %v", mountErr)
	} else {
		mlog.Infof("mount returned (unmounted)")
	}

	d.shutdown()
	listener.Close()

	mlog.Infof("mount daemon exiting")
	return mountErr
}

func (d *Daemon) acceptIPC(listener net.Listener) { acceptIPC(d, listener) }

func (d *Daemon) handleConn(conn net.Conn) { handleIPCConn(d, conn) }

func (d *Daemon) ipcName() string                { return "mount daemon" }
func (d *Daemon) ipcToken() string               { return d.token }
func (d *Daemon) ipcShutdownCh() <-chan struct{} { return d.shutdownCh }
func (d *Daemon) endMutation()                   { d.gate.end() }
func (d *Daemon) setPinned(remotePath string, pinned bool) {
	d.cacheDB.SetPinned(remotePath, pinned)
}
func (d *Daemon) flushWriteback(budget time.Duration) (syncer.FlushResult, error) {
	return d.writeback.FlushAll(budget)
}
func (d *Daemon) cleanRejected() (int, error) { return d.vfs.CleanRejected() }

func (d *Daemon) handleExtra(mount.DaemonRequest, *json.Encoder) bool { return false }

func (d *Daemon) retryFailed(remotePath string) (int, error) {
	cleared, err := cache.ClearFailedTransfers(d.cacheDB, strings.TrimPrefix(remotePath, "/"))
	if err != nil {
		return 0, err
	}
	for _, in := range cleared {
		d.cacheDB.SetSyncStatus(in.ID, cache.StatusPending, "")
		if node := d.vfs.NodeByID(in.ID); node != nil {
			node.Mu.Lock()
			node.SyncStatus = cache.StatusPending
			node.StatusReason = ""
			node.Mu.Unlock()
		}
	}
	return len(cleared), nil
}

func (d *Daemon) handleStatus(enc *json.Encoder) {
	cacheUsed := cache.CacheBytes(d.cacheDB, d.store)
	pending, _ := d.cacheDB.PendingWritebackCount()
	failed, _ := d.cacheDB.FailedWritebackCount()
	deferred, nextDue := deferredQueue(d.cacheDB)

	lastPoll := d.poller.LastPoll()
	lastPollStr := ""
	if !lastPoll.IsZero() {
		lastPollStr = fmt.Sprintf("%ds ago", int(time.Since(lastPoll).Seconds()))
	}

	uptime := time.Since(d.startedAt).Round(time.Second).String()

	enc.Encode(mount.DaemonResponse{
		OK:             true,
		Online:         d.poller.IsOnline(),
		MountPoint:     d.mountPoint,
		RemotePath:     "/" + mount.NormalizeRemotePath(d.remotePath),
		Mode:           mount.ModeVirtual,
		CacheUsed:      cacheUsed,
		CacheMax:       d.cacheMax,
		PendingCount:   pending,
		FailedCount:    failed,
		DeferredCount:  deferred,
		NextDueSeconds: nextDue,
		LastPoll:       lastPollStr,
		Uptime:         uptime,
	})
}

func (d *Daemon) shutdown() {
	d.shutdownOnce.Do(func() {
		close(d.shutdownCh)
		d.vfs.Shutdown()

		d.gate.close()
		d.gate.drain("mount daemon")

		d.writeback.FlushAll(mount.FlushBudget)
		d.writeback.Stop()
		d.poller.Stop()

		d.backend.Unmount()

		d.cleanup()
	})
}

func (d *Daemon) cleanup() {
	d.store.Close()
	d.cacheDB.Close()
	mount.EvictMountEntry(d.mountInfo)
	if d.cacheDir != "" {
		os.RemoveAll(d.cacheDir)
	}
}
