package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/syncer"
	"pigcloud/internal/mount/vfs"
	"pigcloud/internal/netutil"
)

type mountRuntime struct {
	cacheDB   *cache.DB
	store     *cache.Store
	evictor   *cache.Evictor
	client    *api.Client
	vfs       *vfs.VFS
	poller    *syncer.Poller
	writeback *syncer.WritebackProcessor
}

func openMountRuntime(cfg *Config, dir, syncDir, label string) (*mountRuntime, error) {
	cacheDB, err := cache.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("open cache DB: %w", err)
	}

	store, err := cache.NewStore(dir)
	if err != nil {
		cacheDB.Close()
		return nil, fmt.Errorf("create cache store: %w", err)
	}

	if n, err := cacheDB.RequeueInProgress(); err == nil && n > 0 {
		mlog.Infof("%s: requeued %d stranded writeback entries", label, n)
	}
	if swept, err := cache.GCOrphans(cacheDB, store); err == nil {
		if swept.Blobs > 0 {
			mlog.Infof("%s: removed %d orphan cache blobs", label, swept.Blobs)
		}
		if swept.Temps > 0 {
			mlog.Infof("%s: removed %d stranded cache temp files", label, swept.Temps)
		}
	}

	evictor := cache.NewEvictor(cacheDB, store, cfg.CacheSize)
	client := api.NewClient()

	v := vfs.New(cfg.RemotePath, cacheDB, store, evictor, client,
		cfg.PublicKey, cfg.PrivateKey, cfg.NameKey, cfg.SigningPublicKey, cfg.SigningPrivateKey)
	v.SetReadOnly(cfg.ReadOnly)

	return &mountRuntime{
		cacheDB:   cacheDB,
		store:     store,
		evictor:   evictor,
		client:    client,
		vfs:       v,
		poller:    syncer.NewPoller(v, client, cacheDB, cfg.PollInterval),
		writeback: syncer.NewWritebackProcessor(v, client, cacheDB, store, syncDir),
	}, nil
}

func listenIPC() (net.Listener, string, int, error) {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	listener, err := net.Listen("tcp", netutil.LoopbackAny)
	if err != nil {
		return nil, "", 0, fmt.Errorf("start IPC server: %w", err)
	}
	return listener, token, listener.Addr().(*net.TCPAddr).Port, nil
}
