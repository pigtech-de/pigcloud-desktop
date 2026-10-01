package cache

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	cacheSizeGiB = 1024 * 1024 * 1024

	DefaultMaxSize = 5 * cacheSizeGiB

	evictionTarget = 0.90

	evictionBatchSize = 100

	tempFileGrace = time.Hour
)

func ParseCacheSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return DefaultMaxSize, nil
	}

	s = strings.TrimSuffix(s, "IB")
	s = strings.TrimSuffix(s, "B")

	multiplier := int64(1)
	numStr := s

	if len(s) > 0 {
		suffix := s[len(s)-1]
		switch suffix {
		case 'K':
			multiplier = 1024
			numStr = s[:len(s)-1]
		case 'M':
			multiplier = 1024 * 1024
			numStr = s[:len(s)-1]
		case 'G':
			multiplier = 1024 * 1024 * 1024
			numStr = s[:len(s)-1]
		case 'T':
			multiplier = 1024 * 1024 * 1024 * 1024
			numStr = s[:len(s)-1]
		}
	}

	numStr = strings.TrimSpace(numStr)

	value, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cache size %q", s)
	}
	if value <= 0 {
		return 0, fmt.Errorf("cache size must be positive")
	}

	return int64(value * float64(multiplier)), nil
}

func ReleaseBlob(db *DB, store *Store, hash string, excludeID int64) {
	if hash == "" || db == nil || store == nil {
		return
	}
	n, err := db.CountCachedByHash(hash, excludeID)
	if err != nil || n > 0 {
		return
	}
	store.Remove(hash)
}

type GCSweep struct {
	Blobs int
	Temps int
}

func GCOrphans(db *DB, store *Store) (GCSweep, error) {
	var swept GCSweep

	referenced, err := db.AllCachedHashes()
	if err != nil {
		return swept, err
	}
	hashes, err := store.ListHashes()
	if err != nil {
		return swept, err
	}

	for _, h := range hashes {
		if referenced[h] {
			continue
		}
		if store.Remove(h) == nil {
			swept.Blobs++
		}
	}
	swept.Temps, err = store.GCTempFiles(tempFileGrace)
	if err != nil {
		return swept, err
	}
	return swept, nil
}

type Evictor struct {
	db      *DB
	store   *Store
	maxSize int64

	inUse   func(id int64) bool
	onEvict func(id int64)
}

func NewEvictor(db *DB, store *Store, maxSize int64) *Evictor {
	return &Evictor{db: db, store: store, maxSize: maxSize}
}

func (e *Evictor) SetHooks(inUse func(id int64) bool, onEvict func(id int64)) {
	e.inUse = inUse
	e.onEvict = onEvict
}

func CacheBytes(db *DB, store *Store) int64 {
	if store != nil {
		return store.Bytes()
	}
	if db == nil {
		return 0
	}
	n, _ := db.TotalCacheSize()
	return n
}

func (e *Evictor) RunIfNeeded() (int, error) {
	totalSize := CacheBytes(e.db, e.store)
	if totalSize <= e.maxSize {
		return 0, nil
	}

	return e.evict(totalSize)
}

func (e *Evictor) evict(currentSize int64) (int, error) {
	targetSize := int64(float64(e.maxSize) * evictionTarget)
	evicted := 0

	for currentSize > targetSize {
		candidates, err := e.db.LRUEvictionCandidates(evictionBatchSize)
		if err != nil {
			return evicted, fmt.Errorf("get eviction candidates: %w", err)
		}
		if len(candidates) == 0 {
			break
		}

		progressed := false
		for _, inode := range candidates {
			if currentSize <= targetSize {
				break
			}
			if e.inUse != nil && e.inUse(inode.ID) {
				continue
			}

			ReleaseBlob(e.db, e.store, inode.ContentHash, inode.ID)

			if err := e.db.InvalidateCache(inode.ID); err != nil {
				return evicted, fmt.Errorf("invalidate cache for %s: %w", inode.RemotePath, err)
			}
			if e.onEvict != nil {
				e.onEvict(inode.ID)
			}

			currentSize = CacheBytes(e.db, e.store)
			evicted++
			progressed = true
		}
		if !progressed {
			break
		}
	}

	return evicted, nil
}

func (e *Evictor) ForceEvict() (int, error) {
	evicted := 0
	for {
		candidates, err := e.db.LRUEvictionCandidates(evictionBatchSize)
		if err != nil {
			return evicted, err
		}
		if len(candidates) == 0 {
			break
		}

		progressed := false
		for _, inode := range candidates {
			if e.inUse != nil && e.inUse(inode.ID) {
				continue
			}
			ReleaseBlob(e.db, e.store, inode.ContentHash, inode.ID)
			if err := e.db.InvalidateCache(inode.ID); err != nil {
				return evicted, err
			}
			if e.onEvict != nil {
				e.onEvict(inode.ID)
			}
			evicted++
			progressed = true
		}
		if !progressed {
			break
		}
	}

	return evicted, nil
}
