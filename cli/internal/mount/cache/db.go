package cache

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"pigcloud/internal/api"

	_ "modernc.org/sqlite"
)

type SyncStatus string

const (
	StatusSynced   SyncStatus = "synced"
	StatusPending  SyncStatus = "pending"
	StatusRejected SyncStatus = "rejected"
	StatusFailed   SyncStatus = "failed"
	StatusConflict SyncStatus = "conflict"
	StatusOffline  SyncStatus = "offline"
)

type Inode struct {
	ID          int64
	RemotePath  string
	DisplayName string
	IsDir       bool
	Size        int64
	Mtime       int64
	Cached      bool
	Dirty       bool
	Pinned      bool
	LastAccess  int64
	ContentHash string
	LocalHash    string
	LocalMtime   int64
	SealedKey    string
	EncMeta      string
	Etag         string
	ParentID     int64
	SyncStatus   SyncStatus
	StatusReason string
}

const (
	FailureDownload = "download"
	FailureUpload   = "upload"
)

type SyncFailure struct {
	InodeID     int64
	Kind        string
	Permanent   bool
	Attempts    int
	NextRetryAt int64
	LastError   string
}

type WritebackEntry struct {
	ID         int64
	InodeID    int64
	Action     string
	RemotePath string
	ExtraJSON  string
	EnqueuedAt int64
	Attempts   int
	LastError  string
	Status     string
}

var ErrReadOnlyMount = errors.New("mount is read-only; nothing is uploaded")

type DB struct {
	db      *sql.DB
	writeMu sync.Mutex
	closed  bool
	writebackDisabled bool
}

func (d *DB) SetWritebackDisabled(v bool) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.writebackDisabled = v
}

func (d *DB) WritebackDisabled() bool {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.writebackDisabled
}

func Open(cacheDir string) (*DB, error) {
	dbPath := filepath.Join(cacheDir, "mount_cache.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &DB{db: db}, nil
}

func (d *DB) Close() error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.closed = true
	return d.db.Close()
}

var migrationSteps = []string{
	`CREATE TABLE IF NOT EXISTS sync_failures (
	    inode_id      INTEGER NOT NULL,
	    kind          TEXT    NOT NULL,
	    permanent     INTEGER NOT NULL DEFAULT 0,
	    attempts      INTEGER NOT NULL DEFAULT 0,
	    next_retry_at INTEGER NOT NULL DEFAULT 0,
	    last_error    TEXT    NOT NULL DEFAULT '',
	    PRIMARY KEY (inode_id, kind)
	);`,
	`ALTER TABLE inodes ADD COLUMN local_hash TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE inodes ADD COLUMN local_mtime INTEGER NOT NULL DEFAULT 0;`,
	`ALTER TABLE inodes ADD COLUMN download_baseline_hash TEXT NOT NULL DEFAULT '';`,
	`ALTER TABLE inodes ADD COLUMN local_remote_etag TEXT NOT NULL DEFAULT '';
	 UPDATE inodes SET local_remote_etag = etag WHERE local_hash != '';`,
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(baseSchema); err != nil {
		return err
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for v := version; v < len(migrationSteps); v++ {
		if _, err := db.Exec(migrationSteps[v]); err != nil {
			return fmt.Errorf("apply migration %d: %w", v+1, err)
		}
	}
	if version < len(migrationSteps) {
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", len(migrationSteps))); err != nil {
			return fmt.Errorf("set schema version: %w", err)
		}
	}
	return nil
}

const baseSchema = `
CREATE TABLE IF NOT EXISTS inodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    remote_path   TEXT    NOT NULL UNIQUE,
    display_name  TEXT    NOT NULL,
    is_dir        INTEGER NOT NULL DEFAULT 0,
    size          INTEGER NOT NULL DEFAULT 0,
    mtime         INTEGER NOT NULL DEFAULT 0,
    cached        INTEGER NOT NULL DEFAULT 0,
    dirty         INTEGER NOT NULL DEFAULT 0,
    pinned        INTEGER NOT NULL DEFAULT 0,
    last_access   INTEGER NOT NULL DEFAULT 0,
    content_hash  TEXT    NOT NULL DEFAULT '',
    sealed_key    TEXT    NOT NULL DEFAULT '',
    enc_meta      TEXT    NOT NULL DEFAULT '',
    etag          TEXT    NOT NULL DEFAULT '',
    parent_id     INTEGER NOT NULL DEFAULT 0,
    sync_status   TEXT    NOT NULL DEFAULT 'synced',
    status_reason TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_inodes_parent ON inodes(parent_id);
CREATE INDEX IF NOT EXISTS idx_inodes_dirty  ON inodes(dirty) WHERE dirty = 1;
CREATE INDEX IF NOT EXISTS idx_inodes_lru    ON inodes(last_access) WHERE cached = 1 AND pinned = 0;
CREATE INDEX IF NOT EXISTS idx_inodes_status ON inodes(sync_status) WHERE sync_status != 'synced';

CREATE TABLE IF NOT EXISTS writeback_queue (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    inode_id    INTEGER NOT NULL,
    action      TEXT    NOT NULL,
    remote_path TEXT    NOT NULL,
    extra_json  TEXT    NOT NULL DEFAULT '',
    enqueued_at INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_wb_status ON writeback_queue(status, enqueued_at);
`

func (d *DB) GetInode(id int64) (*Inode, error) {
	return scanInodeRow(d.db.QueryRow(
		`SELECT `+inodeColumns+` FROM inodes WHERE id = ?`, id))
}

func (d *DB) GetInodeByPath(remotePath string) (*Inode, error) {
	return scanInodeRow(d.db.QueryRow(
		`SELECT `+inodeColumns+` FROM inodes WHERE remote_path = ?`, remotePath))
}

func (d *DB) ListChildren(parentID int64) ([]*Inode, error) {
	rows, err := d.db.Query(
		`SELECT `+inodeColumns+` FROM inodes WHERE parent_id = ? ORDER BY is_dir DESC, display_name ASC`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectInodes(rows)
}

func (d *DB) UpsertInode(inode *Inode) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	isDir := 0
	if inode.IsDir {
		isDir = 1
	}
	cached := 0
	if inode.Cached {
		cached = 1
	}
	dirty := 0
	if inode.Dirty {
		dirty = 1
	}
	pinned := 0
	if inode.Pinned {
		pinned = 1
	}

	var id int64
	err := d.db.QueryRow(`
		INSERT INTO inodes (remote_path, display_name, is_dir, size, mtime, cached, dirty,
		                     pinned, last_access, content_hash, local_hash, local_mtime, sealed_key, enc_meta, etag,
		                     parent_id, sync_status, status_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(remote_path) DO UPDATE SET
		    display_name  = excluded.display_name,
		    is_dir        = excluded.is_dir,
		    size          = excluded.size,
		    mtime         = excluded.mtime,
		    cached        = excluded.cached,
		    -- Never clear a persisted pending-edit flag on a listing rebuild; only
		    -- an explicit MarkSynced clears dirty. The prune guard depends on it.
		    dirty         = (inodes.dirty OR excluded.dirty),
		    content_hash  = excluded.content_hash,
		    -- Most callers rebuild an Inode from a listing and know nothing about
		    -- local content, so an empty value means "unchanged", not "forget".
		    -- Clearing is explicit: SetLocalContent or InvalidateCache.
		    local_hash    = COALESCE(NULLIF(excluded.local_hash, ''), inodes.local_hash),
		    local_mtime   = COALESCE(NULLIF(excluded.local_mtime, 0), inodes.local_mtime),
		    sealed_key    = excluded.sealed_key,
		    enc_meta      = excluded.enc_meta,
		    etag          = COALESCE(NULLIF(excluded.etag, ''), inodes.etag),
		    parent_id     = excluded.parent_id,
		    sync_status   = excluded.sync_status,
		    status_reason = excluded.status_reason
		RETURNING id`,
		inode.RemotePath, inode.DisplayName, isDir, inode.Size, inode.Mtime,
		cached, dirty, pinned, inode.LastAccess, inode.ContentHash, inode.LocalHash, inode.LocalMtime,
		inode.SealedKey, inode.EncMeta, inode.Etag, inode.ParentID,
		string(inode.SyncStatus), inode.StatusReason).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (d *DB) DeleteInode(remotePath string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("DELETE FROM inodes WHERE remote_path = ?", remotePath)
	return err
}

func (d *DB) DeleteChildren(parentID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("DELETE FROM inodes WHERE parent_id = ?", parentID)
	return err
}

func (d *DB) MarkDirty(id int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET dirty = 1, sync_status = 'pending' WHERE id = ?", id)
	return err
}

func (d *DB) MarkSynced(id int64, etag string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec(
		"UPDATE inodes SET dirty = 0, sync_status = 'synced', status_reason = '', etag = ? WHERE id = ?",
		etag, id)
	return err
}

func (d *DB) MarkCached(id int64, contentHash string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	now := time.Now().Unix()
	_, err := d.db.Exec(
		"UPDATE inodes SET cached = 1, content_hash = ?, last_access = ? WHERE id = ?",
		contentHash, now, id)
	return err
}

func (d *DB) SetInodeSize(id int64, size int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET size = ? WHERE id = ?", size, id)
	return err
}

func (d *DB) SetLocalContent(id int64, hash string, mtime int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if hash == "" {
		mtime = 0
	}
	_, err := d.db.Exec("UPDATE inodes SET local_hash = ?, local_mtime = ?, download_baseline_hash = ?, local_remote_etag = CASE WHEN ? = '' THEN '' ELSE etag END WHERE id = ?", hash, mtime, hash, hash, id)
	return err
}

func (d *DB) InvalidateCache(id int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec(
		"UPDATE inodes SET download_baseline_hash = CASE WHEN local_hash != '' THEN local_hash ELSE download_baseline_hash END, cached = 0, content_hash = '', local_hash = '', local_mtime = 0 WHERE id = ?", id)
	return err
}

func (d *DB) TouchAccess(id int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET last_access = ? WHERE id = ?", time.Now().Unix(), id)
	return err
}

func (d *DB) SetSyncStatus(id int64, status SyncStatus, reason string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec(
		"UPDATE inodes SET sync_status = ?, status_reason = ? WHERE id = ?",
		string(status), reason, id)
	return err
}

func (d *DB) SetPinned(remotePath string, pinned bool) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	val := 0
	if pinned {
		val = 1
	}
	_, err := d.db.Exec("UPDATE inodes SET pinned = ? WHERE remote_path = ?", val, remotePath)
	return err
}

func (d *DB) ListPinned() ([]*Inode, error) {
	rows, err := d.db.Query(
		`SELECT ` + inodeColumns + ` FROM inodes WHERE pinned = 1 ORDER BY remote_path ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectInodes(rows)
}

func (d *DB) ListIssues() ([]*Inode, error) {
	rows, err := d.db.Query(
		`SELECT ` + inodeColumns + ` FROM inodes WHERE sync_status NOT IN ('synced', 'pending')
		 ORDER BY remote_path ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectInodes(rows)
}

func (d *DB) InodesWithFailures() ([]*Inode, error) {
	rows, err := d.db.Query(
		`SELECT ` + inodeColumns + ` FROM inodes
		 WHERE sync_status = 'failed'
		    OR id IN (SELECT inode_id FROM sync_failures)
		 ORDER BY remote_path ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectInodes(rows)
}

func (d *DB) hasFailureLatch(in *Inode) bool {
	if in.SyncStatus == StatusFailed {
		return true
	}
	for _, kind := range []string{FailureUpload, FailureDownload} {
		if f, err := d.GetSyncFailure(in.ID, kind); err == nil && f != nil {
			return true
		}
	}
	return false
}

func (d *DB) CountByStatus() (map[SyncStatus]int, error) {
	rows, err := d.db.Query("SELECT sync_status, COUNT(*) FROM inodes GROUP BY sync_status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := make(map[SyncStatus]int)
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return nil, err
		}
		counts[SyncStatus(status)] = count
	}
	return counts, rows.Err()
}

func (d *DB) EnqueueWriteback(inodeID int64, action, remotePath, extraJSON string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.writebackDisabled {
		return ErrReadOnlyMount
	}
	if action == "upload" && UploadKeyFromExtra(extraJSON) == "" {
		extraJSON = MarshalUploadExtra(api.NewUploadIdempotencyKey())
	}
	if action != "rename" {
		if _, err := d.db.Exec(
			"DELETE FROM writeback_queue WHERE inode_id = ? AND action = ? AND status = 'pending'",
			inodeID, action); err != nil {
			return err
		}
	}
	_, err := d.db.Exec(
		`INSERT INTO writeback_queue (inode_id, action, remote_path, extra_json, enqueued_at)
		 VALUES (?, ?, ?, ?, ?)`,
		inodeID, action, remotePath, extraJSON, time.Now().Unix())
	return err
}

func MarshalUploadExtra(key string) string {
	if key == "" {
		return ""
	}
	b, err := json.Marshal(struct {
		IdempotencyKey string `json:"idempotency_key"`
	}{key})
	if err != nil {
		return ""
	}
	return string(b)
}

func UploadKeyFromExtra(extraJSON string) string {
	if extraJSON == "" {
		return ""
	}
	var x struct {
		IdempotencyKey string `json:"idempotency_key"`
	}
	if err := json.Unmarshal([]byte(extraJSON), &x); err != nil {
		return ""
	}
	return x.IdempotencyKey
}

func (d *DB) DequeueWriteback(limit int, claimBefore int64) ([]*WritebackEntry, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	if claimBefore <= 0 {
		claimBefore = time.Now().Unix() + 1
	}

	rows, err := d.db.Query(
		`UPDATE writeback_queue SET status = 'in_progress'
		 WHERE id IN (
		     SELECT id FROM writeback_queue
		     WHERE status = 'pending' AND enqueued_at <= ?
		     ORDER BY enqueued_at ASC, id ASC LIMIT ?
		 )
		 RETURNING id, inode_id, action, remote_path, extra_json, enqueued_at, attempts, last_error, status`,
		claimBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*WritebackEntry
	for rows.Next() {
		var e WritebackEntry
		if err := rows.Scan(&e.ID, &e.InodeID, &e.Action, &e.RemotePath,
			&e.ExtraJSON, &e.EnqueuedAt, &e.Attempts, &e.LastError, &e.Status); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

func (d *DB) HasActiveWriteback(inodeID int64, action string) (bool, error) {
	var n int
	err := d.db.QueryRow(
		`SELECT COUNT(*) FROM writeback_queue
		 WHERE inode_id = ? AND action = ? AND status IN ('pending', 'in_progress')`,
		inodeID, action).Scan(&n)
	return n > 0, err
}

func (d *DB) RequeueInProgress() (int, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	result, err := d.db.Exec("UPDATE writeback_queue SET status = 'pending' WHERE status = 'in_progress'")
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

func (d *DB) UpdateWriteback(id int64, status, lastError string, attempts int) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec(
		"UPDATE writeback_queue SET status = ?, last_error = ?, attempts = ? WHERE id = ?",
		status, lastError, attempts, id)
	return err
}

func (d *DB) DeferWriteback(id int64, lastError string, attempts int, notBefore int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec(
		"UPDATE writeback_queue SET status = 'pending', last_error = ?, attempts = ?, enqueued_at = ? WHERE id = ?",
		lastError, attempts, notBefore, id)
	return err
}

func (d *DB) DeferredWritebackCount(horizon int64) (int, int64, error) {
	var count int
	var next sql.NullInt64
	err := d.db.QueryRow(
		`SELECT COUNT(*), MIN(enqueued_at) FROM writeback_queue
		 WHERE status = 'pending' AND enqueued_at > ?`, horizon).Scan(&count, &next)
	if err != nil {
		return 0, 0, err
	}
	if !next.Valid {
		return count, 0, nil
	}
	return count, next.Int64, nil
}

func (d *DB) DeleteWriteback(id int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("DELETE FROM writeback_queue WHERE id = ?", id)
	return err
}

func (d *DB) PendingWritebackCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM writeback_queue WHERE status = 'pending'").Scan(&count)
	return count, err
}

func (d *DB) FailedWritebackCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM writeback_queue WHERE status = 'failed'").Scan(&count)
	return count, err
}

const StalledDownloadAttempts = 3

func (d *DB) FailedDownloadCount() (int, error) {
	var count int
	err := d.db.QueryRow(
		"SELECT COUNT(*) FROM sync_failures WHERE kind = ? AND (permanent = 1 OR attempts >= ?)",
		FailureDownload, StalledDownloadAttempts).Scan(&count)
	return count, err
}

func (d *DB) DeleteWritebackByInode(inodeID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("DELETE FROM writeback_queue WHERE inode_id = ?", inodeID)
	return err
}

func (d *DB) DeleteFailedUploadWritebacks(inodeID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec(
		"DELETE FROM writeback_queue WHERE inode_id = ? AND action = 'upload' AND status = 'failed'",
		inodeID)
	return err
}

func (d *DB) DeleteFailedWritebacks() int {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	result, err := d.db.Exec("DELETE FROM writeback_queue WHERE status = 'failed'")
	if err != nil {
		return 0
	}
	n, _ := result.RowsAffected()
	return int(n)
}

func (d *DB) GetSyncFailure(inodeID int64, kind string) (*SyncFailure, error) {
	var f SyncFailure
	var permanent int
	err := d.db.QueryRow(
		`SELECT inode_id, kind, permanent, attempts, next_retry_at, last_error
		 FROM sync_failures WHERE inode_id = ? AND kind = ?`, inodeID, kind).Scan(
		&f.InodeID, &f.Kind, &permanent, &f.Attempts, &f.NextRetryAt, &f.LastError)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f.Permanent = permanent != 0
	return &f, nil
}

func (d *DB) RecordSyncFailure(f *SyncFailure) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	permanent := 0
	if f.Permanent {
		permanent = 1
	}
	_, err := d.db.Exec(
		`INSERT INTO sync_failures (inode_id, kind, permanent, attempts, next_retry_at, last_error)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(inode_id, kind) DO UPDATE SET
		     permanent     = excluded.permanent,
		     attempts      = excluded.attempts,
		     next_retry_at = excluded.next_retry_at,
		     last_error    = excluded.last_error`,
		f.InodeID, f.Kind, permanent, f.Attempts, f.NextRetryAt, f.LastError)
	return err
}

func (d *DB) ClearSyncFailure(inodeID int64, kind string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("DELETE FROM sync_failures WHERE inode_id = ? AND kind = ?", inodeID, kind)
	return err
}

func (d *DB) DeleteSyncFailures(inodeID int64) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("DELETE FROM sync_failures WHERE inode_id = ?", inodeID)
	return err
}

func (d *DB) EvictableCacheSize() (int64, error) {
	var size int64
	err := d.db.QueryRow(
		"SELECT COALESCE(SUM(size), 0) FROM inodes WHERE cached = 1 AND dirty = 0 AND pinned = 0").Scan(&size)
	return size, err
}

func (d *DB) TotalCacheSize() (int64, error) {
	var size int64
	err := d.db.QueryRow("SELECT COALESCE(SUM(size), 0) FROM inodes WHERE cached = 1").Scan(&size)
	return size, err
}

func (d *DB) CountCachedByHash(hash string, excludeID int64) (int, error) {
	var n int
	err := d.db.QueryRow(
		"SELECT COUNT(*) FROM inodes WHERE content_hash = ? AND cached = 1 AND id != ?",
		hash, excludeID).Scan(&n)
	return n, err
}

func (d *DB) AllCachedHashes() (map[string]bool, error) {
	rows, err := d.db.Query("SELECT DISTINCT content_hash FROM inodes WHERE cached = 1 AND content_hash != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	set := make(map[string]bool)
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		set[h] = true
	}
	return set, rows.Err()
}

func (d *DB) LRUEvictionCandidates(limit int) ([]*Inode, error) {
	rows, err := d.db.Query(
		`SELECT `+inodeColumns+` FROM inodes WHERE cached = 1 AND dirty = 0 AND pinned = 0
		 ORDER BY last_access ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectInodes(rows)
}

func (d *DB) AllInodes() ([]*Inode, error) {
	rows, err := d.db.Query(
		`SELECT ` + inodeColumns + ` FROM inodes ORDER BY remote_path ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return collectInodes(rows)
}

func (d *DB) DeleteRejected() ([]string, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	rows, err := d.db.Query(
		"SELECT content_hash FROM inodes WHERE sync_status = 'rejected' AND content_hash != ''")
	if err != nil {
		return nil, err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	_, err = d.db.Exec("DELETE FROM inodes WHERE sync_status = 'rejected'")
	return hashes, err
}

type rowScanner interface {
	Scan(dest ...any) error
}

const inodeColumns = `id, remote_path, display_name, is_dir, size, mtime, cached, dirty,
	pinned, last_access, content_hash, local_hash, local_mtime, sealed_key, enc_meta, etag,
	parent_id, sync_status, status_reason`

func collectInodes(rows *sql.Rows) ([]*Inode, error) {
	var inodes []*Inode
	for rows.Next() {
		inode, err := scanInodeRow(rows)
		if err != nil {
			return nil, err
		}
		inodes = append(inodes, inode)
	}
	return inodes, rows.Err()
}

func scanInodeRow(row rowScanner) (*Inode, error) {
	var inode Inode
	var isDir, cached, dirty, pinned int
	var syncStatus string
	err := row.Scan(
		&inode.ID, &inode.RemotePath, &inode.DisplayName, &isDir,
		&inode.Size, &inode.Mtime, &cached, &dirty, &pinned,
		&inode.LastAccess, &inode.ContentHash, &inode.LocalHash, &inode.LocalMtime, &inode.SealedKey,
		&inode.EncMeta, &inode.Etag, &inode.ParentID,
		&syncStatus, &inode.StatusReason)
	if err != nil {
		return nil, err
	}
	inode.IsDir = isDir != 0
	inode.Cached = cached != 0
	inode.Dirty = dirty != 0
	inode.Pinned = pinned != 0
	inode.SyncStatus = SyncStatus(syncStatus)
	return &inode, nil
}
