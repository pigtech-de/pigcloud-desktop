package cache

func (d *DB) LocalContentState(id int64) (current, baseline, remoteEtag string, err error) {
	err = d.db.QueryRow("SELECT local_hash, COALESCE(NULLIF(local_hash, ''), download_baseline_hash), local_remote_etag FROM inodes WHERE id = ?", id).Scan(&current, &baseline, &remoteEtag)
	return
}

func (d *DB) MarkLocalConflict(id int64, reason string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET dirty = 1, cached = 0, sync_status = 'conflict', status_reason = ? WHERE id = ?", reason, id)
	return err
}

func (d *DB) SetLocalFileID(id int64, fileID string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET local_file_id = ? WHERE id = ?", fileID, id)
	return err
}

const treeScope = `(remote_path = ? OR substr(remote_path, 1, length(?) + 1) = ? || '/')`

func (d *DB) TreeSettled(remotePath string) bool {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM inodes WHERE `+treeScope+` AND (dirty = 1 OR sync_status != 'synced'
		OR id IN (SELECT inode_id FROM writeback_queue WHERE status IN ('pending', 'in_progress')))`,
		remotePath, remotePath, remotePath).Scan(&n)
	return err == nil && n == 0
}

func (d *DB) MoveInodeTree(oldPath, newPath, newName string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE inodes SET remote_path = ? || substr(remote_path, length(?) + 1) WHERE `+treeScope,
		newPath, oldPath, oldPath, oldPath, oldPath); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE inodes SET display_name = ?,
		parent_id = COALESCE((SELECT id FROM inodes WHERE remote_path = ?), 0) WHERE remote_path = ?`,
		newName, RemoteParentPath(newPath), newPath); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *DB) InodesUnder(remotePath string) ([]*Inode, error) {
	rows, err := d.db.Query(`SELECT `+inodeColumns+` FROM inodes WHERE `+treeScope+` ORDER BY remote_path ASC`,
		remotePath, remotePath, remotePath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectInodes(rows)
}

func (d *DB) ChildNames(remotePath string) ([]string, error) {
	rows, err := d.db.Query(`SELECT display_name FROM inodes
		WHERE substr(remote_path, 1, length(?) + 1) = ? || '/' AND instr(substr(remote_path, length(?) + 2), '/') = 0`,
		remotePath, remotePath, remotePath)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (d *DB) RenamePendingFor(nodeID string) bool {
	if nodeID == "" {
		return false
	}
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM writeback_queue q JOIN inodes i ON i.id = q.inode_id
		WHERE q.action = 'rename' AND q.status IN ('pending', 'in_progress') AND i.node_id = ?`, nodeID).Scan(&n)
	return err == nil && n > 0
}

func (d *DB) CancelPendingWriteback(inodeID int64, action string) bool {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	res, err := d.db.Exec("DELETE FROM writeback_queue WHERE inode_id = ? AND action = ? AND status = 'pending'", inodeID, action)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (d *DB) FailedRenames() ([]*WritebackEntry, error) {
	rows, err := d.db.Query(`SELECT id, inode_id, action, remote_path, extra_json, enqueued_at, attempts, last_error, status
		FROM writeback_queue WHERE action = 'rename' AND status = 'failed'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []*WritebackEntry
	for rows.Next() {
		var e WritebackEntry
		if err := rows.Scan(&e.ID, &e.InodeID, &e.Action, &e.RemotePath, &e.ExtraJSON, &e.EnqueuedAt, &e.Attempts, &e.LastError, &e.Status); err != nil {
			return nil, err
		}
		entries = append(entries, &e)
	}
	return entries, rows.Err()
}

func (d *DB) CountLocalFiles() (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM inodes WHERE is_dir = 0 AND (local_hash != '' OR download_baseline_hash != '')`).Scan(&n)
	return n, err
}

func (d *DB) GetMeta(key string) string {
	var value string
	if err := d.db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&value); err != nil {
		return ""
	}
	return value
}

func (d *DB) SetMeta(key, value string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

func (d *DB) SetMassDeleteHeld(source string, ids []int64) {
	d.heldMu.Lock()
	defer d.heldMu.Unlock()
	if d.massHeld == nil {
		d.massHeld = map[string][]int64{}
	}
	d.massHeld[source] = ids
}

func (d *DB) MassDeleteHeld() int {
	return len(d.heldUnion(false))
}

func (d *DB) TakeMassDeleteHeld() []int64 {
	return d.heldUnion(true)
}

func (d *DB) heldUnion(clear bool) []int64 {
	d.heldMu.Lock()
	defer d.heldMu.Unlock()
	seen := map[int64]bool{}
	var ids []int64
	for _, list := range d.massHeld {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if clear {
		d.massHeld = nil
	}
	return ids
}

func (d *DB) SetRemoteVersion(id int64, etag string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET etag = ? WHERE id = ?", etag, id)
	return err
}

func (d *DB) SetLocalContentForVersion(id int64, hash string, localMtime int64, remoteEtag string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET local_hash = ?, download_baseline_hash = ?, local_mtime = ?, local_remote_etag = ? WHERE id = ?", hash, hash, localMtime, remoteEtag, id)
	return err
}
