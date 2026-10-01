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
