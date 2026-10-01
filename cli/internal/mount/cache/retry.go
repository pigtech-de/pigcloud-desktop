package cache

import (
	"database/sql"
	"errors"
)

func ClearFailedTransfers(db *DB, remotePath string) ([]*Inode, error) {
	if remotePath == "" {
		candidates, err := db.InodesWithFailures()
		if err != nil {
			return nil, err
		}
		return clearEach(db, candidates), nil
	}

	in, err := db.GetInodeByPath(remotePath)
	if errors.Is(err, sql.ErrNoRows) || in == nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !db.hasFailureLatch(in) {
		return nil, nil
	}
	return clearEach(db, []*Inode{in}), nil
}

func clearEach(db *DB, candidates []*Inode) []*Inode {
	cleared := make([]*Inode, 0, len(candidates))
	for _, in := range candidates {
		if in.SyncStatus == StatusConflict || in.SyncStatus == StatusRejected {
			continue
		}
		db.DeleteSyncFailures(in.ID)
		db.DeleteFailedUploadWritebacks(in.ID)
		cleared = append(cleared, in)
	}
	return cleared
}
