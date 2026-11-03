package cache

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
)

type ParentSealer func(nodeIDHex, parentIDHex string) (string, error)

func (d *DB) SetParentSealer(fn ParentSealer) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	d.parentSealer = fn
}

type WritebackExtra struct {
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	Target         string `json:"target,omitempty"`
	NodeID         string `json:"node_id,omitempty"`
	ParentID       string `json:"parent_id,omitempty"`
	SealedParent   string `json:"sealed_parent,omitempty"`
}

func (d *DB) SetWritebackExtra(id int64, extraJSON string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE writeback_queue SET extra_json = ? WHERE id = ?", extraJSON, id)
	return err
}

func ParseWritebackExtra(extraJSON string) WritebackExtra {
	var x WritebackExtra
	if extraJSON != "" {
		_ = json.Unmarshal([]byte(extraJSON), &x)
	}
	return x
}

func (x WritebackExtra) Marshal() string {
	if x == (WritebackExtra{}) {
		return ""
	}
	b, err := json.Marshal(x)
	if err != nil {
		return ""
	}
	return string(b)
}

func MintNodeID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func RemoteParentPath(remotePath string) string {
	parent := path.Dir(remotePath)
	if parent == "." || parent == "/" {
		return ""
	}
	return parent
}

func (d *DB) SetInodeNodeID(id int64, nodeID string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET node_id = NULLIF(?, ''), pending_node_id = NULL WHERE id = ?", nodeID, id)
	return err
}

func (d *DB) SetPendingNodeID(id int64, nodeID string) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	_, err := d.db.Exec("UPDATE inodes SET pending_node_id = NULLIF(?, '') WHERE id = ?", nodeID, id)
	return err
}

func (d *DB) ClearNodeIDs(id int64, onlyIfConfirmed bool) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return d.clearNodeIDsLocked(id, onlyIfConfirmed)
}

func (d *DB) clearNodeIDsLocked(id int64, onlyIfConfirmed bool) error {
	query := "UPDATE inodes SET node_id = NULL, pending_node_id = NULL WHERE id = ?"
	if onlyIfConfirmed {
		query += " AND node_id IS NOT NULL"
	}
	_, err := d.db.Exec(query, id)
	return err
}

func (d *DB) withNodeIdentityLocked(inodeID int64, remotePath, extraJSON string) (string, error) {
	var confirmed, pending sql.NullString
	err := d.db.QueryRow("SELECT node_id, pending_node_id FROM inodes WHERE id = ?", inodeID).Scan(&confirmed, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return extraJSON, nil
	}
	if err != nil {
		return "", err
	}
	x := ParseWritebackExtra(extraJSON)
	x.NodeID = confirmed.String
	if x.NodeID == "" {
		x.NodeID = pending.String
	}
	if x.NodeID == "" {
		if x.NodeID, err = MintNodeID(); err != nil {
			return "", err
		}
		if _, err := d.db.Exec("UPDATE inodes SET pending_node_id = ? WHERE id = ?", x.NodeID, inodeID); err != nil {
			return "", err
		}
	}
	x.ParentID, x.SealedParent = "", ""
	parentPath := RemoteParentPath(remotePath)
	known := parentPath == ""
	if !known {
		var parentID sql.NullString
		err := d.db.QueryRow("SELECT node_id FROM inodes WHERE remote_path = ?", parentPath).Scan(&parentID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		x.ParentID = parentID.String
		known = x.ParentID != ""
	}
	if known && d.parentSealer != nil {
		if sealed, err := d.parentSealer(x.NodeID, x.ParentID); err == nil {
			x.SealedParent = sealed
		}
	}
	return x.Marshal(), nil
}
