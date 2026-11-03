package vfs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount/cache"
)

var ErrParentPending = errors.New("parent folder is still queued for creation")

func (v *VFS) SealParentRef(nodeIDHex, parentIDHex string) (string, error) {
	return e2ee.SealParentRefB64(nodeIDHex, parentIDHex, v.ParentKey)
}

func (v *VFS) ResolveNodeID(ctx context.Context, remotePath string) (string, error) {
	if remotePath == "" {
		return "", nil
	}
	inode, _ := v.Cache.GetInodeByPath(remotePath)
	if inode != nil && inode.NodeID != "" {
		return inode.NodeID, nil
	}
	if inode != nil && inode.PendingNodeID != "" {
		active, err := v.Cache.HasActiveWriteback(inode.ID, "mkdir")
		if err != nil || active {
			return "", ErrParentPending
		}
		id, err := v.LookupNodeID(ctx, remotePath)
		if err != nil {
			return "", cache.Permanent(fmt.Errorf("folder %s was never created: %w", remotePath, err))
		}
		return id, nil
	}
	return v.LookupNodeID(ctx, remotePath)
}

func (v *VFS) LookupNodeID(ctx context.Context, remotePath string) (string, error) {
	if remotePath == "" {
		return "", nil
	}
	inode, _ := v.Cache.GetInodeByPath(remotePath)
	options := map[string]string{"source": "/" + remotePath}
	v.addPathTokens(options, []string{remotePath})
	resp, err := v.Client.Execute(ctx, "in", options)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", remotePath, err)
	}
	if resp == nil || !resp.Success {
		msg := "the server did not answer"
		if resp != nil && resp.Message != "" {
			msg = resp.Message
		}
		return "", fmt.Errorf("resolve %s: %s", remotePath, msg)
	}
	var payload api.InfoPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return "", fmt.Errorf("resolve %s: %w", remotePath, err)
	}
	if !e2ee.IsNodeIDHex(payload.Details.NodeID) {
		return "", errors.New("resolve " + remotePath + ": the server named no node id")
	}
	id := strings.ToLower(payload.Details.NodeID)
	if inode != nil {
		v.Cache.SetInodeNodeID(inode.ID, id)
	}
	return id, nil
}

func (v *VFS) ForgetVanished(n *Node) {
	n.Mu.Lock()
	n.NodeID = ""
	id := n.ID
	n.Mu.Unlock()
	if id != 0 {
		v.Cache.ClearNodeIDs(id, true)
	}
}

func (v *VFS) nodeIDOf(ctx context.Context, n *Node) (string, error) {
	n.Mu.RLock()
	id, remotePath := n.NodeID, n.RemotePath
	n.Mu.RUnlock()
	if id != "" {
		return id, nil
	}
	id, err := v.ResolveNodeID(ctx, remotePath)
	if err != nil || id == "" {
		return id, err
	}
	n.Mu.Lock()
	n.NodeID = id
	n.Mu.Unlock()
	return id, nil
}
