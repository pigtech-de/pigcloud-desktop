package tree

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
)

type Executor interface {
	Execute(ctx context.Context, command string, options map[string]string) (*api.Response, error)
}

type shellPage struct {
	Shells     []Shell `json:"shells"`
	NextCursor *string `json:"next_cursor"`
	Done       bool    `json:"done"`
}

type Keys struct {
	Priv      *crypto.PrivateKeySet
	ParentKey []byte
}

func Fetch(ctx context.Context, client Executor, keys Keys) (*Tree, error) {
	if keys.Priv == nil {
		return nil, fmt.Errorf("tree: private key set required")
	}
	var nodes []*Node
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 10000 {
			return nil, fmt.Errorf("tree: shell walk did not terminate")
		}
		options := map[string]string{}
		if cursor != "" {
			options["cursor"] = cursor
		}
		resp, err := client.Execute(ctx, "e2ee_list_shells", options)
		if err != nil {
			return nil, fmt.Errorf("tree: list shells: %w", err)
		}
		if resp == nil || !resp.Success {
			return nil, fmt.Errorf("tree: list shells refused")
		}
		var page shellPage
		if err := json.Unmarshal(resp.Raw, &page); err != nil {
			return nil, fmt.Errorf("tree: parse shells: %w", err)
		}
		for i := range page.Shells {
			node, err := decodeShell(&page.Shells[i], keys)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, node)
		}
		if page.Done || page.NextCursor == nil || *page.NextCursor == "" {
			break
		}
		cursor = *page.NextCursor
	}
	return New(nodes), nil
}

func decodeShell(shell *Shell, keys Keys) (*Node, error) {
	nodeIDBytes, err := IDBytes(shell.NodeID)
	if err != nil {
		return nil, fmt.Errorf("tree: node id %q: %w", shell.NodeID, err)
	}

	name := "(encrypted)"
	if sealedName, err := base64.StdEncoding.DecodeString(shell.DisplayName); err == nil {
		if decrypted, err := crypto.UnsealDisplayName(sealedName, keys.Priv); err == nil {
			name = decrypted
		}
	}

	parent := shell.PlaintextParent
	if shell.SealedParent != "" {
		if blob, err := base64.StdEncoding.DecodeString(shell.SealedParent); err == nil {
			if parentBytes, err := crypto.OpenParentRef(blob, nodeIDBytes, keys.ParentKey, keys.Priv); err == nil {
				parent = ""
				if parentBytes != nil {
					parent = fmt.Sprintf("%x", parentBytes)
				}
			}
		}
	}

	return &Node{
		ID:         shell.NodeID,
		Name:       name,
		ParentID:   parent,
		IsDir:      shell.ItemType == "directory" || shell.ItemType == "folder",
		Size:       shell.FileSize,
		CreatedAt:  shell.CreatedAt,
		ModifiedAt: shell.ModifiedAt,
		Hidden:     shell.IsHidden,
		Trashed:    shell.IsTrashed,
	}, nil
}
