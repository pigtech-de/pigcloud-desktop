package cmd

import (
	"context"
	"encoding/json"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/tree"
)

func loadClientTree(ctx context.Context) *tree.Tree {
	if !e2ee.HasE2EEKeys() {
		return nil
	}
	_, priv := e2ee.GetKeyPair(ExitWithError)
	if priv == nil {
		return nil
	}
	built, err := tree.Load(ctx, api.NewClient(), tree.Keys{
		Priv:      priv,
		ParentKey: e2ee.GetParentKey(ExitWithError),
	})
	if err != nil {
		return nil
	}
	return built
}

func folderIDFor(built *tree.Tree, resolvedPath string) (string, bool) {
	trimmed := strings.Trim(resolvedPath, "/")
	if trimmed == "" {
		return "", true
	}
	node, err := built.Resolve(trimmed)
	if err != nil || node == nil || !node.IsDir {
		return "", false
	}
	return node.ID, true
}

func setScope(options map[string]string, ids []string) {
	encoded, err := json.Marshal(ids)
	if err != nil {
		return
	}
	options["scope_node_ids"] = string(encoded)
}

func addChildScope(ctx context.Context, options map[string]string, resolvedPath string) {
	built := loadClientTree(ctx)
	if built == nil {
		return
	}
	folderID, ok := folderIDFor(built, resolvedPath)
	if !ok {
		return
	}
	ids := []string{}
	for _, child := range built.Children(folderID) {
		ids = append(ids, child.ID)
	}
	setScope(options, ids)
}

func addRecursiveListingScope(ctx context.Context, options map[string]string, resolvedPath string, includeHidden bool) {
	built := loadClientTree(ctx)
	if built == nil {
		return
	}
	folderID, ok := folderIDFor(built, resolvedPath)
	if !ok {
		return
	}
	setScope(options, built.Subtree(folderID, includeHidden))
}

func addSubtreeScope(ctx context.Context, options map[string]string, resolvedPath string) {
	built := loadClientTree(ctx)
	if built == nil {
		return
	}
	folderID, ok := folderIDFor(built, resolvedPath)
	if !ok {
		return
	}
	setScope(options, built.Descendants(folderID))
}
