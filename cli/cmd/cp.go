package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
	"pigcloud/internal/tree"

	"github.com/spf13/cobra"
)

var cpDry bool

var cpCmd = &cobra.Command{
	Use:               "cp <source> <target>",
	GroupID:           GroupFiles,
	Aliases:           []string{"copy"},
	Short:             "Copy a file or directory",
	Args:              cobra.ExactArgs(2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runCopy(args[0], args[1])
	},
}

func init() {
	cpCmd.Flags().BoolVarP(&cpDry, "dry-run", "d", false, "Preview what would be copied without making changes")
	rootCmd.AddCommand(cpCmd)
}

func runCopy(source, target string) {
	relocate("cp", source, target, cpDry, addCopyMap, func(ctx context.Context, landed string, payload api.CopyPayload) {
		if payload.Dry {
			output.PrintInfo("[dry-run] Would copy " + output.PrintPath(payload.Path) + " to " + output.PrintPath(payload.Target))
			return
		}
		propagateSubtreeNames(ctx, landed, ExitWithError)
		if !GetQuietOutput() {
			output.PrintSuccess("Copied " + output.PrintPath(payload.Path) + " to " + output.PrintPath(payload.Target))
		}
	})
}

const copyMapMaxNodes = 5000

type copyMapEntry struct {
	NodeID       string `json:"node_id"`
	SealedParent string `json:"sealed_parent"`
}

type subtreeNameEntry struct {
	DisplayName string `json:"e2ee_display_name"`
	PathToken   string `json:"e2ee_path_token"`
}

func addCopyMap(ctx context.Context, options map[string]string, resolvedSource, destDir, landed string, parentKey []byte) func(map[string]string) error {
	if parentKey == nil {
		return nil
	}
	source, err := cmdutil.StatRemote(ctx, resolvedSource)
	if errors.Is(err, cmdutil.ErrRemoteMissing) {
		err = fmt.Errorf("not found: %s", resolvedSource)
	}
	if err != nil {
		refuseWrite(err)
		return nil
	}
	destID, err := cmdutil.ResolveDirID(ctx, destDir)
	if err != nil {
		refuseWrite(err)
		return nil
	}
	var built *tree.Tree
	if source.IsDir {
		if built = loadClientTree(ctx); built == nil {
			refuseWrite(errors.New("could not build the folder tree to name the copied items"))
			return nil
		}
	}
	build := func(opts map[string]string) error {
		copyMap, names, err := buildCopyMap(built, source.ID, destID, landed, parentKey, sealSubtreeName)
		if err != nil {
			return err
		}
		if built != nil {
			encoded, err := json.Marshal(names)
			if err != nil {
				return err
			}
			opts["e2ee_subtree_names"] = string(encoded)
		}
		encoded, err := json.Marshal(copyMap)
		if err != nil {
			return err
		}
		opts["e2ee_copy_map"] = string(encoded)
		return nil
	}
	if err := build(options); err != nil {
		refuseWrite(err)
		return nil
	}
	return build
}

func buildCopyMap(built *tree.Tree, sourceID, destID, landed string, parentKey []byte,
	sealName func(name, fullPath string) (subtreeNameEntry, error)) (map[string]copyMapEntry, map[string]subtreeNameEntry, error) {
	root, err := e2ee.MintSealedNode(destID, parentKey)
	if err != nil {
		return nil, nil, err
	}
	copyMap := map[string]copyMapEntry{sourceID: {NodeID: root.ID, SealedParent: root.SealedParent}}
	if built == nil {
		return copyMap, nil, nil
	}
	names, err := copySubtree(built, sourceID, root.ID, landed, parentKey, copyMap, sealName)
	return copyMap, names, err
}

func sealSubtreeName(name, fullPath string) (subtreeNameEntry, error) {
	fields := map[string]string{}
	if err := e2ee.AddE2eeNameFields(fields, name, fullPath); err != nil {
		return subtreeNameEntry{}, err
	}
	return subtreeNameEntry{DisplayName: fields["e2ee_display_name"], PathToken: fields["e2ee_path_token"]}, nil
}

func copySubtree(built *tree.Tree, sourceID, rootCopyID, landed string, parentKey []byte, copyMap map[string]copyMapEntry,
	sealName func(name, fullPath string) (subtreeNameEntry, error)) (map[string]subtreeNameEntry, error) {
	ids := built.Subtree(sourceID, true)
	if len(ids)+1 > copyMapMaxNodes {
		return nil, fmt.Errorf("the copy holds %d items, more than the %d one request can carry", len(ids)+1, copyMapMaxNodes)
	}
	copyOf := map[string]string{sourceID: rootCopyID}
	landedOf := map[string]string{sourceID: trimLeadingSlash(landed)}
	names := map[string]subtreeNameEntry{}
	for _, id := range ids {
		node, _ := built.Get(id)
		parentCopy, ok := copyOf[node.ParentID]
		if !ok {
			return nil, fmt.Errorf("copied item %s has no copied parent", id)
		}
		ref, err := e2ee.MintSealedNode(parentCopy, parentKey)
		if err != nil {
			return nil, err
		}
		copyMap[id] = copyMapEntry{NodeID: ref.ID, SealedParent: ref.SealedParent}
		copyOf[id] = ref.ID

		parentLanded, named := landedOf[node.ParentID]
		if !named || e2ee.IsNameUnavailable(node.Name) {
			continue
		}
		fullPath := parentLanded + "/" + node.Name
		entry, err := sealName(node.Name, fullPath)
		if err != nil {
			return nil, err
		}
		names[id] = entry
		landedOf[id] = fullPath
	}
	return names, nil
}

func trimLeadingSlash(p string) string {
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	return p
}
