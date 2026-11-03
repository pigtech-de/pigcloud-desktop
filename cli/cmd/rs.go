package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
	"pigcloud/internal/tree"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var nodeIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

var rsToRoot bool

type rootRestoreDecision int

const (
	restoreAbort rootRestoreDecision = iota
	restoreAsk
	restoreProceed
)

const rootParentID = "00000000000000000000000000000000"

var errRestoreParentUnknown = errors.New("the folder this item came from is unknown; pass --to-root to restore it at the account root")

type restoreTarget struct {
	parentID string
	toRoot   bool
}

func restoreTargetFor(built *tree.Tree, nodeID string) (restoreTarget, error) {
	id := strings.ToLower(nodeID)
	node, ok := built.Get(id)
	if !ok {
		return restoreTarget{}, fmt.Errorf("item %s is not in this device's folder tree", nodeID)
	}
	if slices.Contains(built.Orphans, id) {
		return restoreTarget{}, errRestoreParentUnknown
	}
	if node.ParentID == "" {
		return restoreTarget{parentID: rootParentID}, nil
	}
	return restoreTarget{parentID: node.ParentID}, nil
}

func restoreOptions(nodeID string, target restoreTarget, parentKey []byte) (map[string]string, error) {
	options := map[string]string{"node_id": nodeID}
	if target.toRoot {
		options["to_root"] = "1"
	}
	if parentKey == nil {
		return options, nil
	}
	sealTo := ""
	if !target.toRoot {
		if target.parentID == "" {
			return nil, errors.New("restore names no parent folder")
		}
		options["restore_parent_id"] = target.parentID
		if target.parentID != rootParentID {
			sealTo = target.parentID
		}
	}
	sealed, err := e2ee.SealParentRefB64(nodeID, sealTo, parentKey)
	if err != nil {
		return nil, err
	}
	options["e2ee_sealed_parent"] = sealed
	return options, nil
}

func restoreRequest(ctx context.Context, nodeID string, toRoot bool, parentKey []byte) map[string]string {
	target := restoreTarget{toRoot: toRoot}
	if parentKey != nil && !toRoot {
		built := loadClientTree(ctx)
		if built == nil {
			refuseWrite(errors.New("could not build the folder tree to find where the item came from"))
			return nil
		}
		var err error
		target, err = restoreTargetFor(built, nodeID)
		if errors.Is(err, errRestoreParentUnknown) && restoreInteractive() {
			if !cmdutil.ConfirmAction("The folder this item came from is unknown. Restore it to the account root instead?", false) {
				output.PrintInfo("Cancelled")
				ExitWithError()
				return nil
			}
			target, err = restoreTarget{toRoot: true}, nil
		}
		if err != nil {
			refuseWrite(err)
			return nil
		}
	}
	options, err := restoreOptions(nodeID, target, parentKey)
	if err != nil {
		refuseWrite(err)
		return nil
	}
	return options
}

func restoreInteractive() bool {
	return term.IsTerminal(int(syscall.Stdin)) && !GetJSONOutput() && !GetQuietOutput()
}

func decideRootRestore(errorCode string, toRoot, interactive bool) rootRestoreDecision {
	if toRoot {
		return restoreProceed
	}
	if errorCode != "orphaned" || !interactive {
		return restoreAbort
	}
	return restoreAsk
}

var restoreCmd = &cobra.Command{
	Use:     "rs <path-or-node-id>",
	GroupID: GroupFiles,
	Aliases: []string{"restore"},
	Short:   "Restore an item from the recycling bin",
	Long: `Restore a file or directory from the recycling bin to its original location.

Accepts either a path ('/photo.jpg') or a 32-char hex node ID from 'pc tb ls'.
Paths are resolved against the recycling bin; if multiple deleted items share
the same name, you'll be asked which to restore.`,
	Example: `pc rs /report.pdf                 # Restore by path (prompts on collision)
pc rs abc123def456...           # Restore by node ID from 'pc tb' output`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runRestore(args[0])
	},
}

func init() {
	restoreCmd.Flags().BoolVar(&rsToRoot, "to-root", false, "Restore to the account root when the original folder is gone")
	rootCmd.AddCommand(restoreCmd)
}

func runRestore(arg string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	nodeID := arg
	if !nodeIDPattern.MatchString(arg) {
		nodeID = resolveTrashPath(ctx, arg)
		if nodeID == "" {
			ExitWithError()
			return
		}
	}

	parentKey := writerParentKey()
	options := restoreRequest(ctx, nodeID, rsToRoot, parentKey)

	client := api.NewClient()
	resp, err := client.Execute(ctx, "rs", options)
	if err != nil {
		output.PrintError("Request failed: " + err.Error())
		ExitWithError()
		return
	}

	if !resp.Success {
		interactive := restoreInteractive()
		switch decideRootRestore(resp.ErrorCode, rsToRoot, interactive) {
		case restoreAsk:
			output.PrintWarning(resp.Message)
			if !cmdutil.ConfirmAction("Restore it to the account root instead?", false) {
				output.PrintInfo("Cancelled")
				return
			}
			options = restoreRequest(ctx, nodeID, true, parentKey)
			resp, err = client.Execute(ctx, "rs", options)
			if err != nil {
				output.PrintError("Request failed: " + err.Error())
				ExitWithError()
				return
			}
		case restoreAbort:
			output.PrintError(resp.Message)
			ExitWithError()
			return
		}
	}

	if !resp.Success {
		output.PrintError(resp.Message)
		ExitWithError()
		return
	}

	var payload api.RestorePayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		output.PrintError("Failed to parse response: " + err.Error())
		ExitWithError()
		return
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	output.PrintSuccess("Item restored successfully")
}

func resolveTrashPath(ctx context.Context, input string) string {
	_, payload := cmdutil.ExecuteCommand[api.TrashListPayload](ctx, "tb", map[string]string{}, ExitWithError)
	if len(payload.Items) == 0 {
		output.PrintError("Recycling bin is empty")
		return ""
	}

	target := strings.TrimPrefix(input, "/")
	target = path.Base(target)
	if target == "" || target == "." || target == "/" {
		output.PrintError("Path cannot be empty")
		return ""
	}

	type candidate struct {
		name      string
		nodeID    string
		itemType  string
		deletedAt string
	}
	var matches []candidate
	for i := range payload.Items {
		item := &payload.Items[i]
		name := e2ee.ResolveName(item.E2EEDisplayName, item.Name)
		if name == target {
			matches = append(matches, candidate{
				name: name, nodeID: item.NodeID,
				itemType: item.Type, deletedAt: output.FormatTime(&item.DeletedAt),
			})
		}
	}

	if len(matches) == 0 {
		output.PrintError("No item named " + target + " in recycling bin")
		return ""
	}
	if len(matches) == 1 {
		return matches[0].nodeID
	}

	fmt.Println("Multiple trashed items match " + target + ":")
	for i, m := range matches {
		fmt.Printf("  %d) [%s] %s — deleted %s (id %s)\n",
			i+1, m.itemType, m.name, m.deletedAt, m.nodeID[:8]+"…")
	}
	fmt.Print("Pick one (number, or empty to cancel): ")
	var choice string
	fmt.Scanln(&choice)
	choice = strings.TrimSpace(choice)
	if choice == "" {
		output.PrintInfo("Cancelled")
		return ""
	}
	idx := 0
	if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil || idx < 1 || idx > len(matches) {
		output.PrintError("Invalid selection")
		return ""
	}
	return matches[idx-1].nodeID
}
