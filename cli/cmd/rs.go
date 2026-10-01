package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"syscall"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

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

func restoreOptions(nodeID string, toRoot bool, parentKey []byte) map[string]string {
	options := map[string]string{"node_id": nodeID}
	if !toRoot {
		return options
	}
	options["to_root"] = "1"
	if sealed := e2ee.SealedRootParentB64(nodeID, parentKey); sealed != "" {
		options["e2ee_sealed_parent"] = sealed
	}
	return options
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

	var rootParentKey []byte
	if rsToRoot {
		rootParentKey = e2ee.GetParentKey(ExitWithError)
	}
	options := restoreOptions(nodeID, rsToRoot, rootParentKey)

	client := api.NewClient()
	resp, err := client.Execute(ctx, "rs", options)
	if err != nil {
		output.PrintError("Request failed: " + err.Error())
		ExitWithError()
		return
	}

	if !resp.Success {
		interactive := term.IsTerminal(int(syscall.Stdin)) && !GetJSONOutput() && !GetQuietOutput()
		switch decideRootRestore(resp.ErrorCode, rsToRoot, interactive) {
		case restoreAsk:
			output.PrintWarning(resp.Message)
			if !cmdutil.ConfirmAction("Restore it to the account root instead?", false) {
				output.PrintInfo("Cancelled")
				return
			}
			options = restoreOptions(nodeID, true, e2ee.GetParentKey(ExitWithError))
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
		name := item.Name
		if item.E2EEDisplayName != "" {
			name = e2ee.DecryptE2EEName(item.E2EEDisplayName)
		}
		if name == target {
			matches = append(matches, candidate{
				name: name, nodeID: item.NodeID,
				itemType: item.Type, deletedAt: item.DeletedAt,
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
