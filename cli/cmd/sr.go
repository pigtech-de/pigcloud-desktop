package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var sharePermission string

var srCmd = &cobra.Command{
	Use:     "sr [path]",
	GroupID: GroupSharing,
	Aliases: []string{"share"},
	Short:   "Manage shared files and folders",
	Long: `Manage shared files and folders.

Without arguments, shows shares you've received (inbox).
With a path, shows share recipients for that folder.`,
	Example: `pc sr                            # Show shares you've received
pc sr /Shared                    # List recipients for /Shared
pc sr add alice /Shared          # Share with alice
pc sr rm /Shared alice           # Revoke alice's access
pc sr set /Shared -P secret      # Add password`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			runShareInbox()
		} else {
			runShareList(args[0])
		}
	},
}

var srAddCmd = &cobra.Command{
	Use:               "add <username> <path>",
	Short:             "Share a folder with a user",
	Example:           "pc sr add alice /Documents    # Share with alice",
	Args:              cobra.ExactArgs(2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runShareAdd(args[1], args[0])
	},
}

var srLsCmd = &cobra.Command{
	Use:   "ls <path>",
	Short: "List share recipients for a folder",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runShareList(args[0])
	},
}

var srRmForce bool

var srRmCmd = &cobra.Command{
	Use:   "rm <path> <username>",
	Short: "Remove a specific share recipient",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		runShareRemove(args[0], args[1])
	},
}

var srInboxCmd = &cobra.Command{
	Use:     "inbox",
	Short:   "List shares you've received from others",
	Example: "pc sr inbox                      # Show folders shared with you",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runShareInbox()
	},
}

var (
	srSetPermission string
	srSetPassword   string
	srSetExpires    string
	srSetUsername   string
	srRmPassword    bool
	srRmExpires     bool
)

var srSetCmd = &cobra.Command{
	Use:   "set <path>",
	Short: "Update share settings (permission, password, expiry)",
	Long: `Update settings on an existing share.

Update a recipient's permission level:
  sr set /Docs -u bob -p edit

Set or change share password/expiration:
  sr set /Docs --password secret123
  sr set /Docs --expires "2026-12-31"

Remove password/expiration:
  sr set /Docs --remove-password
  sr set /Docs --remove-expiration`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runShareUpdate(args[0])
	},
}

var srDeclineCmd = &cobra.Command{
	Use:   "decline <path> <owner>",
	Short: "Remove a share you received",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		runShareDecline(args[0], args[1])
	},
}

func init() {
	srAddCmd.Flags().StringVarP(&sharePermission, "permissions", "p", "read", "Permission level: read or edit")
	srAddCmd.RegisterFlagCompletionFunc("permissions", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"read\tRead-only access", "edit\tRead and edit access"}, cobra.ShellCompDirectiveNoFileComp
	})
	srSetCmd.Flags().StringVarP(&srSetUsername, "username", "u", "", "recipient username (for permission changes)")
	srSetCmd.Flags().StringVarP(&srSetPermission, "permissions", "p", "", "new permission level: read or edit")
	srSetCmd.Flags().StringVarP(&srSetPassword, "password", "P", "", "set or change share password")
	srSetCmd.Flags().StringVarP(&srSetExpires, "expires", "e", "", "set or change expiration date")
	srSetCmd.Flags().BoolVar(&srRmPassword, "remove-password", false, "remove password protection")
	srSetCmd.Flags().BoolVar(&srRmExpires, "remove-expiration", false, "remove expiration date")
	srSetCmd.RegisterFlagCompletionFunc("permissions", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"read\tRead-only access", "edit\tRead and edit access"}, cobra.ShellCompDirectiveNoFileComp
	})
	srRmCmd.Flags().BoolVarP(&srRmForce, "force", "f", false, "skip confirmation prompt")
	srCmd.AddCommand(srAddCmd, srLsCmd, srRmCmd, srInboxCmd, srDeclineCmd, srSetCmd)
	rootCmd.AddCommand(srCmd)
}

func runShareAdd(targetPath, username string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	options := map[string]string{
		"source":      resolvedPath,
		"username":    username,
		"permissions": sharePermission,
	}

	var keys []api.SealedKeyEntry
	var names []api.SealedNameEntry
	if e2ee.HasE2EEKeys() {
		keys, names = resealKeysAndNamesForRecipient(ctx, resolvedPath, username)
		setFirstShareBatch(options, "sealed_keys", keys)
		setFirstShareBatch(options, "sealed_names", names)
	}

	cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfOnly, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.SharePayload](ctx, "sr", options, ExitWithError)

	if payload.Status == "revoked" {
		output.PrintSuccess("Revoked sharing of " + output.PrintPath(payload.Path) + " from " + payload.Username)
		return
	}
	storeShareOverflow(ctx, username, payload.NodeID, keys, names)
	output.PrintSuccess("Shared " + output.PrintPath(payload.Path) + " with " + payload.Username + " (" + payload.Permission + ")")
}

func setFirstShareBatch[T any](options map[string]string, option string, rows []T) {
	if len(rows) == 0 {
		return
	}
	if data, err := json.Marshal(rows[:min(len(rows), api.ShareRowBatchMax)]); err == nil {
		options[option] = string(data)
	}
}

func storeShareOverflow(ctx context.Context, username, anchorHex string, keys []api.SealedKeyEntry, names []api.SealedNameEntry) {
	client := api.NewClient()
	err := client.StoreShareContentKeys(ctx, username, keys[min(len(keys), api.ShareRowBatchMax):])
	if err == nil {
		err = client.StoreShareDisplayNames(ctx, username, anchorHex, names[min(len(names), api.ShareRowBatchMax):])
	}
	if err != nil {
		output.PrintError("Shared, but some encryption keys did not reach " + username + ": " + err.Error())
		ExitWithError()
	}
}

func resealKeysAndNamesForRecipient(ctx context.Context, folderPath, recipientUsername string) ([]api.SealedKeyEntry, []api.SealedNameEntry) {
	client := api.NewClient()

	pubkeyResp, err := client.FetchPublicKey(ctx, recipientUsername)
	if err != nil || !pubkeyResp.Success {
		return nil, nil
	}
	var pubkeyPayload api.E2EEPubkeyPayload
	if err := json.Unmarshal(pubkeyResp.Raw, &pubkeyPayload); err != nil {
		return nil, nil
	}
	recipientPubKey, err := e2ee.PinPeerSealKeyFromPubkey(recipientUsername, &pubkeyPayload)
	if err != nil {
		output.PrintError(err.Error())
		ExitWithError()
		return nil, nil
	}

	keysResp, err := client.Execute(ctx, "e2ee_list_keys", map[string]string{
		"source":        folderPath,
		"include_names": "1",
		"include_dirs":  "1",
	})
	if err != nil || !keysResp.Success {
		return nil, nil
	}
	var keysPayload api.E2EEListKeysPayload
	if err := json.Unmarshal(keysResp.Raw, &keysPayload); err != nil {
		return nil, nil
	}
	if len(keysPayload.Keys) == 0 {
		return nil, nil
	}

	_, privKey := cmdutil.GetKeyPair(ExitWithError)

	var keyEntries []api.SealedKeyEntry
	var nameEntries []api.SealedNameEntry

	for _, k := range keysPayload.Keys {
		if k.SealedKey != "" {
			if sealedBytes, err := base64.StdEncoding.DecodeString(k.SealedKey); err == nil {
				if dataKey, err := crypto.UnsealDataKey(sealedBytes, privKey); err == nil {
					if reSealed, err := crypto.SealDataKey(dataKey, recipientPubKey); err == nil {
						keyEntries = append(keyEntries, api.SealedKeyEntry{
							NodeID:    k.NodeID,
							SealedKey: base64.StdEncoding.EncodeToString(reSealed),
						})
					}
				}
			}
		}
		if k.E2EEDisplayName != "" {
			if sealedNameBytes, err := base64.StdEncoding.DecodeString(k.E2EEDisplayName); err == nil {
				if plaintext, err := crypto.UnsealDisplayName(sealedNameBytes, privKey); err == nil {
					if reSealed, err := crypto.SealDisplayName(plaintext, recipientPubKey); err == nil {
						nameEntries = append(nameEntries, api.SealedNameEntry{
							NodeID:            k.NodeID,
							SealedDisplayName: base64.StdEncoding.EncodeToString(reSealed),
						})
					}
				}
			}
		}
	}

	return keyEntries, nameEntries
}

func runShareList(targetPath string) {
	resp, _, printed := cmdutil.RunPathCommand[api.ShareListPayload](cmdutil.PathCommand{
		Command: "sr", Path: targetPath, Mode: "list", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runShareRemove(targetPath, username string) {
	cmdutil.RequireLogin(ExitWithError)

	if !GetJSONOutput() && !GetQuietOutput() {
		if !cmdutil.ConfirmAction("Remove "+username+" from "+cmdutil.ResolvePath(targetPath)+"?", srRmForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	ctx, cancel := cmdutil.InterruptContext()
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	srRmOpts := map[string]string{
		"source":   resolvedPath,
		"username": username,
		"mode":     "remove",
	}
	cmdutil.AddPathTokensFor(srRmOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
	_, payload := cmdutil.ExecuteCommand[api.SharePayload](ctx, "sr", srRmOpts, ExitWithError)

	output.PrintSuccess("Removed " + payload.Username + " from " + output.PrintPath(payload.Path))
}

func runShareInbox() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.ShareInboxPayload](ctx, "sr", map[string]string{
		"mode": "inbox",
	}, ExitWithError)

	for i := range payload.Shares {
		s := &payload.Shares[i]
		s.Name = e2ee.ResolveName(s.E2EEDisplayName, s.Name)
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runShareUpdate(targetPath string) {
	options := map[string]string{}
	if srSetUsername != "" {
		options["username"] = srSetUsername
	}
	if srSetPermission != "" {
		options["permissions"] = srSetPermission
	}
	if srSetPassword != "" {
		options["password"] = srSetPassword
	}
	if srSetExpires != "" {
		options["expires"] = srSetExpires
	}
	if srRmPassword {
		options["remove-password"] = "true"
	}
	if srRmExpires {
		options["remove-expiration"] = "true"
	}

	_, payload, printed := cmdutil.RunPathCommand[api.ShareUpdatePayload](cmdutil.PathCommand{
		Command: "sr", Path: targetPath, Mode: "update", Options: options,
		JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}

	output.PrintSuccess("Updated share for " + output.PrintPath(payload.Path))
	for _, change := range payload.Changes {
		fmt.Println("  - " + change)
	}
}

func runShareDecline(targetPath, owner string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	options := map[string]string{
		"source":   targetPath,
		"username": owner,
		"mode":     "decline",
	}
	if nodeID := receivedShareNodeID(ctx, targetPath, owner); nodeID != "" {
		options["node_id"] = nodeID
	}

	_, payload := cmdutil.ExecuteCommand[api.SharePayload](ctx, "sr", options, ExitWithError)

	output.PrintSuccess("Removed share from " + payload.Username + " for " + output.PrintPath(payload.Path))
}

func receivedShareNodeID(ctx context.Context, targetPath, owner string) string {
	_, inbox := cmdutil.ExecuteCommand[api.ShareInboxPayload](ctx, "sr", map[string]string{
		"mode": "inbox",
	}, ExitWithError)

	wanted := strings.Trim(strings.ReplaceAll(targetPath, "\\", "/"), "/")
	if index := strings.LastIndex(wanted, "/"); index >= 0 {
		wanted = wanted[index+1:]
	}
	if wanted == "" {
		return ""
	}

	matched := ""
	for i := range inbox.Shares {
		entry := &inbox.Shares[i]
		if entry.NodeID == "" || !strings.EqualFold(entry.Owner, owner) {
			continue
		}
		name := e2ee.ResolveName(entry.E2EEDisplayName, entry.Name)
		if !strings.EqualFold(entry.NodeID, wanted) && !strings.EqualFold(name, wanted) {
			continue
		}
		if matched != "" && !strings.EqualFold(matched, entry.NodeID) {
			output.PrintError("More than one share from " + owner + " is called " + wanted + "; name it by the node id from `pc sr inbox`.")
			ExitWithError()
			return ""
		}
		matched = entry.NodeID
	}
	return matched
}
