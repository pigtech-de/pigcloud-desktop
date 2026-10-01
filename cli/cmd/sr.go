package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
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

	if e2ee.HasE2EEKeys() {
		sealedKeys, sealedNames := resealKeysAndNamesForRecipient(ctx, resolvedPath, username)
		if sealedKeys != "" {
			options["sealed_keys"] = sealedKeys
		}
		if sealedNames != "" {
			options["sealed_names"] = sealedNames
		}
	}

	e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfOnly, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.SharePayload](ctx, "sr", options, ExitWithError)

	if payload.Status == "revoked" {
		output.PrintSuccess("Revoked sharing of " + output.PrintPath(payload.Path) + " from " + payload.Username)
	} else {
		output.PrintSuccess("Shared " + output.PrintPath(payload.Path) + " with " + payload.Username + " (" + payload.Permission + ")")
	}
}

func resealKeysAndNamesForRecipient(ctx context.Context, folderPath, recipientUsername string) (string, string) {
	client := api.NewClient()

	pubkeyResp, err := client.FetchPublicKey(ctx, recipientUsername)
	if err != nil || !pubkeyResp.Success {
		return "", ""
	}
	var pubkeyPayload api.E2EEPubkeyPayload
	if err := json.Unmarshal(pubkeyResp.Raw, &pubkeyPayload); err != nil {
		return "", ""
	}
	recipientPubKey, err := e2ee.PinPeerSealKeyFromPubkey(recipientUsername, &pubkeyPayload)
	if err != nil {
		output.PrintError(err.Error())
		ExitWithError()
		return "", ""
	}

	keysResp, err := client.Execute(ctx, "e2ee_list_keys", map[string]string{
		"source":        folderPath,
		"include_names": "1",
		"include_dirs":  "1",
	})
	if err != nil || !keysResp.Success {
		return "", ""
	}
	var keysPayload api.E2EEListKeysPayload
	if err := json.Unmarshal(keysResp.Raw, &keysPayload); err != nil {
		return "", ""
	}
	if len(keysPayload.Keys) == 0 {
		return "", ""
	}

	_, privKey := e2ee.GetKeyPair(ExitWithError)

	type sealedKeyEntry struct {
		NodeID    string `json:"node_id"`
		SealedKey string `json:"sealed_key"`
	}
	type sealedNameEntry struct {
		NodeID            string `json:"node_id"`
		SealedDisplayName string `json:"sealed_display_name"`
	}
	var keyEntries []sealedKeyEntry
	var nameEntries []sealedNameEntry

	for _, k := range keysPayload.Keys {
		if k.SealedKey != "" {
			if sealedBytes, err := base64.StdEncoding.DecodeString(k.SealedKey); err == nil {
				if dataKey, err := crypto.UnsealDataKey(sealedBytes, privKey); err == nil {
					if reSealed, err := crypto.SealDataKey(dataKey, recipientPubKey); err == nil {
						keyEntries = append(keyEntries, sealedKeyEntry{
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
						nameEntries = append(nameEntries, sealedNameEntry{
							NodeID:            k.NodeID,
							SealedDisplayName: base64.StdEncoding.EncodeToString(reSealed),
						})
					}
				}
			}
		}
	}

	var keysJSON, namesJSON string
	if len(keyEntries) > 0 {
		if data, err := json.Marshal(keyEntries); err == nil {
			keysJSON = string(data)
		}
	}
	if len(nameEntries) > 0 {
		if data, err := json.Marshal(nameEntries); err == nil {
			namesJSON = string(data)
		}
	}
	return keysJSON, namesJSON
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	srRmOpts := map[string]string{
		"source":   resolvedPath,
		"username": username,
		"mode":     "remove",
	}
	e2ee.AddPathTokensFor(srRmOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
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
		if s.E2EEDisplayName != "" {
			s.Name = e2ee.DecryptE2EEName(s.E2EEDisplayName)
		}
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
		name := entry.Name
		if entry.E2EEDisplayName != "" {
			name = e2ee.DecryptE2EEName(entry.E2EEDisplayName)
		}
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
