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

	"github.com/fatih/color"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

var (
	plPassword     string
	plExpires      string
	plMaxDownloads string
	plRmPassword   bool
	plRmExpires    bool
	plRmMaxDl      bool
	plQR           bool
)

var plCmd = &cobra.Command{
	Use:     "pl <path>",
	GroupID: GroupSharing,
	Aliases: []string{"link"},
	Short:   "Create and manage public links",
	Long: `Manage public links for files and directories.

With a path argument, shows existing link details (or "no link" if none exists).
Use subcommands to create, update, or revoke links.`,
	Example: `pc pl /report.pdf                         # Show link details
pc pl add /report.pdf                     # Create public link
pc pl add /report.pdf -P secret123        # Create with password
pc pl add /report.pdf --qr                # Print a scannable QR code
pc pl set /report.pdf --max-downloads 50  # Set download limit
pc pl rm /report.pdf                      # Revoke link`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			output.PrintError("Path required. Usage: pc pl <path>")
			ExitWithError()
		}
		runLinkGet(args[0])
	},
}

var plAddCmd = &cobra.Command{
	Use:               "add <path>",
	Short:             "Create a public link",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runLinkCreate(args[0])
	},
}

var plSetCmd = &cobra.Command{
	Use:               "set <path>",
	Short:             "Update public link settings",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runLinkUpdate(args[0])
	},
}

var plRmForce bool

var plRmCmd = &cobra.Command{
	Use:               "rm <path>",
	Short:             "Revoke a public link",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runLinkDelete(args[0])
	},
}

var plListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List all public links",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runLinkList()
	},
}

func init() {
	plAddCmd.Flags().StringVarP(&plPassword, "password", "P", "", "protect link with a password")
	plAddCmd.Flags().StringVarP(&plExpires, "expires", "e", "", "expiration date (e.g. 2026-03-01)")
	plAddCmd.Flags().StringVar(&plMaxDownloads, "max-downloads", "", "maximum download count")
	plAddCmd.Flags().BoolVar(&plQR, "qr", false, "print the link as a terminal QR code")

	plSetCmd.Flags().StringVarP(&plPassword, "password", "P", "", "set or change password")
	plSetCmd.Flags().StringVarP(&plExpires, "expires", "e", "", "set or change expiration")
	plSetCmd.Flags().StringVar(&plMaxDownloads, "max-downloads", "", "set download limit")
	plSetCmd.Flags().BoolVar(&plRmPassword, "remove-password", false, "remove password protection")
	plSetCmd.Flags().BoolVar(&plRmExpires, "remove-expiration", false, "remove expiration date")
	plSetCmd.Flags().BoolVar(&plRmMaxDl, "remove-max-downloads", false, "remove download limit")

	plRmCmd.Flags().BoolVarP(&plRmForce, "force", "f", false, "skip confirmation prompt")
	plCmd.AddCommand(plListCmd, plAddCmd, plSetCmd, plRmCmd)
	rootCmd.AddCommand(plCmd)
}

func runLinkCreate(targetPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	options := map[string]string{
		"source": resolvedPath,
		"mode":   "create",
	}
	if plPassword != "" {
		options["password"] = plPassword
	}
	if plExpires != "" {
		options["expires"] = plExpires
	}
	if plMaxDownloads != "" {
		options["max-downloads"] = plMaxDownloads
	}

	e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfOnly, ExitWithError)

	var linkKeyFragment string
	var linkKeyRaw []byte
	if e2ee.HasE2EEKeys() {
		fragment, sealedLinkKeyB64, nonceB64, rawKey := generateLinkKey(ctx, resolvedPath)
		if fragment != "" {
			linkKeyFragment = fragment
			linkKeyRaw = rawKey
			options["sealed_link_key"] = sealedLinkKeyB64
			options["link_key_nonce"] = nonceB64
		}
		if linkKeyRaw == nil {
			rawKey, err := crypto.GenerateDataKey()
			if err == nil {
				linkKeyRaw = rawKey
				linkKeyFragment = base64.RawURLEncoding.EncodeToString(rawKey)
			}
		}
		if linkKeyRaw != nil {
			encNames := encryptLinkNameFromPath(resolvedPath, linkKeyRaw)
			if encNames != "" {
				options["encrypted_names"] = encNames
			}
		}
	}

	_, payload := cmdutil.ExecuteCommand[api.LinkCreatePayload](ctx, "pl", options, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	url := payload.URL
	if linkKeyFragment != "" {
		url += "#key=" + linkKeyFragment
	}
	fmt.Println(color.CyanString(url))
	if plQR {
		printLinkQR(url)
	}
}

func printLinkQR(url string) {
	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		output.PrintError("QR generation failed: " + err.Error())
		return
	}
	fmt.Println()
	fmt.Print(qr.ToSmallString(false))
}

func generateLinkKey(ctx context.Context, filePath string) (string, string, string, []byte) {
	client := api.NewClient()

	listKeysOpts := map[string]string{"source": filePath}
	e2ee.AddPathTokensFor(listKeysOpts, filePath, e2ee.SelfOnly, ExitWithError)
	keysResp, err := client.Execute(ctx, "e2ee_list_keys", listKeysOpts)
	if err != nil || !keysResp.Success {
		return "", "", "", nil
	}
	var keysPayload api.E2EEListKeysPayload
	if err := json.Unmarshal(keysResp.Raw, &keysPayload); err != nil {
		return "", "", "", nil
	}
	if len(keysPayload.Keys) == 0 {
		return "", "", "", nil
	}

	_, privKey := e2ee.GetKeyPair(ExitWithError)

	sealedBytes, err := base64.StdEncoding.DecodeString(keysPayload.Keys[0].SealedKey)
	if err != nil {
		return "", "", "", nil
	}
	dataKey, err := crypto.UnsealDataKey(sealedBytes, privKey)
	if err != nil {
		return "", "", "", nil
	}

	linkKey, err := crypto.GenerateDataKey()
	if err != nil {
		return "", "", "", nil
	}

	sealedLinkKey, nonce, err := crypto.EncryptWithKey(dataKey, linkKey)
	if err != nil {
		return "", "", "", nil
	}

	linkKeyB64URL := base64.RawURLEncoding.EncodeToString(linkKey)
	sealedLinkKeyB64 := base64.StdEncoding.EncodeToString(sealedLinkKey)
	nonceB64 := base64.StdEncoding.EncodeToString(nonce)

	return linkKeyB64URL, sealedLinkKeyB64, nonceB64, linkKey
}

func encryptLinkNameFromPath(filePath string, linkKey []byte) string {
	parts := strings.Split(strings.Trim(filePath, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	name := parts[len(parts)-1]
	if name == "" {
		return ""
	}

	ct, nonce, err := crypto.EncryptWithKey([]byte(name), linkKey)
	if err != nil {
		return ""
	}

	type encEntry struct {
		CT string `json:"ct"`
		N  string `json:"n"`
	}
	result := map[string]encEntry{
		"root": {
			CT: base64.StdEncoding.EncodeToString(ct),
			N:  base64.StdEncoding.EncodeToString(nonce),
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}
	return string(data)
}

func runLinkGet(targetPath string) {
	resp, _, printed := cmdutil.RunPathCommand[api.LinkGetPayload](cmdutil.PathCommand{
		Command: "pl", Path: targetPath, Mode: "get", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runLinkUpdate(targetPath string) {
	options := map[string]string{}
	if plPassword != "" {
		options["password"] = plPassword
	}
	if plExpires != "" {
		options["expires"] = plExpires
	}
	if plMaxDownloads != "" {
		options["max-downloads"] = plMaxDownloads
	}
	if plRmPassword {
		options["remove-password"] = "true"
	}
	if plRmExpires {
		options["remove-expiration"] = "true"
	}
	if plRmMaxDl {
		options["remove-max-downloads"] = "true"
	}

	_, _, printed := cmdutil.RunPathCommand[api.LinkActionPayload](cmdutil.PathCommand{
		Command: "pl", Path: targetPath, Mode: "update", Options: options,
		Scope: e2ee.SelfOnly, JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}

	output.PrintSuccess("Public link updated")
}

func runLinkDelete(targetPath string) {
	cmdutil.RequireLogin(ExitWithError)

	resolvedForPrompt := cmdutil.ResolvePath(targetPath)
	if !GetJSONOutput() && !GetQuietOutput() {
		if !cmdutil.ConfirmAction("Revoke public link for "+resolvedForPrompt+"?", plRmForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	plDelOpts := map[string]string{
		"source": resolvedPath,
		"mode":   "delete",
	}
	e2ee.AddPathTokensFor(plDelOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
	cmdutil.ExecuteCommand[api.LinkActionPayload](ctx, "pl", plDelOpts, ExitWithError)

	output.PrintSuccess("Public link removed for " + output.PrintPath(resolvedPath))
}

func runLinkList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.LinkListPayload](ctx, "pl", map[string]string{
		"mode": "list",
	}, ExitWithError)

	for i := range payload.Links {
		link := &payload.Links[i]
		if link.E2EEDisplayName != "" {
			decrypted := e2ee.DecryptE2EEName(link.E2EEDisplayName)
			if decrypted != "" {
				link.E2EEDisplayName = decrypted
			}
		}
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}
