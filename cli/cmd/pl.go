package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

	cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfOnly, ExitWithError)

	linkKey := addLinkKeyMaterial(ctx, resolvedPath, options)
	if linkKey == nil {
		return
	}

	_, payload := cmdutil.ExecuteCommand[api.LinkCreatePayload](ctx, "pl", options, ExitWithError)
	payload.URL += linkKeyFragment(linkKey)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	fmt.Println(color.CyanString(payload.URL))
	if plQR {
		printLinkQR(payload.URL)
	}
}

func linkKeyFragment(linkKey []byte) string {
	return "#key=" + base64.RawURLEncoding.EncodeToString(linkKey)
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

const publicLinkTreeMaxNodes = 2000

func addLinkKeyMaterial(ctx context.Context, resolvedPath string, options map[string]string) []byte {
	pub, priv := cmdutil.GetKeyPair(ExitWithError)
	if pub == nil || priv == nil {
		return nil
	}
	root, err := cmdutil.StatRemote(ctx, resolvedPath)
	if errors.Is(err, cmdutil.ErrRemoteMissing) {
		err = fmt.Errorf("not found: %s", resolvedPath)
	}
	if err != nil {
		refuseWrite(err)
		return nil
	}
	listOpts := map[string]string{
		"source":          resolvedPath,
		"include_names":   "1",
		"include_dirs":    "1",
		"include_parents": "1",
	}
	cmdutil.AddPathTokensFor(listOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
	_, listed := cmdutil.ExecuteCommand[api.E2EEListKeysPayload](ctx, "e2ee_list_keys", listOpts, ExitWithError)

	linkKey, err := crypto.GenerateDataKey()
	if err == nil {
		err = buildLinkKeyMaterial(options, resolvedPath, root, listed.Keys, linkKey, pub, priv)
	}
	if err != nil {
		refuseWrite(err)
		return nil
	}
	return linkKey
}

type linkSnapshotNode struct {
	CT string `json:"ct"`
	N  string `json:"n"`
	D  int    `json:"d"`
	P  string `json:"p"`
	K  string `json:"k,omitempty"`
	KN string `json:"kn,omitempty"`
}

func buildLinkKeyMaterial(options map[string]string, resolvedPath string, root e2ee.RemoteNode, entries []api.E2EEKeyEntry, linkKey []byte, pub *crypto.PublicKeySet, priv *crypto.PrivateKeySet) error {
	underLink := func(plain []byte) (string, string, error) {
		ct, nonce, err := crypto.EncryptWithKey(plain, linkKey)
		return base64.StdEncoding.EncodeToString(ct), base64.StdEncoding.EncodeToString(nonce), err
	}
	rootID := strings.ToLower(root.ID)
	var rootEntry *api.E2EEKeyEntry
	var members []api.E2EEKeyEntry
	for i := range entries {
		switch {
		case rootID != "" && strings.ToLower(entries[i].NodeID) == rootID:
			rootEntry = &entries[i]
		case root.IsDir && !entries[i].IsTrashed:
			members = append(members, entries[i])
		}
	}
	if rootEntry == nil {
		return fmt.Errorf("not found: %s", resolvedPath)
	}
	if len(members) > publicLinkTreeMaxNodes {
		return fmt.Errorf("folder too large for a public link: links hold up to %d items", publicLinkTreeMaxNodes)
	}

	rootName, err := unsealEntryName(rootEntry, priv)
	if err != nil {
		return err
	}
	rootCT, rootN, err := underLink([]byte(rootName))
	if err != nil {
		return err
	}
	snapshot := map[string]any{"v": 3, "root": map[string]string{"ct": rootCT, "n": rootN}}
	if !root.IsDir {
		dataKey, err := unsealEntryDataKey(rootEntry, priv)
		if err != nil {
			return err
		}
		if options["sealed_link_key"], options["link_key_nonce"], err = underLink(dataKey); err != nil {
			return err
		}
	}
	for i := range members {
		node, err := buildLinkSnapshotNode(&members[i], priv, underLink)
		if err != nil {
			return err
		}
		snapshot[strings.ToLower(members[i].NodeID)] = node
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	accessHash, err := crypto.PublicLinkAccessHash(linkKey)
	if err != nil {
		return err
	}
	ownerSealed, err := crypto.SealDataKey(linkKey, pub)
	if err != nil {
		return err
	}
	options["encrypted_names"] = string(encoded)
	options["access_hash"] = base64.StdEncoding.EncodeToString(accessHash)
	options["owner_sealed_link_key"] = base64.StdEncoding.EncodeToString(ownerSealed)
	return nil
}

func buildLinkSnapshotNode(entry *api.E2EEKeyEntry, priv *crypto.PrivateKeySet, underLink func([]byte) (string, string, error)) (linkSnapshotNode, error) {
	name, err := unsealEntryName(entry, priv)
	if err != nil {
		return linkSnapshotNode{}, err
	}
	node := linkSnapshotNode{P: strings.ToLower(entry.ParentID)}
	if node.CT, node.N, err = underLink([]byte(name)); err != nil {
		return linkSnapshotNode{}, err
	}
	if entry.IsDir {
		node.D = 1
		return node, nil
	}
	dataKey, err := unsealEntryDataKey(entry, priv)
	if err != nil {
		return linkSnapshotNode{}, err
	}
	if node.K, node.KN, err = underLink(dataKey); err != nil {
		return linkSnapshotNode{}, err
	}
	return node, nil
}

func unsealEntryName(entry *api.E2EEKeyEntry, priv *crypto.PrivateKeySet) (string, error) {
	sealed, err := base64.StdEncoding.DecodeString(entry.E2EEDisplayName)
	if err != nil {
		return "", err
	}
	return crypto.UnsealDisplayName(sealed, priv)
}

func unsealEntryDataKey(entry *api.E2EEKeyEntry, priv *crypto.PrivateKeySet) ([]byte, error) {
	sealed, err := base64.StdEncoding.DecodeString(entry.SealedKey)
	if err != nil {
		return nil, err
	}
	return crypto.UnsealDataKey(sealed, priv)
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

	ctx, cancel := cmdutil.InterruptContext()
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	plDelOpts := map[string]string{
		"source": resolvedPath,
		"mode":   "delete",
	}
	cmdutil.AddPathTokensFor(plDelOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
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
		link.E2EEDisplayName = e2ee.ResolveName(link.E2EEDisplayName, "")
	}
	keyed := restoreOwnerLinkURLs(payload.Links)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	patchLinkListURLs(resp, payload.Links, keyed)
	cmdutil.RenderServerDisplay(resp)
}

func restoreOwnerLinkURLs(links []api.LinkListItem) []bool {
	keyed := make([]bool, len(links))
	if !e2ee.HasE2EEKeys() {
		return keyed
	}
	var priv *crypto.PrivateKeySet
	for i := range links {
		sealed, err := base64.StdEncoding.DecodeString(links[i].OwnerSealedLinkKey)
		if err != nil || len(sealed) == 0 {
			continue
		}
		if priv == nil {
			if _, priv, err = e2ee.GetKeyPair(); err != nil {
				return keyed
			}
		}
		linkKey, err := crypto.UnsealDataKey(sealed, priv)
		if err != nil || len(linkKey) != crypto.KeySize {
			continue
		}
		links[i].URL += linkKeyFragment(linkKey)
		keyed[i] = true
	}
	return keyed
}

func patchLinkListURLs(resp *api.Response, links []api.LinkListItem, keyed []bool) {
	if resp == nil || !slices.Contains(keyed, true) {
		return
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(resp.Raw, &raw) != nil {
		return
	}
	var blocks []output.DisplayBlock
	if json.Unmarshal(raw["_display"], &blocks) != nil {
		return
	}
	for b := range blocks {
		if blocks[b].Type != "table" || len(blocks[b].Rows) != len(links) {
			continue
		}
		for i, row := range blocks[b].Rows {
			if keyed[i] && len(row) > 0 {
				row[len(row)-1] = output.DisplayCell{Text: links[i].URL, Style: "accent"}
			}
		}
	}
	patched, err := json.Marshal(blocks)
	if err != nil {
		return
	}
	raw["_display"] = patched
	if encoded, err := json.Marshal(raw); err == nil {
		resp.Raw = encoded
	}
}
