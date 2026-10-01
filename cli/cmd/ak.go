package cmd

import (
	"context"
	"os"
	"os/signal"

	"pigcloud/internal/agent"
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/config"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var akRevokeForce bool

var akCmd = &cobra.Command{
	Use:     "ak",
	GroupID: GroupTools,
	Aliases: []string{"apikeys"},
	Short:   "View or revoke your API key",
	Long: `Show the status of your PigCloud API key, or revoke it.

PigCloud issues a single API key per account, the same key this CLI uses to
authenticate. 'pc ak' shows its identifier, creation time, and last use.

'pc ak revoke' invalidates the key server-side so it stops working everywhere,
then clears it from this machine. Create a new key in account settings on the
web, then run 'pc li' to log back in.`,
	Example: `pc ak                 # Show API key status
pc ak revoke          # Revoke the API key (logs this CLI out)`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runAPIKeyStatus()
	},
}

var akListCmd = &cobra.Command{
	Use:   "ls",
	Short: "Show API key status",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runAPIKeyStatus()
	},
}

var akRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke the API key (logs this CLI out)",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runAPIKeyRevoke()
	},
}

func init() {
	akRevokeCmd.Flags().BoolVarP(&akRevokeForce, "force", "f", false, "skip confirmation prompt")
	akCmd.AddCommand(akListCmd, akRevokeCmd)
	rootCmd.AddCommand(akCmd)
}

func runAPIKeyStatus() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.APIKeyStatusPayload](ctx, "ak", map[string]string{
		"mode": "list",
	}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runAPIKeyRevoke() {
	cmdutil.RequireLogin(ExitWithError)

	if !GetJSONOutput() && !GetQuietOutput() {
		if !cmdutil.ConfirmAction("Revoke your API key? It will stop working everywhere and this CLI will be logged out. This cannot be undone.", akRevokeForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	_, payload := cmdutil.ExecuteCommand[api.APIKeyRevokePayload](ctx, "ak", map[string]string{
		"mode": "revoke",
	}, ExitWithError)

	if payload.Revoked {
		agent.Shutdown()
		e2ee.ClearCachedKey()
		_ = config.Clear()
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if payload.Revoked {
		output.PrintSuccess("API key revoked. Create a new key in account settings, then run 'pc li' to log back in.")
	} else {
		output.PrintInfo("No active API key to revoke.")
	}
}
