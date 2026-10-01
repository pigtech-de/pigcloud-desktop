package cmd

import (
	"context"
	"os"
	"os/signal"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var ssCmd = &cobra.Command{
	Use:     "ss",
	GroupID: GroupTools,
	Aliases: []string{"sessions"},
	Short:   "Manage active sessions and devices",
	Long: `View and manage active login sessions and trusted devices.

Without arguments, lists all sessions and trusted devices.
Use subcommands to revoke sessions or forget devices.`,
	Example: `pc ss                          # List sessions and devices
pc ss revoke <session-id>      # Revoke a session
pc ss revoke-all               # Revoke all other sessions
pc ss devices                  # List trusted devices only
pc ss forget <device-id>       # Remove a trusted device`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runSessionList()
	},
}

var ssListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List active sessions and devices",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runSessionList()
	},
}

var ssRevokeCmd = &cobra.Command{
	Use:   "revoke <session-id>",
	Short: "Revoke an active session",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSessionRevoke(args[0])
	},
}

var ssRevokeAllForce bool

var ssRevokeAllCmd = &cobra.Command{
	Use:   "revoke-all",
	Short: "Revoke all other sessions",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runSessionRevokeAll()
	},
}

var ssDevicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "List trusted devices",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runSessionDevices()
	},
}

var ssForgetCmd = &cobra.Command{
	Use:   "forget <device-id>",
	Short: "Remove a trusted device",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runSessionForget(args[0])
	},
}

func init() {
	ssRevokeAllCmd.Flags().BoolVarP(&ssRevokeAllForce, "force", "f", false, "skip confirmation prompt")
	ssCmd.AddCommand(ssListCmd, ssRevokeCmd, ssRevokeAllCmd, ssDevicesCmd, ssForgetCmd)
	rootCmd.AddCommand(ssCmd)
}

func runSessionList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.SessionsPayload](ctx, "ss", map[string]string{
		"mode": "list",
	}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runSessionRevoke(sessionID string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, _ := cmdutil.ExecuteCommand[any](ctx, "ss", map[string]string{
		"mode":       "revoke",
		"session-id": sessionID,
	}, ExitWithError)

	output.PrintSuccess(resp.Message)
}

func runSessionRevokeAll() {
	cmdutil.RequireLogin(ExitWithError)

	answer, hadTerminal := cmdutil.ConfirmActionStrict("Revoke all other sessions?", ssRevokeAllForce)
	if !hadTerminal {
		output.PrintError("Revoking every other session needs a terminal to confirm at. Pass --force to do it from a script.")
		ExitWithError()
		return
	}
	if !answer {
		output.PrintInfo("Cancelled")
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	resp, _ := cmdutil.ExecuteCommand[any](ctx, "ss", map[string]string{
		"mode": "revoke-all",
	}, ExitWithError)

	output.PrintSuccess(resp.Message)
}

func runSessionDevices() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.SessionsPayload](ctx, "ss", map[string]string{
		"mode": "devices",
	}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runSessionForget(deviceID string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, _ := cmdutil.ExecuteCommand[any](ctx, "ss", map[string]string{
		"mode":      "forget",
		"device-id": deviceID,
	}, ExitWithError)

	output.PrintSuccess(resp.Message)
}
