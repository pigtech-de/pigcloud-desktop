package cmd

import (
	"fmt"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var frCmd = &cobra.Command{
	Use:     "fr",
	GroupID: GroupSharing,
	Aliases: []string{"friend"},
	Short:   "Manage friends",
	Example: `  pc fr                    # List your friends
  pc fr add alice           # Send a friend request
  pc fr accept alice        # Accept a friend request
  pc fr decline alice       # Decline a friend request
  pc fr rm alice            # Remove a friend
  pc fr pending             # List pending friend requests`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runFriendList()
	},
}

var frAddCmd = &cobra.Command{
	Use:   "add <username>",
	Short: "Send a friend request",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runFriendAdd(args[0])
	},
}

var frAcceptCmd = &cobra.Command{
	Use:   "accept <username>",
	Short: "Accept a friend request",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runFriendRespond(args[0], "accept")
	},
}

var frDeclineCmd = &cobra.Command{
	Use:   "decline <username>",
	Short: "Decline a friend request",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runFriendRespond(args[0], "decline")
	},
}

var frRmCmd = &cobra.Command{
	Use:   "rm <username>",
	Short: "Remove a friend",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runFriendRemove(args[0])
	},
}

var frPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending friend requests",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runFriendPending()
	},
}

var frListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your friends",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runFriendList()
	},
}

var frRepinCmd = &cobra.Command{
	Use:   "repin <username>",
	Short: "Accept a contact's new encryption key",
	Long: `Move this account's seal pin to the encryption key a contact publishes now.

Shares and chat messages are sealed to the contact's public key, and the CLI
pins the first key it seals to. A rotation the contact signed is accepted on its
own; anything else blocks the seal, because a server can publish a key it holds
the private half of and read everything sealed to it.

Repin prints the pair's safety number, the same eight groups of five digits the
web app shows when you open the chat with that contact and choose Verify safety
number. Read it out to them over a channel the server does not carry, and accept
only if both screens agree.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runFriendRepin(args[0])
	},
}

func init() {
	frRepinCmd.Flags().BoolVarP(&frRepinForce, "force", "f", false, "skip the confirmation prompt")
	frCmd.AddCommand(frListCmd, frAddCmd, frAcceptCmd, frDeclineCmd, frRmCmd, frPendingCmd, frRepinCmd)
	rootCmd.AddCommand(frCmd)
}

var frRepinForce bool

func runFriendList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.FriendListPayload](ctx, "fr", map[string]string{
		"mode": "list",
	}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runFriendAdd(username string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, _ := cmdutil.ExecuteCommand[api.FriendActionPayload](ctx, "fr", map[string]string{
		"mode":     "add",
		"username": username,
	}, ExitWithError)

	output.PrintSuccess(resp.Message)
}

func runFriendRespond(username, action string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, _ := cmdutil.ExecuteCommand[api.FriendActionPayload](ctx, "fr", map[string]string{
		"mode":     action,
		"username": username,
	}, ExitWithError)

	output.PrintSuccess(resp.Message)
}

func runFriendRemove(username string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, _ := cmdutil.ExecuteCommand[api.FriendActionPayload](ctx, "fr", map[string]string{
		"mode":     "remove",
		"username": username,
	}, ExitWithError)

	output.PrintSuccess(resp.Message)
}

func runFriendRepin(username string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	if !e2ee.HasE2EEKeys() {
		output.PrintError("This device has no encryption key set, so there is no pin to move. Run `pc uk` first.")
		ExitWithError()
		return
	}
	offered, err := e2ee.FetchPeerKeyBundle(ctx, username)
	if err != nil {
		output.PrintError("Could not read " + username + "'s published keys: " + err.Error())
		ExitWithError()
		return
	}
	pinned := e2ee.PinnedPeerSealFingerprint(username)
	if pinned == offered.Fingerprint() {
		output.PrintInfo(username + " publishes the key already pinned; nothing to move.")
		return
	}

	safety, err := e2ee.PeerSafetyNumber(offered)
	if err != nil {
		output.PrintError("Could not compute the safety number for " + username + ": " + err.Error())
		ExitWithError()
		return
	}
	fmt.Println("  Safety number with " + username)
	fmt.Println("    " + color.YellowString(safety))
	fmt.Println("  Seal key fingerprint")
	fmt.Println("    pinned: " + color.CyanString(e2ee.FingerprintDisplay(pinned)))
	fmt.Println("    offered: " + color.YellowString(e2ee.FingerprintDisplay(offered.Fingerprint())))
	fmt.Println()
	fmt.Println("  The same server serves these keys and your shares, so the safety number")
	fmt.Println("  only means something read out loud. " + username + " sees it in the web app by")
	fmt.Println("  opening your chat and choosing Verify safety number.")
	fmt.Println()

	answer, hadTerminal := cmdutil.ConfirmActionStrict("Seal to "+username+"'s new key from now on?", frRepinForce)
	if !hadTerminal {
		output.PrintError("Repin needs a terminal to confirm at. Pass --force once you have compared the safety number out of band.")
		ExitWithError()
		return
	}
	if !answer {
		output.PrintInfo("Cancelled; the pin is unchanged.")
		return
	}
	if err := e2ee.RepinPeerSealKey(username, offered); err != nil {
		output.PrintError("Repin failed: " + err.Error())
		ExitWithError()
		return
	}
	output.PrintSuccess("Pinned " + e2ee.FingerprintDisplay(offered.Fingerprint()) + " for " + username)
}

func runFriendPending() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.FriendPendingPayload](ctx, "fr", map[string]string{
		"mode": "pending",
	}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
	fmt.Printf("\n%d pending request(s)\n", len(payload.Pending))
}
