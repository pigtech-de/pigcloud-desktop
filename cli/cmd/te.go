package cmd

import (
	"fmt"
	"strings"

	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var teRepinForce bool

var teeCmd = &cobra.Command{
	Use:     "te",
	GroupID: GroupTools,
	Aliases: []string{"tee"},
	Short:   "Review the security scanner's signing keys",
	Long: `Show and manage the enclave signing keys this account has accepted.

Sanitized files carry no owner signature, so the scanner's signing key is the
only anchor they have. The CLI pins the first key it is offered and refuses
every other one. After a deliberate rekey, repin moves the pin to the key the
server offers now and keeps the superseded key on a retired list, so files
signed before the rekey stay readable.

Fingerprints match the ones the web app shows under Settings > Encryption.`,
	Example: `pc te                     # Show the pinned and retired keys
pc te repin               # Move the pin after a deliberate rekey
pc te forget 1a2b3c4d     # Stop accepting one retired key`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runTeeKeys()
	},
}

var teKeysCmd = &cobra.Command{
	Use:   "keys",
	Short: "List the pinned and retired signing keys",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runTeeKeys()
	},
}

var teRepinCmd = &cobra.Command{
	Use:   "repin",
	Short: "Move the pin to the key the server offers now",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runTeeRepin()
	},
}

var teForgetCmd = &cobra.Command{
	Use:   "forget <fingerprint>",
	Short: "Stop accepting one retired signing key",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runTeeForget(args[0])
	},
}

func init() {
	teRepinCmd.Flags().BoolVarP(&teRepinForce, "force", "f", false, "skip the confirmation prompt")
	teeCmd.AddCommand(teKeysCmd, teRepinCmd, teForgetCmd)
	rootCmd.AddCommand(teeCmd)
}

type teeKeyRow struct {
	Fingerprint string `json:"fingerprint"`
	Ed25519     string `json:"ed25519"`
	Mldsa       string `json:"mldsa"`
	Status      string `json:"status"`
	RetiredAt   string `json:"retired_at,omitempty"`
}

func teeKeyRows() []teeKeyRow {
	pinned, retired := e2ee.TeeSigningPins()
	rows := []teeKeyRow{}
	if pinned != nil {
		rows = append(rows, teeKeyRow{
			Fingerprint: pinned.Fingerprint(),
			Ed25519:     pinned.Ed25519,
			Mldsa:       pinned.Mldsa,
			Status:      "pinned",
		})
	}
	for _, key := range retired {
		rows = append(rows, teeKeyRow{
			Fingerprint: key.Fingerprint(),
			Ed25519:     key.Ed25519,
			Mldsa:       key.Mldsa,
			Status:      "retired",
			RetiredAt:   key.RetiredAt,
		})
	}
	return rows
}

func runTeeKeys() {
	rows := teeKeyRows()
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), map[string]any{"keys": rows}) {
		return
	}
	if len(rows) == 0 {
		output.PrintInfo("No scanner signing key is pinned for this account yet.")
		return
	}
	table := output.Table([]string{"Status", "Fingerprint", "Retired"})
	for _, row := range rows {
		_ = table.Append([]string{row.Status, row.Fingerprint, row.RetiredAt})
	}
	_ = table.Render()
}

func runTeeRepin() {
	cmdutil.RequireLogin(ExitWithError)
	if !e2ee.HasE2EEKeys() {
		output.PrintError("This device has no encryption key set, so there is no pin to move. Run `pc uk` first.")
		ExitWithError()
		return
	}
	offer, err := e2ee.OfferedTeeSigningPk()
	if err != nil {
		output.PrintError("The server did not offer an attestation to pin: " + err.Error())
		ExitWithError()
		return
	}
	pinned, _ := e2ee.TeeSigningPins()
	pinnedPosture := e2ee.PinnedTeeAttestationLabel()
	keySame := pinned != nil && pinned.Ed25519 == offer.Ed25519 && pinned.Mldsa == offer.Mldsa
	if keySame && pinnedPosture == offer.PostureLabel() {
		output.PrintInfo("The server is attesting to the key set already pinned; nothing to move.")
		return
	}

	fmt.Println("  Signing keys")
	if pinned == nil {
		fmt.Println("    pinned: " + color.HiBlackString("none"))
	} else {
		fmt.Println("    pinned: " + color.CyanString(pinned.Fingerprint()))
	}
	fmt.Println("    offered: " + color.YellowString(offer.Fingerprint()))
	fmt.Println("  Scanner identity")
	if pinnedPosture == "" {
		fmt.Println("    pinned: " + color.HiBlackString("none"))
	} else {
		fmt.Println("    pinned: " + color.CyanString(pinnedPosture))
	}
	fmt.Println("    offered: " + color.YellowString(offer.PostureLabel()))
	fmt.Println()
	fmt.Println("  The same server answers both the download and this attestation, so")
	fmt.Println("  compare the new fingerprint against the release notes and the public")
	fmt.Println("  pigcloud-tee history before accepting it. See /security#scanner-identity.")
	fmt.Println()

	answer, hadTerminal := cmdutil.ConfirmActionStrict("Move the pin to the offered attestation?", teRepinForce)
	if !hadTerminal {
		output.PrintError("Repin needs a terminal to confirm at. Pass --force once you have compared the fingerprints out of band.")
		ExitWithError()
		return
	}
	if !answer {
		output.PrintInfo("Cancelled; the pin is unchanged.")
		return
	}
	if err := e2ee.RepinTeeSigningPk(offer); err != nil {
		output.PrintError("Repin failed: " + err.Error())
		ExitWithError()
		return
	}
	output.PrintSuccess("Pinned " + offer.Fingerprint())
	if pinned != nil && !keySame {
		output.PrintInfo("Retired " + pinned.Fingerprint() + "; files it signed still verify.")
	}
}

func runTeeForget(fingerprint string) {
	needle := strings.ToLower(strings.ReplaceAll(fingerprint, " ", ""))
	if len(needle) < 8 {
		output.PrintError("Give at least 8 hex characters of the fingerprint.")
		ExitWithError()
		return
	}
	var matches []teeKeyRow
	for _, row := range teeKeyRows() {
		if row.Status != "retired" {
			continue
		}
		if strings.HasPrefix(strings.ReplaceAll(row.Fingerprint, " ", ""), needle) {
			matches = append(matches, row)
		}
	}
	switch len(matches) {
	case 0:
		output.PrintError("No retired signing key matches " + fingerprint + ".")
		ExitWithError()
		return
	case 1:
	default:
		output.PrintError("That prefix matches several retired keys; give more characters.")
		ExitWithError()
		return
	}
	if !e2ee.ForgetRetiredTeeSigningPk(matches[0].Fingerprint) {
		output.PrintError("Could not write the pin store.")
		ExitWithError()
		return
	}
	output.PrintSuccess("Forgot " + matches[0].Fingerprint + "; files it signed refuse from now on.")
}
