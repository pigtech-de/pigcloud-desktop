package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var (
	ukTTL   string
	ukStdin bool
)

var ukCmd = &cobra.Command{
	Use:     "uk",
	GroupID: GroupAuth,
	Aliases: []string{"unlock"},
	Short:   "Unlock encryption keys for this session",
	Long: `Unlock your encryption keys so subsequent commands don't prompt for a password.

Starts a background agent that holds your decrypted keys in memory.
The agent automatically expires after the TTL (default: 1 hour).

Use 'pc lk' to lock (stop the agent) manually.`,
	Example: `pc uk              # Unlock for 1 hour (default)
pc uk -t 8h          # Unlock for 8 hours
pc uk -t 30m         # Unlock for 30 minutes`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runUnlock()
	},
}

func init() {
	ukCmd.Flags().StringVarP(&ukTTL, "ttl", "t", "1h", "how long to keep keys unlocked (e.g. 30m, 2h, 8h)")
	ukCmd.Flags().BoolVar(&ukStdin, "stdin", false, "read the account password from stdin instead of prompting (non-interactive/GUI callers)")
	rootCmd.AddCommand(ukCmd)
}

func runUnlock() {
	cmdutil.RequireLogin(ExitWithError)

	if agent.IsRunning() {
		output.PrintInfo("Already unlocked")
		return
	}

	ttl, err := time.ParseDuration(ukTTL)
	if err != nil {
		output.PrintError("Invalid TTL: " + ukTTL)
		ExitWithError()
	}
	if ttl < time.Minute {
		ttl = time.Minute
	}

	if ukStdin {
		pw, err := readStdinPassword(os.Stdin)
		if err != nil {
			output.PrintError("Failed to read password from stdin: " + err.Error())
			ExitWithError()
		}
		if pw == "" {
			output.PrintError("No password on stdin")
			ExitWithError()
		}
		e2ee.SetSuppliedPassword([]byte(pw))
	}

	pub, priv := e2ee.GetKeyPair(ExitWithError)
	nameKey := e2ee.GetNameKey(ExitWithError)
	signPub, signPriv := e2ee.GetSigningKeysIfAvailable(ExitWithError)

	if err := e2ee.StartAgentForKeys(pub, priv, nameKey, signPub, signPriv, ttl); err != nil {
		output.PrintError("Failed to start agent: " + err.Error())
		ExitWithError()
	}

	ttlDisplay := formatTTL(ttl)
	output.PrintSuccess(fmt.Sprintf("Unlocked (expires in %s)", ttlDisplay))
}

func readStdinPassword(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

func DeriveAndStartAgent(pub *crypto.PublicKeySet, priv *crypto.PrivateKeySet) {
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		return
	}
	signPub, signPriv := e2ee.GetSigningKeysIfAvailable(func() {})
	e2ee.StartAgentForKeys(pub, priv, nameKey, signPub, signPriv, time.Hour)
}

func formatTTL(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	m := int(d.Minutes())
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}
