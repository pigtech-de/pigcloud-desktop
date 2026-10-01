package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:     "cm [bash|zsh|fish|powershell]",
	GroupID: GroupTools,
	Aliases: []string{"completion"},
	Short:   "Generate shell completion scripts",
	Long: `Generate shell completion scripts for PigCloud CLI.

To load completions:

Bash:
  $ source <(pigcloud completion bash)
  # To load completions for each session, add to your bashrc:
  $ echo 'source <(pigcloud completion bash)' >> ~/.bashrc

Zsh:
  $ source <(pigcloud completion zsh)
  # To load completions for each session, add to your zshrc:
  $ echo 'source <(pigcloud completion zsh)' >> ~/.zshrc

Fish:
  $ pigcloud completion fish | source
  # To load completions for each session:
  $ pigcloud completion fish > ~/.config/fish/completions/pigcloud.fish

PowerShell:
  PS> pigcloud completion powershell | Out-String | Invoke-Expression
  # To load completions for each session, add to your profile:
  PS> pigcloud completion powershell >> $PROFILE
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
