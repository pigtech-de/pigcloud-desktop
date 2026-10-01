package cmd

import (
	"fmt"

	"pigcloud/internal/config"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var welcomeCmd = &cobra.Command{
	Use:     "hi",
	GroupID: GroupTools,
	Aliases: []string{"welcome"},
	Short:   "Quickstart tour for the PigCloud CLI",
	Example: "pc hi                             # Friendly walkthrough of the CLI",
	Long: `Print a quickstart tour covering identity, common commands, and power
features. Re-run anytime to refresh your memory.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runWelcome()
	},
}

func init() {
	rootCmd.AddCommand(welcomeCmd)
}

func runWelcome() {
	bold := color.HiWhiteString
	cmdStyle := color.CyanString

	fmt.Println()
	fmt.Println(color.CyanString("PigCloud CLI") + " — quickstart tour")
	fmt.Println()

	if !config.IsLoggedIn() {
		fmt.Println("You're not logged in yet.")
		fmt.Println("  Run " + cmdStyle("pc login") + " and paste an API key from Settings > API Key.")
		fmt.Println()
		return
	}

	fmt.Println(bold("YOUR ACCOUNT"))
	fmt.Println("  " + cmdStyle("pc wh") + "                  Confirm who you're logged in as")
	fmt.Println("  " + cmdStyle("pc st") + "                  Show storage usage and limits")
	fmt.Println("  " + cmdStyle("pc cf") + "                  Manage CLI configuration")
	fmt.Println()

	fmt.Println(bold("EVERYDAY FILE OPS"))
	fmt.Println("  " + cmdStyle("pc ls") + "                  List files in the current cloud folder")
	fmt.Println("  " + cmdStyle("pc cd <path>") + "           Change working folder for subsequent commands")
	fmt.Println("  " + cmdStyle("pc ul <file> /") + "         Upload a file to the root")
	fmt.Println("  " + cmdStyle("pc dl /file.txt .") + "      Download a file to the current directory")
	fmt.Println("  " + cmdStyle("pc mk <name>") + "           Create a new folder")
	fmt.Println("  " + cmdStyle("pc rm <path>") + "           Move a file or folder to the trash")
	fmt.Println()

	fmt.Println(bold("SEARCH & SHARING"))
	fmt.Println("  " + cmdStyle("pc fd <query>") + "          Find files by name across all folders")
	fmt.Println("  " + cmdStyle("pc gr <pattern>") + "        Search inside file contents")
	fmt.Println("  " + cmdStyle("pc sr <path> <user>") + "    Share a file or folder with another PigCloud user")
	fmt.Println("  " + cmdStyle("pc pl <path>") + "           Create or manage public links")
	fmt.Println()

	fmt.Println(bold("POWER FEATURES"))
	fmt.Println("  " + cmdStyle("pc mn <local-path>") + "     Mount cloud storage as a local drive")
	fmt.Println("  " + cmdStyle("pc sh") + "                  Drop into an interactive shell")
	fmt.Println("  " + cmdStyle("pc vh <path>") + "           Browse and restore previous file versions")
	fmt.Println("  " + cmdStyle("pc ac") + "                  Show recent account activity / notifications")
	fmt.Println()

	fmt.Println(bold("LEARN MORE"))
	fmt.Println("  " + cmdStyle("pc hl") + "                  Browse the full command tree")
	fmt.Println("  " + cmdStyle("pc hl <command>") + "        Detailed help for a single command")
	fmt.Println()

	if err := config.MarkCLIWelcomeCompleted(); err != nil {
		output.PrintWarning("Could not save welcome state: " + err.Error())
	}
}
