package cmd

import (
	"fmt"
	"os"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	cfgFile       string
	jsonOutput    bool
	quietOutput   bool
	noColorOutput bool
	shellMode     bool
	versionInfo   struct {
		Version string
		Commit  string
		Date    string
	}
)

func SetShellMode(enabled bool) {
	shellMode = enabled
}

func ExitWithError() {
	if shellMode {
		panic("command_error")
	}
	os.Exit(1)
}

const longDescription = `PigCloud CLI allows you to manage your PigCloud storage from the command line.

Upload, download, share, and organize your files without opening the browser.

Quick Start:
  pigcloud login          # Authenticate with your API key
  pigcloud welcome        # Friendly quickstart tour
  pigcloud ls             # List files in current directory
  pigcloud mk newfolder   # Create a new directory
  pigcloud ct file.txt    # Display file content
  pigcloud ul file.txt /  # Upload a file
  pigcloud dl /file.txt . # Download a file`

func buildAliasLine() string {
	return "\n\nUse 'pc' as a shorthand for 'pigcloud'. Run 'pc hl' for the full command tree."
}

var rootCmd = &cobra.Command{
	Use:     "pigcloud",
	Short:   "PigCloud CLI - Manage your cloud files from the terminal",
	Long:    longDescription,
	Version: versionInfo.Version,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		output.SetQuiet(quietOutput)
	},
}

func GetRootCmd() *cobra.Command {
	return rootCmd
}

func Execute() {
	defer e2ee.ClearCachedKey()
	rootCmd.Long = longDescription + buildAliasLine()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func SetVersionInfo(version, commit, date string) {
	versionInfo.Version = version
	versionInfo.Commit = commit
	versionInfo.Date = date
	rootCmd.Version = version
	rootCmd.SetVersionTemplate(fmt.Sprintf("PigCloud CLI v%s (commit: %s, built: %s)\n",
		version, commit, date))
	api.Version = version
}

const (
	GroupAuth    = "auth"
	GroupNav     = "nav"
	GroupFiles   = "files"
	GroupSharing = "sharing"
	GroupTools   = "tools"
)

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		if !config.IsLoggedIn() && !output.IsQuiet() {
			fmt.Println()
			fmt.Println(color.YellowString("ℹ") + " First time? Run " + color.CyanString("pc login") + " to authenticate, then " + color.CyanString("pc hi") + " for a quickstart tour.")
		}
		runHelp()
	}

	rootCmd.SuggestionsMinimumDistance = 2

	rootCmd.AddGroup(
		&cobra.Group{ID: GroupAuth, Title: "Authentication"},
		&cobra.Group{ID: GroupNav, Title: "Navigation"},
		&cobra.Group{ID: GroupFiles, Title: "File Operations"},
		&cobra.Group{ID: GroupSharing, Title: "Sharing"},
		&cobra.Group{ID: GroupTools, Title: "Info & Tools"},
	)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "use custom config file path")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
	rootCmd.PersistentFlags().BoolVarP(&quietOutput, "quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().BoolVar(&noColorOutput, "no-color", false, "disable colored output")
}

func initConfig() {
	if cfgFile != "" {
		config.SetConfigFile(cfgFile)
	}
	config.Load()

	cfg := config.Get()
	if cfg.DefaultJSON && !jsonOutput {
		jsonOutput = true
	}
	if cfg.DefaultQuiet && !quietOutput {
		quietOutput = true
	}
	if cfg.NoColor && !noColorOutput {
		noColorOutput = true
	}
	if noColorOutput {
		os.Setenv("NO_COLOR", "1")
	}
	output.SetJSONErrors(jsonOutput)
}

func GetJSONOutput() bool {
	return jsonOutput
}

func GetQuietOutput() bool {
	return quietOutput
}
