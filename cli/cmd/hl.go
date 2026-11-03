package cmd

import (
	"slices"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"

	"github.com/spf13/cobra"
)

var hlVerbose bool

var hlCmd = &cobra.Command{
	Use:     "hl [command]",
	GroupID: GroupTools,
	Aliases: []string{"help"},
	Short:   "Show help for commands",
	Long:    `Display help information about PigCloud CLI commands.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			rootCmd.Help()
		} else {
			runHelpDetail(args[0])
		}
	},
}

func init() {
	hlCmd.Flags().BoolVarP(&hlVerbose, "verbose", "v", false, "Show detailed information including defaults and related commands")
	rootCmd.AddCommand(hlCmd)
}

func runHelpDetail(commandName string) {
	if localCmd := findLocalCommand(commandName); localCmd != nil {
		localCmd.Help()
		return
	}

	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()
	options := map[string]string{"source": commandName}
	if hlVerbose {
		options["verbose"] = "true"
	}
	resp, payload := cmdutil.ExecuteCommand[api.HelpDetailPayload](ctx, "hl", options, ExitWithError)
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func findLocalCommand(name string) *cobra.Command {
	clientOnly := map[string]bool{
		"li": true, "login": true,
		"lo": true, "logout": true,
		"lk": true, "lock": true,
		"uk": true, "unlock": true,
		"cf": true, "config": true,
		"cm": true, "completion": true,
		"op": true, "open": true,
		"sh": true, "shell": true,
		"vr": true, "version": true,
		"mn": true, "mount": true,
		"di": true, "diff": true,
		"dr": true, "doctor": true,
		"vf": true, "verify": true,
		"hi": true, "welcome": true,
		"te": true, "tee": true,
	}
	if !clientOnly[name] {
		return nil
	}
	for _, sub := range rootCmd.Commands() {
		if sub.Name() == name {
			return sub
		}
		if slices.Contains(sub.Aliases, name) {
			return sub
		}
	}
	return nil
}
