package cmd

import (
	"fmt"
	"slices"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
			runHelp()
		} else {
			runHelpDetail(args[0])
		}
	},
}

func init() {
	hlCmd.Flags().BoolVarP(&hlVerbose, "verbose", "v", false, "Show detailed information including defaults and related commands")
	rootCmd.AddCommand(hlCmd)
}

var groupOrder = []string{GroupAuth, GroupNav, GroupFiles, GroupSharing, GroupTools}

func runHelp() {
	fmt.Println()
	fmt.Println(color.CyanString("PigCloud CLI") + " - Manage your cloud files from the terminal")
	fmt.Println()
	fmt.Println(color.HiWhiteString("USAGE"))
	fmt.Println("  pigcloud <command> [arguments]")
	fmt.Println("  pc <command> [arguments]")
	fmt.Println()
	fmt.Println(color.HiWhiteString("COMMANDS"))

	grouped := map[string][]*cobra.Command{}
	for _, cmd := range rootCmd.Commands() {
		if cmd.Hidden || cmd.Name() == "help" {
			continue
		}
		gid := cmd.GroupID
		if gid == "" {
			gid = GroupTools
		}
		grouped[gid] = append(grouped[gid], cmd)
	}

	for gi, gid := range groupOrder {
		cmds := grouped[gid]
		if len(cmds) == 0 {
			continue
		}

		title := gid
		for _, g := range rootCmd.Groups() {
			if g.ID == gid {
				title = g.Title
				break
			}
		}

		isLastGroup := gi == len(groupOrder)-1
		groupConnector := "├── "
		groupPrefix := "│   "
		if isLastGroup {
			groupConnector = "└── "
			groupPrefix = "    "
		}

		fmt.Printf("\n%s%s\n", groupConnector, color.YellowString(title))

		for ci, cmd := range cmds {
			isLastCmd := ci == len(cmds)-1
			subs := visibleSubcommands(cmd)
			hasSubs := len(subs) > 0

			cmdConnector := "├── "
			cmdChildPrefix := "│   "
			if isLastCmd {
				cmdConnector = "└── "
				cmdChildPrefix = "    "
			}

			name := cmd.Name()
			aliases := cmd.Aliases
			label := name
			if len(aliases) > 0 {
				label = name + ", " + strings.Join(aliases, ", ")
			}

			flagHints := buildFlagHints(cmd)
			desc := cmd.Short
			if flagHints != "" {
				desc += " " + color.HiBlackString(flagHints)
			}

			fmt.Printf("%s%s%-16s %s\n", groupPrefix, cmdConnector, label, desc)

			for si, sub := range subs {
				isLastSub := si == len(subs)-1
				subConnector := "├── "
				if isLastSub {
					subConnector = "└── "
				}
				subLabel := sub.Name()
				subDesc := sub.Short
				subFlagHints := buildFlagHints(sub)
				if subFlagHints != "" {
					subDesc += " " + color.HiBlackString(subFlagHints)
				}
				fmt.Printf("%s%s%s%-12s %s\n", groupPrefix, cmdChildPrefix, subConnector, subLabel, subDesc)
			}

			if hasSubs && !isLastCmd {
				fmt.Printf("%s%s\n", groupPrefix, "│")
			}
		}
	}

	fmt.Println()
	fmt.Println(color.HiWhiteString("GLOBAL FLAGS"))
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Name == "help" {
			return
		}
		label := "--" + f.Name
		if f.Shorthand != "" {
			label = "-" + f.Shorthand + ", --" + f.Name
		}
		fmt.Printf("    %-15s%s\n", label, strings.ToUpper(f.Usage[:1])+f.Usage[1:])
	})
	if rootCmd.Version != "" {
		fmt.Printf("    %-15s%s\n", "--version", "Show version")
	}

	fmt.Println()
	fmt.Println("Use " + color.CyanString("pc hl <command>") + " for more information about a command.")
	fmt.Println()
}

func visibleSubcommands(cmd *cobra.Command) []*cobra.Command {
	var subs []*cobra.Command
	for _, sub := range cmd.Commands() {
		if !sub.Hidden {
			subs = append(subs, sub)
		}
	}
	return subs
}

func runHelpDetail(commandName string) {
	if localCmd := findLocalCommand(commandName); localCmd != nil {
		renderLocalHelp(localCmd)
		return
	}

	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()
	options := map[string]string{"source": commandName}
	if hlVerbose {
		options["verbose"] = "true"
	}
	_, payload := cmdutil.ExecuteCommand[api.HelpDetailPayload](ctx, "hl", options, ExitWithError)
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	if payload.Command == nil {
		output.PrintError("Unknown command: " + commandName)
		ExitWithError()
		return
	}
	renderCommandDetail(payload.Command)
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

func renderLocalHelp(cmd *cobra.Command) {
	fmt.Println()
	label := color.CyanString(cmd.Name())
	if len(cmd.Aliases) > 0 {
		label += color.HiBlackString(" (" + strings.Join(cmd.Aliases, ", ") + ")")
	}
	fmt.Println("  " + label)
	fmt.Println()

	desc := cmd.Long
	if desc == "" {
		desc = cmd.Short
	}
	if desc != "" {
		fmt.Println("  " + desc)
		fmt.Println()
	}

	if cmd.HasAvailableLocalFlags() {
		fmt.Println(color.HiWhiteString("  OPTIONS"))
		cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden || f.Name == "help" {
				return
			}
			flagLabel := "--" + f.Name
			if f.Shorthand != "" {
				flagLabel = "-" + f.Shorthand + ", --" + f.Name
			}
			typeStr := ""
			if f.Value.Type() != "bool" {
				typeStr = " <" + f.Value.Type() + ">"
			}
			usage := f.Usage
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				usage += color.HiBlackString(" (default: " + f.DefValue + ")")
			}
			fmt.Printf("    %-22s%s\n", flagLabel+typeStr, usage)
		})
		fmt.Println()
	}

	if cmd.Example != "" {
		fmt.Println(color.HiWhiteString("  EXAMPLES"))
		for line := range strings.SplitSeq(strings.TrimSpace(cmd.Example), "\n") {
			fmt.Println("    " + strings.TrimSpace(line))
		}
		fmt.Println()
	}
}

func renderCommandDetail(detail *api.HelpCommandDetail) {
	fmt.Println()
	label := color.CyanString(detail.Command)
	if len(detail.Aliases) > 0 {
		label += color.HiBlackString(" (" + strings.Join(detail.Aliases, ", ") + ")")
	}
	fmt.Println("  " + label)
	fmt.Println()

	fmt.Println("  " + detail.Description)
	fmt.Println()

	if len(detail.Options) > 0 {
		fmt.Println(color.HiWhiteString("  OPTIONS"))
		for _, opt := range detail.Options {
			var flagParts []string
			for _, alias := range opt.Aliases {
				flagParts = append(flagParts, "-"+alias)
			}
			flagParts = append(flagParts, "--"+opt.Name)
			flagLabel := strings.Join(flagParts, ", ")

			typeStr := ""
			if opt.Type != "bool" && opt.Type != "" {
				typeStr = " <" + opt.Type + ">"
			}

			desc := opt.Description
			if opt.Default != nil && *opt.Default != "" {
				desc += color.HiBlackString(" (default: " + *opt.Default + ")")
			}
			if len(opt.Values) > 0 {
				desc += color.HiBlackString(" [" + strings.Join(opt.Values, "|") + "]")
			}
			if opt.Required {
				desc += color.RedString(" (required)")
			}

			fmt.Printf("    %-22s%s\n", flagLabel+typeStr, desc)
		}
		fmt.Println()
	}

	if len(detail.Examples) > 0 {
		fmt.Println(color.HiWhiteString("  EXAMPLES"))
		maxCmdWidth := 34
		for _, ex := range detail.Examples {
			if w := len(ex.Cmd); w > maxCmdWidth {
				maxCmdWidth = w
			}
		}
		cmdFmt := fmt.Sprintf("    %%-%ds  %%s\n", maxCmdWidth)
		for _, ex := range detail.Examples {
			fmt.Printf(cmdFmt, ex.Cmd, color.HiBlackString(ex.Description))
		}
		fmt.Println()
	}

	if len(detail.RelatedCommands) > 0 {
		fmt.Println(color.HiWhiteString("  RELATED"))
		fmt.Println("    " + strings.Join(detail.RelatedCommands, ", "))
		fmt.Println()
	}
}

func buildFlagHints(cmd *cobra.Command) string {
	var hints []string
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Name == "help" {
			return
		}
		if f.Shorthand != "" {
			hints = append(hints, "[-"+f.Shorthand+"]")
		} else {
			hints = append(hints, "[--"+f.Name+"]")
		}
	})
	return strings.Join(hints, " ")
}
