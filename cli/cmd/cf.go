package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:     "cf",
	GroupID: GroupTools,
	Aliases: []string{"config"},
	Short:   "Manage CLI configuration",
	Long: `View and modify CLI configuration settings.

Subcommands:
  list (ls)  Show all configuration values
  get        Get a specific configuration value
  set        Set a configuration value

Valid configuration keys:
  api_key       - Your API key for authentication
  endpoint      - The PigCloud API endpoint URL
  cwd           - Current working directory in cloud storage
  default_json  - Always output JSON (true/false)
  default_quiet - Suppress non-essential output (true/false)
  no_color      - Disable colored output (true/false)
  language      - Server message language: en or de (default en)`,
	Run: func(cmd *cobra.Command, args []string) {
		runConfigList()
	},
}

var configListCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "Show all configuration values",
	Run: func(cmd *cobra.Command, args []string) {
		runConfigList()
	},
}

var configGetCmd = &cobra.Command{
	Use:   "get <key>",
	Short: "Get a configuration value",
	Long: `Get a specific configuration value.

Valid keys: api_key, endpoint, cwd, default_json, default_quiet, no_color, language`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runConfigGet(args[0])
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Long: `Set a configuration value.

Valid keys: api_key, endpoint, cwd, default_json, default_quiet, no_color, language`,
	Example: `pc cf set cwd /Documents          # Set a configuration value
pc cf set endpoint https://custom.example.com/api`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		runConfigSet(args[0], args[1])
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
	configCmd.AddCommand(configListCmd)
	configCmd.AddCommand(configGetCmd)
	configCmd.AddCommand(configSetCmd)
}

func maskAPIKey(key string) string {
	if key == "" {
		return "(not set)"
	}
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func runConfigList() {
	cfg := config.Get()
	configPath := config.GetConfigPath()

	if GetJSONOutput() {
		fmt.Printf(`{"api_key":"%s","endpoint":"%s","cwd":"%s","default_json":%t,"default_quiet":%t,"no_color":%t,"language":"%s","config_path":"%s"}`,
			maskAPIKey(cfg.APIKey), cfg.Endpoint, cfg.Cwd, cfg.DefaultJSON, cfg.DefaultQuiet, cfg.NoColor, config.GetLanguage(), configPath)
		fmt.Println()
		return
	}

	table := output.Table([]string{"Key", "Value"})
	table.Append([]string{"api_key", maskAPIKey(cfg.APIKey)})
	table.Append([]string{"endpoint", cfg.Endpoint})
	table.Append([]string{"cwd", cfg.Cwd})
	table.Append([]string{"default_json", fmt.Sprintf("%t", cfg.DefaultJSON)})
	table.Append([]string{"default_quiet", fmt.Sprintf("%t", cfg.DefaultQuiet)})
	table.Append([]string{"no_color", fmt.Sprintf("%t", cfg.NoColor)})
	table.Append([]string{"language", config.GetLanguage()})
	table.Render()

	fmt.Printf("\nConfig file: %s\n", configPath)
}

func runConfigGet(key string) {
	cfg := config.Get()
	var value string

	switch strings.ToLower(key) {
	case "api_key":
		value = maskAPIKey(cfg.APIKey)
	case "endpoint":
		value = cfg.Endpoint
	case "cwd":
		value = cfg.Cwd
	case "default_json":
		value = fmt.Sprintf("%t", cfg.DefaultJSON)
	case "default_quiet":
		value = fmt.Sprintf("%t", cfg.DefaultQuiet)
	case "no_color":
		value = fmt.Sprintf("%t", cfg.NoColor)
	default:
		output.PrintError(fmt.Sprintf("Unknown config key: %s\nValid keys: api_key, endpoint, cwd, default_json, default_quiet, no_color", key))
		ExitWithError()
		return
	}

	fmt.Println(value)
}

func runConfigSet(key, value string) {
	key = strings.ToLower(key)

	switch key {
	case "api_key":
		output.PrintWarning("Passing API keys as command arguments exposes them in process listings. Use 'pc li' to set your key securely.")
		if err := config.SetAPIKey(value); err != nil {
			output.PrintError("Failed to save API key: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess("API key updated")

	case "endpoint":
		if _, err := url.ParseRequestURI(value); err != nil {
			output.PrintError("Invalid URL format: " + value)
			ExitWithError()
			return
		}
		if err := config.SetEndpoint(value); err != nil {
			output.PrintError("Failed to save endpoint: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess("Endpoint updated to " + value)

	case "cwd":
		if !config.IsLoggedIn() {
			output.PrintError("Not logged in. Cannot validate path.")
			ExitWithError()
			return
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()

		client := api.NewClient()
		resp, err := client.Execute(ctx, "cd", map[string]string{
			"source": value,
		})

		if err != nil {
			output.PrintError("Request failed: " + err.Error())
			ExitWithError()
			return
		}

		if !resp.Success {
			output.PrintError("Path does not exist: " + value)
			ExitWithError()
			return
		}

		if err := config.SetCwd(value); err != nil {
			output.PrintError("Failed to save cwd: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess("Working directory set to " + value)

	case "default_json":
		boolVal := parseBoolConfig(key, value)
		cfg := config.Get()
		cfg.DefaultJSON = boolVal
		if err := config.Save(); err != nil {
			output.PrintError("Failed to save config: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess(fmt.Sprintf("default_json set to %t", boolVal))

	case "default_quiet":
		boolVal := parseBoolConfig(key, value)
		cfg := config.Get()
		cfg.DefaultQuiet = boolVal
		if err := config.Save(); err != nil {
			output.PrintError("Failed to save config: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess(fmt.Sprintf("default_quiet set to %t", boolVal))

	case "no_color":
		boolVal := parseBoolConfig(key, value)
		cfg := config.Get()
		cfg.NoColor = boolVal
		if err := config.Save(); err != nil {
			output.PrintError("Failed to save config: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess(fmt.Sprintf("no_color set to %t", boolVal))

	case "language":
		lang := strings.ToLower(value)
		if lang != "en" && lang != "de" {
			output.PrintError(fmt.Sprintf("Invalid language: %s (use en or de)", value))
			ExitWithError()
			return
		}
		cfg := config.Get()
		cfg.Language = lang
		if err := config.Save(); err != nil {
			output.PrintError("Failed to save config: " + err.Error())
			ExitWithError()
			return
		}
		output.PrintSuccess("language set to " + lang)

	default:
		output.PrintError(fmt.Sprintf("Unknown config key: %s\nValid keys: api_key, endpoint, cwd, default_json, default_quiet, no_color, language", key))
		ExitWithError()
	}
}

func parseBoolConfig(key, value string) bool {
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		output.PrintError(fmt.Sprintf("Invalid boolean value for %s: %s (use true/false)", key, value))
		ExitWithError()
		return false
	}
}
