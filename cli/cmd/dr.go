package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/config"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:     "dr",
	GroupID: GroupTools,
	Aliases: []string{"doctor"},
	Short:   "Diagnose the CLI setup",
	Long: `Check the local CLI setup: credentials, endpoint reachability, encryption
keys, the key agent, mount backends, and the mount daemon. Exits non-zero
when a check fails.`,
	Example: `pc dr
pc dr --json`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runDoctor()
	},
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

func runDoctor() {
	var checks []doctorCheck
	add := func(name, status, detail string) {
		checks = append(checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}

	if config.IsLoggedIn() {
		add("credentials", "ok", "logged in ("+config.GetConfigPath()+")")
		if config.APIKeyInKeychain() {
			add("api key storage", "ok", "OS keychain")
		} else {
			add("api key storage", "warn", "plaintext in config.json (keychain unavailable)")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resp, err := api.NewClient().Validate(ctx)
		cancel()
		switch {
		case err != nil:
			add("endpoint", "fail", config.Get().Endpoint+" unreachable: "+err.Error())
		case !resp.Success:
			add("endpoint", "fail", "server rejected the API key: "+resp.Message)
		default:
			add("endpoint", "ok", config.Get().Endpoint)
		}
	} else {
		add("credentials", "fail", "not logged in (run 'pc li')")
	}

	if config.HasEncryptionKeys() {
		add("e2ee keys", "ok", "hybrid X25519+ML-KEM-768 keypair cached")
	} else if config.IsLoggedIn() {
		add("e2ee keys", "fail", "missing (re-run 'pc li' or finish E2EE setup in the web app)")
	} else {
		add("e2ee keys", "info", "unavailable before login")
	}

	if config.HasSigningKeys() {
		add("signing keys", "ok", "Ed25519 + ML-DSA-44 cached")
	} else if config.HasEncryptionKeys() {
		add("signing keys", "warn", "missing; uploads will be rejected (open the web app once)")
	} else {
		add("signing keys", "info", "unavailable before E2EE setup")
	}

	if agent.IsRunning() {
		add("key agent", "ok", "running (keys unlocked)")
	} else {
		add("key agent", "info", "not running; keys locked (run 'pc uk')")
	}

	if n := e2ee.SigningPinCount(); n > 0 {
		add("download pin", "ok", fmt.Sprintf("%d signing key(s) pinned", n))
	} else {
		add("download pin", "info", "no pinned signing keys yet (seeds on first verified download)")
	}

	if n := e2ee.PeerSigningPinCount(); n > 0 {
		add("peer pin", "ok", fmt.Sprintf("%d collaborator signing key(s) pinned", n))
	} else {
		add("peer pin", "info", "no pinned collaborator keys yet (pins on a friend's first upload into your tree)")
	}

	switch n, err := e2ee.PeerSealPinCount(); {
	case err != nil:
		add("seal pin", "error", "the pin store "+e2ee.PeerSealPinStorePath()+" cannot be read, so every new share and chat message is refused: "+err.Error()+". Confirm the keys with the contacts it covers before moving the file aside, which re-accepts whatever key the server offers next")
	case n > 0:
		add("seal pin", "ok", fmt.Sprintf("%d contact encryption key(s) pinned", n))
	default:
		add("seal pin", "info", "no pinned contact keys yet (pins on your first share or chat message to them)")
	}

	if runtime.GOOS == "windows" {
		if mount.IsWinFspInstalled() {
			add("winfsp", "ok", "installed (virtual mounts available)")
		} else {
			add("winfsp", "info", "not installed; only sync-mode mounts work")
		}
	} else {
		if mount.IsFuseAvailable() {
			add("fuse", "ok", "available (virtual mounts available)")
		} else {
			add("fuse", "info", "not available; only sync-mode mounts work")
		}
	}

	if mounts := mount.ListMounts(); len(mounts) > 0 {
		for _, info := range mounts {
			if _, err := mount.SendRequest(info, "ping"); err != nil {
				add("mount daemon", "warn", "mount entry present but the daemon is unreachable (stale entry removed)")
			} else if owner := currentOwnerID(); info.Owner != "" && owner != "" && info.Owner != owner {
				add("mount daemon", "warn", fmt.Sprintf("running for a different account (%s -> %s); run 'pc mn stop'", info.RemotePath, info.MountPoint))
			} else {
				add("mount daemon", "ok", fmt.Sprintf("running: %s -> %s (%s mode)", info.RemotePath, info.MountPoint, info.Mode))
			}
		}
	} else {
		add("mount daemon", "info", "not mounted")
	}

	failed := false
	for _, c := range checks {
		if c.Status == "fail" {
			failed = true
		}
	}

	if GetJSONOutput() {
		cmdutil.PrintJSONOrContinue(true, map[string]any{
			"version": versionInfo.Version,
			"checks":  checks,
			"healthy": !failed,
		})
	} else {
		fmt.Printf("PigCloud CLI v%s\n\n", versionInfo.Version)
		for _, c := range checks {
			var mark string
			switch c.Status {
			case "ok":
				mark = color.GreenString("✓")
			case "warn":
				mark = color.YellowString("!")
			case "fail":
				mark = color.RedString("✗")
			default:
				mark = color.HiBlackString("-")
			}
			fmt.Printf("  %s %-16s %s\n", mark, c.Name, c.Detail)
		}
	}

	if failed {
		os.Exit(1)
	}
}
