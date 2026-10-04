package cmd

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var loginAPIKeyFlag string
var loginDeviceFlag bool

var loginCmd = &cobra.Command{
	Use:     "li",
	GroupID: GroupAuth,
	Aliases: []string{"login"},
	Short:   "Sign in from your browser",
	Example: "pc login                          # Approve this device in your browser",
	Long: `Sign in to PigCloud.

By default 'pc login' opens your browser and asks you to approve this device,
so there is no API key to copy. Approve it while signed in to the web app and
the CLI finishes on its own.

For CI or headless machines, pass an API key instead:
  pc login --api-key <key>        # or pipe it:  echo "<key>" | pc login
Generate the key in the web app under Settings > API access.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		apiKey := loginAPIKeyFlag
		if loginDeviceFlag && (apiKey != "" || len(args) > 0) {
			output.PrintError("--device cannot be combined with an API key")
			ExitWithError()
			return
		}
		if len(args) > 0 {
			output.PrintWarning("Passing API keys as arguments exposes them in process listings. Prefer 'pc login' or --api-key from a secure source.")
			apiKey = args[0]
		}
		runLogin(apiKey)
	},
}

func init() {
	loginCmd.Flags().StringVar(&loginAPIKeyFlag, "api-key", "", "Authenticate with an API key instead of the browser flow (CI/headless)")
	loginCmd.Flags().BoolVar(&loginDeviceFlag, "device", false, "Use browser device approval with piped stdin; --json lets a native host open the verification URL")
	rootCmd.AddCommand(loginCmd)
}

func runLogin(apiKey string) {
	if config.IsLoggedIn() {
		if loginDeviceFlag {
			output.PrintError("Already signed in. Sign out of the CLI before enrolling another account.")
			ExitWithError()
			return
		}
		output.PrintWarning("You are already logged in. Use 'pigcloud logout' first to switch accounts.")
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Continue anyway? [y/N]: ")
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			return
		}
	}

	ctx, cancel := cmdutil.InterruptContext()
	defer cancel()

	if apiKey == "" {
		if loginDeviceFlag || term.IsTerminal(int(syscall.Stdin)) {
			runDeviceLogin(ctx)
			return
		}
		reader := bufio.NewReader(os.Stdin)
		key, _ := reader.ReadString('\n')
		apiKey = strings.TrimSpace(key)
		if apiKey == "" {
			output.PrintError("No API key on stdin. Run 'pc login' interactively for the browser flow, or pass --api-key.")
			os.Exit(1)
		}
	}

	finishLogin(ctx, apiKey, "", nil)
}

func runDeviceLogin(ctx context.Context) {
	ephPub, ephPriv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		output.PrintError("Could not generate a device key: " + err.Error())
		os.Exit(1)
	}
	ephPubBytes := append(append([]byte{}, ephPub.X25519[:]...), ephPub.Kyber...)
	commitment := sha256.Sum256(ephPubBytes)

	client := api.NewClient()
	authResp, err := client.DeviceAuthorize(ctx, deviceLabel(), base64.StdEncoding.EncodeToString(ephPubBytes), false)
	if err != nil {
		output.PrintError("Could not start device login: " + err.Error())
		os.Exit(1)
	}
	if !authResp.Success {
		output.PrintError("Could not start device login: " + deviceErrorMessage(authResp.Error))
		os.Exit(1)
	}

	commitB64 := base64.RawURLEncoding.EncodeToString(commitment[:])
	verificationURL := withCommitmentFragment(authResp.VerificationURIComplete, commitB64)
	machine := loginDeviceFlag && jsonOutput
	stdout := os.Stdout
	if machine {
		if err := writeDeviceAuthorization(stdout, authResp.UserCode, verificationURL); err != nil {
			ExitWithError()
			return
		}
		os.Stdout = os.Stderr
		defer func() { os.Stdout = stdout }()
	} else {
		printDeviceInstructions(authResp)
		_ = openBrowser(verificationURL)
	}

	apiKey, sealedKey, err := pollDeviceToken(ctx, client, authResp.DeviceCode, authResp.Interval, authResp.ExpiresIn)
	if err != nil {
		output.PrintError(err.Error())
		os.Exit(1)
	}
	output.PrintSuccess("Device approved.")
	finishLogin(ctx, apiKey, sealedKey, ephPriv)
	if machine {
		if err := json.NewEncoder(stdout).Encode(map[string]string{"event": "login_complete"}); err != nil {
			ExitWithError()
		}
	}
}

func withCommitmentFragment(url, commitB64 string) string {
	if url == "" || commitB64 == "" {
		return url
	}
	if strings.Contains(url, "#") {
		return url + "&k=" + commitB64
	}
	return url + "#k=" + commitB64
}

func pollDeviceToken(ctx context.Context, client *api.Client, deviceCode string, interval, expiresIn int) (string, string, error) {
	if interval < 1 {
		interval = 5
	}
	if expiresIn < 1 {
		expiresIn = 900
	}
	wait := time.Duration(interval) * time.Second
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for {
		select {
		case <-ctx.Done():
			return "", "", fmt.Errorf("login cancelled")
		case <-time.After(wait):
		}
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf("the request expired before it was approved; run 'pc login' again")
		}
		resp, err := client.DeviceToken(ctx, deviceCode)
		if err != nil {
			continue
		}
		if resp.Success {
			return resp.APIKey, resp.SealedKey, nil
		}
		switch resp.Error {
		case "authorization_pending":
		case "slow_down":
			wait += 5 * time.Second
		case "access_denied":
			return "", "", fmt.Errorf("the request was declined in the browser")
		case "expired_token":
			return "", "", fmt.Errorf("the request expired before it was approved; run 'pc login' again")
		default:
			return "", "", fmt.Errorf("device login failed: %s", deviceErrorMessage(resp.Error))
		}
	}
}

func printDeviceInstructions(r *api.DeviceAuthorizeResult) {
	fmt.Println()
	fmt.Println(color.HiWhiteString("Approve this device to sign in:"))
	fmt.Println()
	fmt.Println("  1. Open  " + color.CyanString(r.VerificationURI))
	fmt.Println("  2. Enter " + color.HiGreenString(r.UserCode))
	fmt.Println()
	fmt.Println(color.HiBlackString("Opening your browser... waiting for approval. Press Ctrl+C to cancel."))
}

func deviceLabel() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "PigCloud CLI"
	}
	return host
}

func deviceErrorMessage(code string) string {
	switch code {
	case "rate_limited":
		return "too many attempts; wait a minute and try again"
	case "invalid_request":
		return "the server rejected the request"
	case "server_error":
		return "the server had a problem; try again shortly"
	case "":
		return "unexpected empty response"
	default:
		return code
	}
}

func finishLogin(ctx context.Context, apiKey, sealedB64 string, ephPriv *crypto.PrivateKeySet) {
	fmt.Println("Validating API key...")
	client := api.NewClientWithKey(apiKey)
	resp, err := client.Validate(ctx)
	if err != nil {
		output.PrintError("Failed to validate API key: " + err.Error())
		os.Exit(1)
	}

	if !resp.Success {
		output.PrintError("Invalid API key: " + resp.Message)
		os.Exit(1)
	}

	if err := config.SetAPIKey(apiKey); err != nil {
		output.PrintError("Failed to save API key: " + err.Error())
		os.Exit(1)
	}

	output.PrintSuccess("Login successful!")

	if sealedB64 != "" && ephPriv != nil {
		importErr := e2ee.ImportDeviceTransferredKeys(sealedB64, ephPriv)
		if importErr == nil {
			output.PrintSuccess("Encryption keys transferred. No password needed.")
			output.PrintInfo("Config saved to: " + config.GetConfigPath())
			printPostLoginNextSteps()
			return
		}
		output.PrintWarning("Key transfer failed: " + importErr.Error() + ". Setting up encryption the usual way.")
	}

	fmt.Println("Setting up encryption...")
	setupE2EEKeys(ctx, client)

	if config.HasEncryptionKeys() && term.IsTerminal(int(syscall.Stdin)) {
		pub, priv := cmdutil.GetKeyPair(func() {})
		if pub != nil && priv != nil {
			DeriveAndStartAgent(pub, priv)
			output.PrintSuccess("Keys unlocked (expires in 1 hour)")
		}
	}

	output.PrintInfo("Config saved to: " + config.GetConfigPath())
	printPostLoginNextSteps()
}

func printPostLoginNextSteps() {
	if output.IsQuiet() {
		return
	}
	cmdStyle := color.CyanString
	fmt.Println()
	fmt.Println(color.HiWhiteString("Next steps:"))
	fmt.Println("  " + cmdStyle("pc hi") + "                  Take the quickstart tour")
	fmt.Println("  " + cmdStyle("pc ls") + "                  List your files")
	fmt.Println("  " + cmdStyle("pc ul <file> /") + "         Upload a file")
	fmt.Println("  " + cmdStyle("pc hl") + "                  Browse all commands")
	fmt.Println()
}

func setupE2EEKeys(ctx context.Context, client *api.Client) {
	keysResp, err := client.FetchEncryptionKeys(ctx)
	if err == nil && keysResp.Success {
		var payload api.E2EEKeysPayload
		if err := json.Unmarshal(keysResp.Raw, &payload); err != nil {
			output.PrintWarning("Could not parse encryption keys: " + err.Error())
			return
		}
		if payload.PublicKeyKyber == "" || payload.EncryptedPrivateKeyKyber == "" {
			output.PrintWarning("Server returned legacy (non-hybrid) keys. Re-run E2EE setup from the web app.")
			return
		}

		if err := config.SetEncryptionKeys(
			payload.PublicKey,
			payload.EncryptedPrivateKey,
			payload.PrivateKeyNonce,
			payload.PublicKeyKyber,
			payload.EncryptedPrivateKeyKyber,
			payload.PrivateKeyKyberNonce,
			payload.KDFSalt,
			payload.KDFOpsLimit,
			payload.KDFMemLimit,
		); err != nil {
			output.PrintWarning("Could not save encryption keys: " + err.Error())
			return
		}

		if payload.SigningPublicKeyEd25519 != "" {
			if err := config.SetSigningKeys(
				payload.SigningPublicKeyEd25519,
				payload.EncryptedSigningPrivateKeyEd25519,
				payload.SigningPrivateKeyEd25519Nonce,
				payload.SigningPublicKeyMldsa,
				payload.EncryptedSigningPrivateKeyMldsa,
				payload.SigningPrivateKeyMldsaNonce,
			); err != nil {
				output.PrintWarning("Could not save signing keys: " + err.Error())
			}
		}

		output.PrintSuccess("Encryption keys loaded.")
		return
	}

	if !term.IsTerminal(int(syscall.Stdin)) {
		output.PrintWarning("Non-interactive mode: skipping encryption key setup. Run 'pc li' interactively to set up encryption.")
		return
	}

	fmt.Print("Set your password: ")
	pw1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		output.PrintWarning("Could not read password: " + err.Error())
		return
	}

	fmt.Print("Confirm password: ")
	pw2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		output.PrintWarning("Could not read password: " + err.Error())
		return
	}

	if string(pw1) != string(pw2) {
		output.PrintError("Passwords do not match")
		os.Exit(1)
	}

	if len(pw1) < 8 {
		output.PrintError("Password must be at least 8 characters")
		os.Exit(1)
	}

	keys, err := e2ee.NewAccountKeys(pw1)
	if err != nil {
		output.PrintError("Failed to set up encryption keys: " + err.Error())
		os.Exit(1)
	}
	pub, enc, signPub, signEnc := keys.Public, keys.Wrapped, keys.SigningPublic, keys.SigningWrapped

	setupResp, err := client.SetupEncryptionKeys(ctx, keys.Params)
	if err != nil {
		output.PrintError("Failed to store encryption keys: " + err.Error())
		os.Exit(1)
	}
	if !setupResp.Success {
		output.PrintError("Failed to store encryption keys: " + setupResp.Message)
		os.Exit(1)
	}

	if err := config.SetEncryptionKeys(
		base64.StdEncoding.EncodeToString(pub.X25519[:]),
		base64.StdEncoding.EncodeToString(enc.X25519Ciphertext),
		base64.StdEncoding.EncodeToString(enc.X25519Nonce),
		base64.StdEncoding.EncodeToString(pub.Kyber),
		base64.StdEncoding.EncodeToString(enc.KyberCiphertext),
		base64.StdEncoding.EncodeToString(enc.KyberNonce),
		base64.StdEncoding.EncodeToString(enc.Salt),
		enc.OpsLimit,
		enc.MemLimit,
	); err != nil {
		output.PrintWarning("Could not save encryption keys locally: " + err.Error())
	}

	if err := config.SetSigningKeys(
		base64.StdEncoding.EncodeToString(signPub.Ed25519[:]),
		base64.StdEncoding.EncodeToString(signEnc.Ed25519Ciphertext),
		base64.StdEncoding.EncodeToString(signEnc.Ed25519Nonce),
		base64.StdEncoding.EncodeToString(signPub.Mldsa),
		base64.StdEncoding.EncodeToString(signEnc.MldsaCiphertext),
		base64.StdEncoding.EncodeToString(signEnc.MldsaNonce),
	); err != nil {
		output.PrintWarning("Could not save signing keys locally: " + err.Error())
	}

	output.PrintSuccess("Encryption keys generated and stored.")
	fmt.Println()
	output.PrintWarning("SAVE YOUR RECOVERY KEY — if you lose your password, this is the only way to recover:")
	fmt.Println()
	fmt.Println("  " + crypto.FormatRecoveryKey(keys.RecoveryKey))
	fmt.Println()
	output.PrintWarning("Write it down and store it in a safe place. It will NOT be shown again.")
}
