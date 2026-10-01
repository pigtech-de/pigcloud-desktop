package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var tcContent string

var tcCmd = &cobra.Command{
	Use:     "tc <name|path> [dir]",
	GroupID: GroupFiles,
	Aliases: []string{"touch"},
	Short:   "Create a new text file",
	Long: `Create a new text file in your cloud storage.

The first argument is either a full path (/Documents/notes.txt) or a bare
name combined with an optional directory argument.

Content can be provided via --content flag or piped from stdin.
With neither, an empty file is created.
The file is encrypted client-side before upload (E2EE).

If no extension is given, .txt is appended automatically.
Only text file types are allowed.`,
	Example: `pc tc /Documents/notes.txt -c "Hello world"
  pc tc notes.txt /Documents --content "Hello world"
  echo "piped content" | pc tc log.txt /Logs
  pc tc readme.md --content "# Title"`,
	Args:              cobra.RangeArgs(1, 2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		name := args[0]
		targetDir := ""
		if len(args) > 1 {
			targetDir = args[1]
		}
		if strings.Contains(name, "/") {
			if targetDir != "" {
				output.PrintError("Give either a full path (tc /dir/file.txt) or a name plus directory (tc file.txt /dir), not both")
				ExitWithError()
			}
			resolved := cmdutil.ResolvePath(name)
			name = path.Base(resolved)
			targetDir = path.Dir(resolved)
		}
		runTouch(name, targetDir)
	},
}

func init() {
	tcCmd.Flags().StringVarP(&tcContent, "content", "c", "", "file content (reads from stdin if omitted)")
	rootCmd.AddCommand(tcCmd)
}

func runTouch(name, targetDir string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	content := tcContent
	if content == "" && !term.IsTerminal(int(syscall.Stdin)) {
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			output.PrintError("Failed to read stdin: " + err.Error())
			ExitWithError()
		}
		content = string(stdinData)
	}

	resolvedPath := cmdutil.ResolvePath(targetDir)

	pubKey := e2ee.GetPublicKey(ExitWithError)
	teeKeys := e2ee.FetchTeeEnclaveKeySet()
	if teeKeys == nil && !e2ee.TeeScannerDisabledByServer() {
		if refusal := e2ee.TeeEnclaveKeyRefusal(); refusal != nil {
			output.PrintError("Security scanner refused: " + refusal.Error())
		} else {
			output.PrintError("Security scanner is not reachable. Please try again shortly.")
		}
		ExitWithError()
	}
	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		output.PrintError("Failed to generate data key: " + err.Error())
		ExitWithError()
	}

	tmpIn, err := os.CreateTemp("", "pigcloud-tc-in-*")
	if err != nil {
		output.PrintError("Failed to create temp file: " + err.Error())
		ExitWithError()
	}
	tmpInPath := tmpIn.Name()
	tmpIn.Write([]byte(content))
	tmpIn.Close()
	defer os.Remove(tmpInPath)

	tmpOut, err := os.CreateTemp("", "pigcloud-tc-out-*")
	if err != nil {
		output.PrintError("Failed to create temp file: " + err.Error())
		ExitWithError()
	}
	tmpOutPath := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpOutPath)

	meta, err := crypto.EncryptFile(tmpInPath, tmpOutPath, dataKey)
	if err != nil {
		output.PrintError("Encryption failed: " + err.Error())
		ExitWithError()
	}

	encryptedBytes, err := os.ReadFile(tmpOutPath)
	if err != nil {
		output.PrintError("Failed to read encrypted file: " + err.Error())
		ExitWithError()
	}

	sealedKey, err := crypto.SealDataKey(dataKey, pubKey)
	if err != nil {
		output.PrintError("Failed to seal data key: " + err.Error())
		ExitWithError()
	}

	teeSealedB64 := ""
	if teeKeys != nil {
		teeSealed, err := crypto.SealDataKey(dataKey, teeKeys)
		if err != nil {
			output.PrintError("Failed to seal data key to enclave: " + err.Error())
			ExitWithError()
		}
		teeSealedB64 = base64.StdEncoding.EncodeToString(teeSealed)
	}

	metaJSON, err := meta.WireJSON()
	if err != nil {
		output.PrintError("Failed to encode metadata: " + err.Error())
		ExitWithError()
	}

	sigEd, sigMl, pkEd, pkMl := e2ee.SignEncryptedFile(tmpOutPath, ExitWithError)

	options := map[string]string{
		"source":             resolvedPath,
		"name":               name,
		"content":            base64.StdEncoding.EncodeToString(encryptedBytes),
		"sealed_key":         base64.StdEncoding.EncodeToString(sealedKey),
		"encryption_meta":    base64.StdEncoding.EncodeToString(metaJSON),
		"tee_sealed_key":     teeSealedB64,
		"signature_ed25519":  sigEd,
		"signature_mldsa":    sigMl,
		"signing_pk_ed25519": pkEd,
		"signing_pk_mldsa":   pkMl,
	}

	if nameKey := e2ee.GetNameKey(ExitWithError); nameKey != nil {
		if hmac, err := crypto.ComputePlaintextHmac(meta.PlaintextSHA256, nameKey); err == nil {
			options["plaintext_hmac"] = hmac
		}
	}

	parentPath := strings.TrimLeft(resolvedPath, "/")
	var fullNodePath string
	if parentPath == "" || parentPath == "/" {
		fullNodePath = name
	} else {
		fullNodePath = parentPath + "/" + name
	}
	e2ee.AddE2eeNameFields(options, name, fullNodePath, ExitWithError)

	e2ee.AddPathTokensForAll(options, []string{fullNodePath, parentPath}, e2ee.SelfAndParent, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.TouchPayload](ctx, "tc", options, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	output.PrintSuccess("Created " + output.PrintPath(payload.Path))
	contentSize := int64(len(content))
	fmt.Printf("  Size: %s\n", output.FormatSize(&contentSize))
}
