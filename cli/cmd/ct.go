package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var (
	ctHead int
	ctTail int
)

var ctCmd = &cobra.Command{
	Use:     "ct <path>",
	GroupID: GroupFiles,
	Aliases: []string{"cat"},
	Short:   "Display file content",
	Long: `Display the content of a text file from your cloud storage.

Only text files up to 1MB can be displayed. Binary files are not supported.

Flags:
  -n, --head N    Show only the first N lines
  -t, --tail N    Show only the last N lines`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runCt(args[0])
	},
}

func init() {
	rootCmd.AddCommand(ctCmd)
	ctCmd.Flags().IntVarP(&ctHead, "head", "n", 0, "show only the first N lines")
	ctCmd.Flags().IntVarP(&ctTail, "tail", "t", 0, "show only the last N lines")
}

func runCt(targetPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	options := map[string]string{"source": resolvedPath}

	if ctHead > 0 {
		options["head"] = strconv.Itoa(ctHead)
	}
	if ctTail > 0 {
		options["tail"] = strconv.Itoa(ctTail)
	}

	e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.CatPayload](ctx, "ct", options, ExitWithError)

	content := decryptCatContent(payload)

	if GetJSONOutput() {
		out := payload
		out.Content = content
		out.E2EE = false
		out.SealedKey = ""
		out.EncryptionMeta = ""
		cmdutil.PrintJSONOrContinue(true, out)
		return
	}

	fmt.Print(content)
	if len(content) > 0 && content[len(content)-1] != '\n' {
		fmt.Println()
	}
}

func decryptCatContent(payload api.CatPayload) string {
	dlResult := payload.AsDownloadResult()
	if gateErr := e2ee.RequireEncryptedDownload(dlResult); gateErr != nil {
		output.PrintError("Read refused: " + gateErr.Error())
		ExitWithError()
	}
	encryptedBytes, err := base64.StdEncoding.DecodeString(payload.Content)
	if err != nil {
		output.PrintError("Invalid encrypted content: " + err.Error())
		ExitWithError()
	}

	if err := e2ee.VerifyDownloadIntegrity(bytes.NewReader(encryptedBytes), dlResult); err != nil {
		output.PrintError("Signature verification failed: " + err.Error())
		ExitWithError()
	}

	_, privKey := e2ee.GetKeyPair(ExitWithError)

	sealedKeyBytes, err := base64.StdEncoding.DecodeString(payload.SealedKey)
	if err != nil {
		output.PrintError("Invalid sealed key: " + err.Error())
		ExitWithError()
	}
	dataKey, err := crypto.UnsealDataKey(sealedKeyBytes, privKey)
	if err != nil {
		output.PrintError("Failed to unseal data key: " + err.Error())
		ExitWithError()
	}

	metaJSON, err := base64.StdEncoding.DecodeString(payload.EncryptionMeta)
	if err != nil {
		output.PrintError("Invalid encryption metadata: " + err.Error())
		ExitWithError()
	}
	var meta crypto.EncryptionMetadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		output.PrintError("Failed to parse encryption metadata: " + err.Error())
		ExitWithError()
	}

	tempFile, err := os.CreateTemp("", "pigcloud-cat-*")
	if err != nil {
		output.PrintError("Failed to create temp file: " + err.Error())
		ExitWithError()
	}
	tempPath := tempFile.Name()
	if _, err := tempFile.Write(encryptedBytes); err != nil {
		tempFile.Close()
		os.Remove(tempPath)
		output.PrintError("Failed to write temp file: " + err.Error())
		ExitWithError()
	}
	tempFile.Close()
	defer os.Remove(tempPath)

	plaintext, err := crypto.DecryptToMemory(tempPath, dataKey, &meta)
	if err != nil {
		output.PrintError("Decryption failed: " + err.Error())
		ExitWithError()
	}

	content := string(plaintext)

	if ctHead > 0 || ctTail > 0 {
		lines := strings.Split(content, "\n")
		if ctTail > 0 && ctTail < len(lines) {
			lines = lines[len(lines)-ctTail:]
		} else if ctHead > 0 && ctHead < len(lines) {
			lines = lines[:ctHead]
		}
		content = strings.Join(lines, "\n")
	}

	return content
}
