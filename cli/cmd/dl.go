package cmd

import (
	"archive/zip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/output"
	"pigcloud/internal/progress"

	"github.com/spf13/cobra"
)

var (
	dlExtract      bool
	dlZip          bool
	dlSkipExisting bool
	dlOverwrite    bool
)

var dlCmd = &cobra.Command{
	Use:     "dl <remote-path> [local-path]",
	GroupID: GroupFiles,
	Aliases: []string{"download"},
	Short:   "Download a file or folder from cloud storage",
	Example: `pc dl /Documents/report.pdf ./       # Download a file
  pc dl /Documents ./docs -x              # Download folder contents individually
  pc dl /Documents ./backup.zip --zip     # Download folder as ZIP archive
  pc dl /backup.sql.gz - | gunzip         # Stream decrypted file to stdout`,
	Long: `Download a file or folder from your cloud storage.

If local-path is not specified, downloads to the current directory.
Use - as local-path to stream the decrypted file to stdout for piping.

Use --extract (-x) to download a folder's contents as individual files,
preserving the directory structure locally instead of creating a ZIP.

Use --zip (-z) to download a folder's contents into a local ZIP archive.
Files are decrypted before being added to the archive.`,
	Args:              cobra.RangeArgs(1, 2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		remotePath := args[0]
		localPath := "."
		if len(args) > 1 {
			localPath = args[1]
		}
		runDownload(remotePath, localPath)
	},
}

func init() {
	rootCmd.AddCommand(dlCmd)
	dlCmd.Flags().BoolVarP(&dlExtract, "extract", "x", false, "Download files individually preserving folder structure")
	dlCmd.Flags().BoolVarP(&dlZip, "zip", "z", false, "Download folder contents as a local ZIP archive")
	dlCmd.Flags().BoolVar(&dlSkipExisting, "skip-existing", false, "skip files that already exist locally")
	dlCmd.Flags().BoolVar(&dlOverwrite, "overwrite", false, "overwrite existing local files")
}

func runDownload(remotePath, localPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(remotePath)
	destArg := localPath

	if localPath == "-" {
		if dlExtract || dlZip {
			output.PrintError("Cannot combine - (stdout) with --extract or --zip")
			ExitWithError()
		}
		runStdoutDownload(ctx, resolvedPath)
		return
	}

	if dlExtract {
		runExtractDownload(ctx, resolvedPath, localPath)
		return
	}

	if dlZip {
		runZipDownload(ctx, resolvedPath, localPath)
		return
	}

	fileName := filepath.Base(resolvedPath)
	if fileName == "" || fileName == "/" {
		fileName = "download"
	}

	stat, err := os.Stat(localPath)
	if err == nil && stat.IsDir() {
		localPath = filepath.Join(localPath, fileName)
	} else if localPath == "." {
		localPath = fileName
	}

	if _, err := os.Stat(localPath); err == nil {
		if dlSkipExisting {
			if !GetQuietOutput() {
				output.PrintInfo("Skipping (exists): " + localPath)
			}
			return
		}
		if !dlOverwrite {
			output.PrintError("File already exists: " + localPath + " (use --overwrite or --skip-existing)")
			ExitWithError()
		}
	}

	dlOpts := map[string]string{}
	cmdutil.AddPathTokensFor(dlOpts, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	bar := progress.NewBar(-1, "Downloading "+fileName)

	client := api.NewClient()
	dlResult, err := client.Download(ctx, resolvedPath, localPath, func(received, total int64) {
		if total > 0 {
			bar.ChangeMax64(total)
		}
		bar.Set64(received)
	}, dlOpts)

	bar.Finish()

	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Code == "is_directory" {
			if !GetQuietOutput() {
				output.PrintInfo(resolvedPath + " is a folder; downloading its contents (use -z for a ZIP archive)")
			}
			runExtractDownload(ctx, resolvedPath, destArg)
			return
		}
		output.PrintError("Download failed: " + err.Error())
		os.Remove(localPath)
		ExitWithError()
	}

	decryptDownloadedFile(localPath, dlResult)

	finalStat, _ := os.Stat(localPath)
	var size int64
	if finalStat != nil {
		size = finalStat.Size()
	}

	if !GetQuietOutput() {
		output.PrintSuccess("Downloaded to " + localPath)
		output.PrintInfo("Size: " + output.FormatSize(&size))
	}
}

func runStdoutDownload(ctx context.Context, resolvedPath string) {
	tmpFile, err := os.CreateTemp("", "pigcloud-dl-*")
	if err != nil {
		output.PrintError("Failed to create temp file: " + err.Error())
		ExitWithError()
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	stdoutOpts := map[string]string{}
	cmdutil.AddPathTokensFor(stdoutOpts, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	bar := progress.NewBar(-1, "Downloading "+filepath.Base(resolvedPath))
	client := api.NewClient()
	dlResult, err := client.Download(ctx, resolvedPath, tmpPath, func(received, total int64) {
		if total > 0 {
			bar.ChangeMax64(total)
		}
		bar.Set64(received)
	}, stdoutOpts)
	bar.Finish()

	if err != nil {
		output.PrintError("Download failed: " + err.Error())
		ExitWithError()
	}

	decryptDownloadedFile(tmpPath, dlResult)

	f, err := os.Open(tmpPath)
	if err != nil {
		output.PrintError("Failed to open downloaded file: " + err.Error())
		ExitWithError()
	}
	defer f.Close()
	if _, err := io.Copy(os.Stdout, f); err != nil {
		output.PrintError("Failed to write to stdout: " + err.Error())
		ExitWithError()
	}
}

func runExtractDownload(ctx context.Context, resolvedPath, localDir string) {
	options := map[string]string{
		"source": resolvedPath,
		"depth":  "100",
	}
	cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)
	_, treeListing := cmdutil.ExecuteCommand[api.TreePayload](ctx, "tr", options, ExitWithError)
	decryptTreeEntries(treeListing.Entries)

	type fileEntry struct {
		remotePath string
		localPath  string
	}
	var files []fileEntry
	cmdutil.WalkTreeFiles(treeListing.Entries, resolvedPath, func(_ api.TreeEntry, remotePath, relPath string) {
		if !localRelPathSafe(relPath) {
			output.PrintWarning("Skipping " + fsutil.StripControl(relPath) + ": not a valid local file name on this system")
			return
		}
		files = append(files, fileEntry{
			remotePath: remotePath,
			localPath:  filepath.Join(localDir, filepath.FromSlash(relPath)),
		})
	})

	if len(files) == 0 {
		output.PrintInfo("No files to download")
		return
	}

	fmt.Printf("Downloading %d files...\n", len(files))

	client := api.NewClient()
	succeeded := 0
	failed := 0
	skipped := 0
	for i, f := range files {
		if _, err := os.Stat(f.localPath); err == nil {
			if dlSkipExisting {
				skipped++
				continue
			}
			if !dlOverwrite {
				output.PrintError("File already exists: " + f.localPath + " (use --overwrite or --skip-existing)")
				failed++
				continue
			}
		}

		if err := os.MkdirAll(filepath.Dir(f.localPath), 0755); err != nil {
			output.PrintError("Failed to create directory: " + err.Error())
			failed++
			continue
		}

		relDisplay := filepath.ToSlash(f.localPath)
		if localDir != "" && localDir != "." {
			if len(f.localPath) > len(localDir)+1 {
				relDisplay = filepath.ToSlash(f.localPath[len(localDir)+1:])
			}
		}

		perFileOpts := map[string]string{}
		cmdutil.AddPathTokensFor(perFileOpts, f.remotePath, e2ee.SelfAndAncestors, ExitWithError)

		label := fmt.Sprintf("[%d/%d] %s", i+1, len(files), relDisplay)
		bar := progress.NewBar(-1, label)
		dlResult, err := client.Download(ctx, f.remotePath, f.localPath, func(received, total int64) {
			if total > 0 {
				bar.ChangeMax64(total)
			}
			bar.Set64(received)
		}, perFileOpts)
		bar.Finish()

		if err != nil {
			output.PrintError("Failed: " + relDisplay + " — " + err.Error())
			os.Remove(f.localPath)
			failed++
		} else {
			decryptDownloadedFile(f.localPath, dlResult)
			succeeded++
		}
	}

	if !GetQuietOutput() {
		msg := fmt.Sprintf("Downloaded %d files to %s", succeeded, localDir)
		if skipped > 0 {
			msg += fmt.Sprintf(", %d skipped", skipped)
		}
		if failed > 0 {
			output.PrintWarning(msg + fmt.Sprintf(", %d failed", failed))
		} else {
			output.PrintSuccess(msg)
		}
	}
}

func runZipDownload(ctx context.Context, resolvedPath, localPath string) {
	zipTreeOpts := map[string]string{
		"source": resolvedPath,
		"depth":  "100",
	}
	cmdutil.AddPathTokensFor(zipTreeOpts, resolvedPath, e2ee.SelfAndParent, ExitWithError)
	_, treeListing := cmdutil.ExecuteCommand[api.TreePayload](ctx, "tr", zipTreeOpts, ExitWithError)
	decryptTreeEntries(treeListing.Entries)

	type fileEntry struct {
		remotePath string
		relPath    string
	}
	var files []fileEntry
	cmdutil.WalkTreeFiles(treeListing.Entries, resolvedPath, func(_ api.TreeEntry, remotePath, relPath string) {
		files = append(files, fileEntry{remotePath: remotePath, relPath: relPath})
	})

	if len(files) == 0 {
		output.PrintInfo("No files to download")
		return
	}

	zipPath := localPath
	if !isZipExtension(zipPath) {
		folderName := filepath.Base(resolvedPath)
		if folderName == "" || folderName == "/" {
			folderName = "download"
		}
		stat, err := os.Stat(zipPath)
		if err == nil && stat.IsDir() {
			zipPath = filepath.Join(zipPath, folderName+".zip")
		} else if zipPath == "." {
			zipPath = folderName + ".zip"
		}
	}

	if _, err := os.Stat(zipPath); err == nil {
		if dlSkipExisting {
			output.PrintInfo("Skipping (exists): " + zipPath)
			return
		}
		if !dlOverwrite {
			output.PrintError("File already exists: " + zipPath + " (use --overwrite or --skip-existing)")
			ExitWithError()
		}
	}

	fmt.Printf("Downloading %d files into %s...\n", len(files), zipPath)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		output.PrintError("Failed to create zip file: " + err.Error())
		ExitWithError()
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	client := api.NewClient()
	succeeded := 0
	failed := 0

	for i, f := range files {
		tmpFile, err := os.CreateTemp("", "pigcloud-zip-*")
		if err != nil {
			output.PrintError("Failed to create temp file: " + err.Error())
			failed++
			continue
		}
		tmpPath := tmpFile.Name()
		tmpFile.Close()

		zipFileOpts := map[string]string{}
		cmdutil.AddPathTokensFor(zipFileOpts, f.remotePath, e2ee.SelfAndAncestors, ExitWithError)

		label := fmt.Sprintf("[%d/%d] %s", i+1, len(files), f.relPath)
		bar := progress.NewBar(-1, label)

		dlResult, err := client.Download(ctx, f.remotePath, tmpPath, func(received, total int64) {
			if total > 0 {
				bar.ChangeMax64(total)
			}
			bar.Set64(received)
		}, zipFileOpts)
		bar.Finish()

		if err != nil {
			output.PrintError("Failed: " + f.relPath + " — " + err.Error())
			os.Remove(tmpPath)
			failed++
			continue
		}

		decryptDownloadedFile(tmpPath, dlResult)

		data, err := os.ReadFile(tmpPath)
		os.Remove(tmpPath)
		if err != nil {
			output.PrintError("Failed to read temp file: " + err.Error())
			failed++
			continue
		}

		w, err := zipWriter.Create(f.relPath)
		if err != nil {
			output.PrintError("Failed to add to zip: " + err.Error())
			failed++
			continue
		}
		if _, err := w.Write(data); err != nil {
			output.PrintError("Failed to write to zip: " + err.Error())
			failed++
			continue
		}
		succeeded++
	}

	zipWriter.Close()
	zipFile.Close()

	if !GetQuietOutput() {
		stat, _ := os.Stat(zipPath)
		var size int64
		if stat != nil {
			size = stat.Size()
		}
		msg := fmt.Sprintf("Created %s (%d files, %s)", zipPath, succeeded, output.FormatSize(&size))
		if failed > 0 {
			output.PrintWarning(msg + fmt.Sprintf(", %d failed", failed))
		} else {
			output.PrintSuccess(msg)
		}
	}
}

func localRelPathSafe(relPath string) bool {
	for _, seg := range strings.Split(relPath, "/") {
		if !fsutil.IsSafeName(seg) {
			return false
		}
	}
	return true
}

func isZipExtension(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".zip" || ext == ".ZIP"
}

func decryptDownloadedFile(filePath string, dlResult *api.DownloadResult) {
	if gateErr := e2ee.RequireEncryptedDownload(dlResult); gateErr != nil {
		output.PrintError("Download refused: " + gateErr.Error())
		os.Remove(filePath)
		ExitWithError()
	}
	f, openErr := os.Open(filePath)
	if openErr != nil {
		output.PrintError("Failed to open downloaded file: " + openErr.Error())
		os.Remove(filePath)
		ExitWithError()
	}
	verifyErr := e2ee.VerifyDownloadIntegrity(f, dlResult)
	f.Close()
	if verifyErr != nil {
		output.PrintError("Signature verification failed: " + verifyErr.Error())
		os.Remove(filePath)
		ExitWithError()
	}

	_, privKey := cmdutil.GetKeyPair(ExitWithError)

	sealedKeyBytes, err := base64.StdEncoding.DecodeString(dlResult.SealedKey)
	if err != nil {
		output.PrintError("Invalid sealed key: " + err.Error())
		os.Remove(filePath)
		ExitWithError()
	}
	dataKey, err := crypto.UnsealDataKey(sealedKeyBytes, privKey)
	if err != nil {
		output.PrintError("Failed to unseal data key: " + err.Error())
		os.Remove(filePath)
		ExitWithError()
	}

	metaJSON, err := base64.StdEncoding.DecodeString(dlResult.EncryptionMeta)
	if err != nil {
		output.PrintError("Invalid encryption metadata: " + err.Error())
		os.Remove(filePath)
		ExitWithError()
	}
	var meta crypto.EncryptionMetadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		output.PrintError("Failed to parse encryption metadata: " + err.Error())
		os.Remove(filePath)
		ExitWithError()
	}

	tempFile, err := os.CreateTemp("", "pigcloud-decrypt-*")
	if err != nil {
		output.PrintError("Failed to create temp file: " + err.Error())
		os.Remove(filePath)
		ExitWithError()
	}
	tempPath := tempFile.Name()
	tempFile.Close()

	if err := crypto.DecryptFile(filePath, tempPath, dataKey, &meta); err != nil {
		output.PrintError("Decryption failed: " + err.Error())
		os.Remove(tempPath)
		os.Remove(filePath)
		ExitWithError()
	}

	os.Remove(filePath)
	if err := os.Rename(tempPath, filePath); err != nil {
		src, _ := os.ReadFile(tempPath)
		if src != nil {
			os.WriteFile(filePath, src, 0600)
		}
		os.Remove(tempPath)
	}
}
