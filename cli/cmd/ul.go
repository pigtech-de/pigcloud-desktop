package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
	"pigcloud/internal/progress"

	"github.com/spf13/cobra"
)

var ulCmd = &cobra.Command{
	Use:     "ul <local-path> [remote-path]",
	GroupID: GroupFiles,
	Aliases: []string{"upload"},
	Short:   "Upload a file or directory to cloud storage",
	Example: `pc ul report.pdf /Documents/     # Upload a file
  pc ul ./my-folder /Backups/      # Upload a directory recursively
  echo "hello" | pc ul - /hello.txt  # Upload from stdin`,
	Long: `Upload a local file or directory to your cloud storage.

If remote-path is not specified, uploads to the current working directory.
If remote-path is a directory, the file keeps its original name.
If a directory is given, all files are uploaded recursively.

Use '-' as the local path to read from stdin. Remote path is required
when uploading from stdin.`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		localPath := args[0]
		remotePath := ""
		if len(args) > 1 {
			remotePath = args[1]
		}
		runUpload(localPath, remotePath)
	},
}

var (
	ulSkipExisting bool
	ulForce        bool
	ulJobs         int
)

func init() {
	rootCmd.AddCommand(ulCmd)
	ulCmd.Flags().BoolVar(&ulSkipExisting, "skip-existing", false, "skip files that already exist on the remote")
	ulCmd.Flags().BoolVarP(&ulForce, "force", "f", false, "on name collision create a sibling instead of versioning")
	ulCmd.Flags().IntVarP(&ulJobs, "jobs", "j", 1, "number of parallel uploads for directory uploads")
}

func runUpload(localPath, remotePath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	stdinMode := localPath == "-"
	if stdinMode {
		if remotePath == "" {
			output.PrintError("Remote path is required when uploading from stdin")
			ExitWithError()
		}
		tmpFile, err := os.CreateTemp("", "pigcloud-stdin-*")
		if err != nil {
			output.PrintError("Failed to create temp file: " + err.Error())
			ExitWithError()
		}
		tmpPath := tmpFile.Name()
		defer os.Remove(tmpPath)
		if _, err := io.Copy(tmpFile, os.Stdin); err != nil {
			tmpFile.Close()
			output.PrintError("Failed to read stdin: " + err.Error())
			ExitWithError()
		}
		tmpFile.Close()
		localPath = tmpPath
	}

	stat, err := os.Stat(localPath)
	if err != nil {
		output.PrintError("Cannot access file: " + err.Error())
		ExitWithError()
	}

	if stat.IsDir() {
		runRecursiveUpload(ctx, localPath, remotePath)
		return
	}

	resolvedPath := cmdutil.ResolvePath(remotePath)
	fileName := filepath.Base(localPath)
	if stdinMode {
		if strings.HasSuffix(resolvedPath, "/") {
			output.PrintError("Stdin upload needs a full remote file path, e.g. pc ul - /notes/log.txt")
			ExitWithError()
		}
		fileName = path.Base(resolvedPath)
		resolvedPath = path.Dir(resolvedPath)
		if resolvedPath != "/" {
			resolvedPath += "/"
		}
	}

	if ulSkipExisting {
		remoteCheck := resolvedPath
		if strings.HasSuffix(remoteCheck, "/") || remoteCheck == "/" {
			remoteCheck = remoteCheck + fileName
		}
		inOpts := map[string]string{"source": remoteCheck}
		cmdutil.AddPathTokensFor(inOpts, remoteCheck, e2ee.SelfAndParent, ExitWithError)
		client := api.NewClient()
		resp, _ := client.Execute(ctx, "in", inOpts)
		if resp != nil && resp.Success {
			if !GetQuietOutput() {
				output.PrintInfo("Skipping (exists): " + remoteCheck)
			}
			return
		}
	}

	uploadPath := localPath
	fileSize := stat.Size()
	plainSize := stat.Size()

	fullUploadPath := resolvedPath
	if strings.HasSuffix(fullUploadPath, "/") {
		fullUploadPath += fileName
	} else {
		fullUploadPath += "/" + fileName
	}

	var e2eeOpts map[string]string
	var sealed *e2ee.UploadArtifacts
	defer func() {
		if sealed != nil {
			os.Remove(sealed.EncryptedPath)
		}
	}()
	seal := func() *e2ee.UploadArtifacts {
		sealed = cmdutil.HandleE2EEUpload(ctx, localPath, ExitWithError)
		if sealed == nil {
			return nil
		}
		encPath := sealed.EncryptedPath
		uploadPath = encPath
		e2eeOpts = map[string]string{
			"sealed_key":      sealed.SealedKeyB64,
			"encryption_meta": sealed.EncMetaB64,
			"_original_name":  fileName,
		}
		applyPreserveTimestamps(e2eeOpts, stat, localPath)
		if sealed.TeeSealedKeyB64 != "" {
			e2eeOpts["tee_sealed_key"] = sealed.TeeSealedKeyB64
		}
		if sealed.PlaintextHmacHex != "" {
			e2eeOpts["plaintext_hmac"] = sealed.PlaintextHmacHex
		}
		if ulForce {
			e2eeOpts["force"] = "true"
		}
		sigEd, sigMl, pkEd, pkMl := cmdutil.SignEncryptedFile(encPath, ExitWithError)
		e2eeOpts["signature_ed25519"] = sigEd
		e2eeOpts["signature_mldsa"] = sigMl
		e2eeOpts["signing_pk_ed25519"] = pkEd
		e2eeOpts["signing_pk_mldsa"] = pkMl
		uploadFullPath := strings.TrimLeft(fullUploadPath, "/")
		cmdutil.AddE2eeNameFields(e2eeOpts, fileName, uploadFullPath, ExitWithError)

		cmdutil.AddPathTokensFor(e2eeOpts, resolvedPath, e2ee.SelfAndParent, ExitWithError)

		if encStat, err := os.Stat(encPath); err == nil {
			fileSize = encStat.Size()
		}
		return sealed
	}
	if e2ee.HasE2EEKeys() {
		seal()
	}

	client := api.NewClient().WaitOutScanBudget()
	if forceCollisionBlocked(ctx, client, fullUploadPath, fileSize) {
		output.PrintError(fullUploadPath + " already exists. " + forceCollisionHint)
		ExitWithError()
	}

	bar := progress.NewBar(fileSize, "Uploading "+fileName)

	var resp *api.Response
	sealed, resp, err = sendResealingOnce(ctx, fileName, sealed, seal, func() (*api.Response, error) {
		return uploadHonouringRateLimit(ctx, client, &rateLimitGate{}, fileName, uploadPath, resolvedPath, func(sent, total int64) {
			bar.Set64(sent)
		}, e2eeOpts)
	})

	bar.Finish()

	if err != nil {
		output.PrintError("Upload failed: " + err.Error())
		ExitWithError()
	}

	if !resp.Success {
		output.PrintError(resp.Message)
		ExitWithError()
	}

	var payload api.UploadPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		output.PrintError("Failed to parse response: " + err.Error())
		ExitWithError()
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if payload.NodeID != "" {
		e2ee.PropagateNameToShares(ctx, payload.NodeID, fileName)
	}

	if !GetQuietOutput() {
		output.PrintSuccess("Uploaded " + payload.Name + " to " + output.PrintPath(payload.StoredPath))
		fmt.Printf("  Size: %s\n", output.FormatSize(&plainSize))
		fmt.Printf("  Storage: %s / %s\n", output.FormatSize(&payload.Storage.UsedBytes), output.FormatSize(&payload.Storage.LimitBytes))
	}
}

type fileEntry struct {
	localPath string
	relPath   string
	size      int64
}

func runRecursiveUpload(ctx context.Context, localDir, remotePath string) {
	resolvedRemote := cmdutil.ResolvePath(remotePath)
	dirName := filepath.Base(localDir)

	remoteRoot := resolvedRemote + "/" + dirName
	if strings.HasSuffix(resolvedRemote, "/") {
		remoteRoot = resolvedRemote + dirName
	}

	var files []fileEntry
	var totalSize int64

	err := filepath.Walk(localDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			rel := relativePath(localDir, path)
			files = append(files, fileEntry{
				localPath: path,
				relPath:   rel,
				size:      info.Size(),
			})
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		output.PrintError("Failed to scan directory: " + err.Error())
		ExitWithError()
	}

	if len(files) == 0 {
		output.PrintWarning("Directory is empty, nothing to upload.")
		return
	}

	fmt.Printf("Uploading %d files (%s) from %s to %s\n",
		len(files), output.FormatSize(&totalSize), dirName, remoteRoot)

	dirs := collectDirs(localDir)
	client := api.NewClient().WaitOutScanBudget()

	if err := ensureRemoteDir(ctx, client, remoteRoot); err != nil {
		output.PrintError("Failed to create remote directory: " + err.Error())
		ExitWithError()
	}
	for _, dir := range dirs {
		remoteDirPath := remoteRoot + "/" + filepath.ToSlash(dir)
		if err := ensureRemoteDir(ctx, client, remoteDirPath); err != nil {
			output.PrintWarning("Failed to create directory " + remoteDirPath + ": " + err.Error())
		}
	}

	uploader := &recursiveUploader{
		ctx:        ctx,
		client:     client,
		files:      files,
		remoteRoot: remoteRoot,
		useE2EE:    e2ee.HasE2EEKeys(),
	}
	uploader.run()

	s, f, sk := uploader.counts()
	if !GetQuietOutput() {
		fmt.Println()
		msg := fmt.Sprintf("Uploaded %d files to %s", s, remoteRoot)
		if sk > 0 {
			msg += fmt.Sprintf(", %d skipped", sk)
		}
		if f > 0 {
			output.PrintWarning(msg + fmt.Sprintf(", %d failed", f))
		} else {
			output.PrintSuccess(msg)
		}
	}
}

type recursiveUploader struct {
	ctx        context.Context
	client     *api.Client
	files      []fileEntry
	remoteRoot string
	useE2EE    bool

	succeeded atomic.Int64
	failed    atomic.Int64
	skipped   atomic.Int64
	rateGate  rateLimitGate
}

const ulRateLimitRetries = 3

type rateLimitGate struct {
	mu    sync.Mutex
	until time.Time
}

func (g *rateLimitGate) holdUntil(until time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if until.After(g.until) {
		g.until = until
	}
}

func (g *rateLimitGate) wait(ctx context.Context) error {
	for {
		g.mu.Lock()
		remaining := time.Until(g.until)
		g.mu.Unlock()
		if remaining <= 0 {
			return nil
		}
		select {
		case <-time.After(remaining):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func uploadHonouringRateLimit(ctx context.Context, client *api.Client, gate *rateLimitGate, label, localPath, remoteDir string, progress func(sent, total int64), opts map[string]string) (*api.Response, error) {
	opts = maps.Clone(opts)
	if opts == nil {
		opts = map[string]string{}
	}
	if opts["upload_idempotency_key"] == "" {
		opts["upload_idempotency_key"] = api.NewUploadIdempotencyKey()
	}
	for attempt := 0; ; attempt++ {
		if err := gate.wait(ctx); err != nil {
			return nil, err
		}
		resp, err := client.Upload(ctx, localPath, remoteDir, progress, maps.Clone(opts))
		if err == nil || !api.IsRateLimited(err) || attempt >= ulRateLimitRetries {
			return resp, err
		}
		delay, spent := api.ScanBudgetWait(err)
		if !spent {
			delay = api.RateLimitDelay(attempt, api.RetryAfterHint(err))
		}
		gate.holdUntil(time.Now().Add(delay))
		output.PrintWarning(fmt.Sprintf("%s: upload rate limit reached, retrying in %s", label, delay.Round(time.Second)))
	}
}

func (u *recursiveUploader) alreadyUploaded(remoteFilePath string) bool {
	if !ulSkipExisting {
		return false
	}
	opts := map[string]string{"source": remoteFilePath}
	if u.useE2EE {
		cmdutil.AddPathTokensFor(opts, remoteFilePath, e2ee.SelfAndParent, ExitWithError)
	}
	resp, _ := u.client.Execute(u.ctx, "in", opts)
	return resp != nil && resp.Success
}

func (u *recursiveUploader) sealForUpload(f fileEntry, remoteFilePath string) (*e2ee.UploadArtifacts, int64, map[string]string) {
	fileName := filepath.Base(f.localPath)
	sealed := cmdutil.HandleE2EEUpload(u.ctx, f.localPath, ExitWithError)
	if sealed == nil {
		return nil, 0, nil
	}
	encPath := sealed.EncryptedPath

	opts := map[string]string{
		"sealed_key":      sealed.SealedKeyB64,
		"encryption_meta": sealed.EncMetaB64,
		"_original_name":  fileName,
	}
	if fileStat, statErr := os.Stat(f.localPath); statErr == nil {
		applyPreserveTimestamps(opts, fileStat, f.localPath)
	}
	if sealed.TeeSealedKeyB64 != "" {
		opts["tee_sealed_key"] = sealed.TeeSealedKeyB64
	}
	if sealed.PlaintextHmacHex != "" {
		opts["plaintext_hmac"] = sealed.PlaintextHmacHex
	}
	if ulForce {
		opts["force"] = "true"
	}

	sigEd, sigMl, pkEd, pkMl := cmdutil.SignEncryptedFile(encPath, ExitWithError)
	opts["signature_ed25519"] = sigEd
	opts["signature_mldsa"] = sigMl
	opts["signing_pk_ed25519"] = pkEd
	opts["signing_pk_mldsa"] = pkMl

	fullUploadPath := strings.TrimLeft(remoteFilePath, "/")
	cmdutil.AddE2eeNameFields(opts, fileName, fullUploadPath, ExitWithError)
	if parentDir := path.Dir(fullUploadPath); parentDir != "." && parentDir != "" {
		cmdutil.AddPathTokensFor(opts, parentDir, e2ee.SelfAndAncestors, ExitWithError)
	}

	uploadSize := f.size
	if encStat, err := os.Stat(encPath); err == nil {
		uploadSize = encStat.Size()
	}
	return sealed, uploadSize, opts
}

const staleTeeSealNotice = "the scanner's sealing key changed, sealing the file again"

var teeSealWentStale = e2ee.TeeSealWentStale

func sendResealingOnce(ctx context.Context, label string, sealed *e2ee.UploadArtifacts, reseal func() *e2ee.UploadArtifacts, send func() (*api.Response, error)) (*e2ee.UploadArtifacts, *api.Response, error) {
	resp, err := send()
	if sealed == nil {
		return nil, resp, err
	}
	stale, refusal := teeSealWentStale(ctx, err, sealed.TeeKeySet)
	if refusal != nil {
		return sealed, nil, fmt.Errorf("security scanner refused: %w", refusal)
	}
	if !stale {
		return sealed, resp, err
	}
	os.Remove(sealed.EncryptedPath)
	output.PrintWarning(label + ": " + staleTeeSealNotice)
	next := reseal()
	if next == nil {
		return nil, nil, err
	}
	resp, err = send()
	return next, resp, err
}

func (u *recursiveUploader) uploadOne(i int, f fileEntry) {
	remoteFilePath := u.remoteRoot + "/" + filepath.ToSlash(f.relPath)

	if u.alreadyUploaded(remoteFilePath) {
		u.skipped.Add(1)
		return
	}
	if u.ctx.Err() != nil {
		u.failed.Add(1)
		return
	}

	label := fmt.Sprintf("[%d/%d] %s", i+1, len(u.files), filepath.ToSlash(f.relPath))
	fileName := filepath.Base(f.localPath)
	uploadPath := f.localPath
	uploadSize := f.size
	var e2eeOpts map[string]string
	var sealed *e2ee.UploadArtifacts
	removeSealed := func() {
		if sealed != nil {
			os.Remove(sealed.EncryptedPath)
		}
	}

	if u.useE2EE {
		sealed, uploadSize, e2eeOpts = u.sealForUpload(f, remoteFilePath)
		if sealed == nil {
			u.failed.Add(1)
			return
		}
		uploadPath = sealed.EncryptedPath
	}

	if forceCollisionBlocked(u.ctx, u.client, remoteFilePath, uploadSize) {
		removeSealed()
		output.PrintError("Skipping " + f.relPath + ": already exists. " + forceCollisionHint)
		u.failed.Add(1)
		return
	}

	bar := progress.NewBar(uploadSize, label)

	reseal := func() *e2ee.UploadArtifacts {
		next, _, opts := u.sealForUpload(f, remoteFilePath)
		if next != nil {
			uploadPath, e2eeOpts = next.EncryptedPath, opts
		}
		return next
	}
	var resp *api.Response
	var err error
	sealed, resp, err = sendResealingOnce(u.ctx, f.relPath, sealed, reseal, func() (*api.Response, error) {
		return uploadHonouringRateLimit(u.ctx, u.client, &u.rateGate, f.relPath, uploadPath, remoteParentDir(remoteFilePath), func(sent, total int64) {
			bar.Set64(sent)
		}, e2eeOpts)
	})

	bar.Finish()
	removeSealed()

	if err != nil {
		output.PrintError("Failed to upload " + f.relPath + ": " + err.Error())
		u.failed.Add(1)
		return
	}

	if !resp.Success {
		output.PrintError("Failed to upload " + f.relPath + ": " + resp.Message)
		u.failed.Add(1)
		return
	}

	if u.useE2EE {
		var payload api.UploadPayload
		if err := json.Unmarshal(resp.Raw, &payload); err == nil && payload.NodeID != "" {
			e2ee.PropagateNameToShares(u.ctx, payload.NodeID, fileName)
		}
	}

	u.succeeded.Add(1)
}

func (u *recursiveUploader) run() {
	jobs := min(max(ulJobs, 1), len(u.files))

	if jobs <= 1 {
		for i, f := range u.files {
			u.uploadOne(i, f)
		}
		return
	}

	var wg sync.WaitGroup
	ch := make(chan int, len(u.files))
	for i := range u.files {
		ch <- i
	}
	close(ch)

	for range jobs {
		wg.Go(func() {
			for i := range ch {
				u.uploadOne(i, u.files[i])
			}
		})
	}
	wg.Wait()
}

func (u *recursiveUploader) counts() (int64, int64, int64) {
	return u.succeeded.Load(), u.failed.Load(), u.skipped.Load()
}

func ensureRemoteDir(ctx context.Context, client *api.Client, remotePath string) error {
	options := map[string]string{
		"source":  remotePath,
		"parents": "true",
	}
	if e2ee.HasE2EEKeys() {
		cmdutil.AddPathTokensFor(options, remotePath, e2ee.SelfAndParent, ExitWithError)
		if trimmed := strings.TrimPrefix(remotePath, "/"); trimmed != "" {
			cmdutil.AddE2eeNameFieldsForMkParents(options, strings.Split(trimmed, "/"), ExitWithError)
		}
	}
	resp, err := client.Execute(ctx, "mk", options)
	if err != nil {
		return err
	}
	if resp != nil && !resp.Success && resp.ErrorCode != mkPathExistsCode {
		reason := strings.TrimSpace(resp.Message)
		if reason == "" {
			reason = "the server declined it"
		}
		return fmt.Errorf("could not create remote directory %s: %s", remotePath, reason)
	}
	return nil
}

const mkPathExistsCode = "path_exists"

func forceCollisionBlocked(ctx context.Context, client *api.Client, remoteFilePath string, ciphertextSize int64) bool {
	if !ulForce || !api.UploadIsChunked(ciphertextSize) {
		return false
	}
	opts := map[string]string{"source": remoteFilePath}
	cmdutil.AddPathTokensFor(opts, remoteFilePath, e2ee.SelfAndParent, ExitWithError)
	resp, err := client.Execute(ctx, "in", opts)
	return err == nil && resp != nil && resp.Success
}

const forceCollisionHint = "--force cannot create a same-name copy for files this large. " +
	"Re-run without --force to store the upload as a new version, or rename the file first."

func remoteParentDir(remoteFilePath string) string {
	dir := path.Dir(remoteFilePath)
	if dir == "." || dir == "" {
		return "/"
	}
	return dir
}

func collectDirs(root string) []string {
	var dirs []string
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && path != root {
			rel := relativePath(root, path)
			dirs = append(dirs, rel)
		}
		return nil
	})
	return dirs
}

func relativePath(base, path string) string {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return filepath.Base(path)
	}
	return rel
}

func applyPreserveTimestamps(opts map[string]string, stat os.FileInfo, localPath string) {
	if opts == nil {
		return
	}
	if mt := stat.ModTime().Unix(); mt > 0 {
		opts["source_mtime"] = fmt.Sprintf("%d", mt)
	}
	if captured := cmdutil.ParseExifCaptureDate(localPath); captured > 0 {
		opts["captured_at"] = fmt.Sprintf("%d", captured)
	}
}
