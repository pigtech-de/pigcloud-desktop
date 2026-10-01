package cmd

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/e2ee"
)

var e2eeField = regexp.MustCompile(`\.E2EE\b`)

func readsE2eeField(code string) bool {
	for _, loc := range e2eeField.FindAllStringIndex(code, -1) {
		rest := strings.TrimLeft(code[loc[1]:], " \t")
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") {
			continue
		}
		return true
	}
	return false
}

var e2eeGateRoots = []string{
	".",
	filepath.Join("..", "internal", "mount"),
	filepath.Join("..", "internal", "api"),
	filepath.Join("..", "internal", "e2ee"),
}

var e2eeAllowedReads = map[string]string{
	"api.AsDownloadResult":          "CatPayload to DownloadResult field copy, before any guard runs",
	"api.parseDownloadMetadata":     "the wire parse itself, which is where the flag enters the process",
	"e2ee.RequireEncryptedDownload": "the one refusal every caller must reach",
}

var funcDecl = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z0-9_]+)`)

func TestNoCommandBranchesOnTheServersE2eeFlag(t *testing.T) {
	var offenders []string
	seenAllowed := map[string]bool{}
	scanned := 0

	for _, root := range e2eeGateRoots {
		pkg := filepath.Base(root)
		if root == "." {
			pkg = "cmd"
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			name := d.Name()
			if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			scanned++
			enclosing := ""
			for i, line := range strings.Split(string(body), "\n") {
				if m := funcDecl.FindStringSubmatch(line); m != nil {
					enclosing = pkg + "." + m[1]
				}
				code := line
				if idx := strings.Index(code, "//"); idx >= 0 {
					code = code[:idx]
				}
				if !readsE2eeField(code) {
					continue
				}
				if _, allowed := e2eeAllowedReads[enclosing]; allowed {
					seenAllowed[enclosing] = true
					continue
				}
				offenders = append(offenders,
					filepath.ToSlash(path)+":"+strconv.Itoa(i+1)+" ("+enclosing+"): "+strings.TrimSpace(line))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	if scanned < 60 {
		t.Fatalf("scanned only %d files, the probe lost its corpus", scanned)
	}
	if len(offenders) != 0 {
		t.Errorf("a caller gates verification or decryption on the response's own e2ee flag; "+
			"call e2ee.RequireEncryptedDownload and make the decrypt unconditional:\n  %s",
			strings.Join(offenders, "\n  "))
	}
	for site, why := range e2eeAllowedReads {
		if !seenAllowed[site] {
			t.Errorf("allowlisted read in %s (%s) is gone: an entry that matches nothing exempts nothing, "+
				"so either the function was renamed or the read it covers moved somewhere unguarded", site, why)
		}
	}
}

func TestAMissingDownloadMetadataHeaderRefuses(t *testing.T) {
	if err := e2ee.RequireEncryptedDownload(&api.DownloadResult{}); !errors.Is(err, e2ee.ErrPlaintextResponse) {
		t.Fatalf("guard on a zero DownloadResult = %v, want ErrPlaintextResponse", err)
	}
	if err := e2ee.RequireEncryptedDownload(nil); !errors.Is(err, e2ee.ErrDownloadMetadataMissing) {
		t.Fatalf("guard on no metadata at all = %v, want ErrDownloadMetadataMissing", err)
	}
}
