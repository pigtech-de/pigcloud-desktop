package daemon

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var bareLogCall = regexp.MustCompile(`(^|[^\w.])log\.(Printf|Println|Print|Fatalf|Fatal|Panicf)\(`)

func TestDaemonLoggingGoesThroughTheLeveledLogger(t *testing.T) {
	root := ".."
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/mount/mlog/") {
			return nil
		}
		if !strings.Contains(filepath.ToSlash(path), "/mount/") {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if bareLogCall.MatchString(line) {
				offenders = append(offenders, path+":"+itoa(i+1)+" "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("%d daemon log call(s) bypass mlog and carry no level:\n%s",
			len(offenders), strings.Join(offenders, "\n"))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
