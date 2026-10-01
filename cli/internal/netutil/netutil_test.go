package netutil

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	loopbackDial   = regexp.MustCompile(`net\.DialTimeout\(.*(LoopbackHost|127\.0\.0\.1)`)
	literalTimeout = regexp.MustCompile(`,\s*\d+\s*(\*\s*time\.\w+)?\s*\)`)
)

func TestLoopbackDialsShareOneTimeout(t *testing.T) {
	var offenders []string
	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if loopbackDial.MatchString(line) && literalTimeout.MatchString(line) {
				offenders = append(offenders, path+":"+itoa(i+1)+" "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("%d loopback dial(s) hardcode a timeout instead of netutil.LoopbackDialTimeout:\n%s",
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
