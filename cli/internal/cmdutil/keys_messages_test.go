package cmdutil

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var pinnedUnlockMessages = []string{
	"Encryption is locked. Unlock to view file names.",
	"Encryption is locked: file names are hidden. Run 'pc uk' to unlock.",
	"Encryption isn't set up for this account. Finish setup in the web app.",
	"Unlocked for this command (agent didn't start, run 'pc uk' to persist).",
}

var bannedDashes = string([]rune{0x2014, 0x2013})

func TestEnsureNamesReadableKeepsItsWording(t *testing.T) {
	src, err := os.ReadFile("keys.go")
	if err != nil {
		t.Fatalf("read keys.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func EnsureNamesReadable()")
	if start < 0 {
		t.Fatal("EnsureNamesReadable is gone; this pin guards nothing")
	}

	var found []string
	for _, m := range regexp.MustCompile(`output\.Print(?:Error|Warning|Info)\("([^"]*)"\)`).FindAllStringSubmatch(body[start:], -1) {
		found = append(found, m[1])
	}
	if len(found) == 0 {
		t.Fatal("the scan matched no printed line inside EnsureNamesReadable")
	}
	slices.Sort(found)
	want := slices.Clone(pinnedUnlockMessages)
	slices.Sort(want)
	if !slices.Equal(found, want) {
		t.Errorf("the unlock guidance drifted.\n  in source: %q\n  pinned:    %q", found, want)
	}

	for _, line := range found {
		if strings.ContainsAny(line, bannedDashes) {
			t.Errorf("%q carries a dash the house punctuation rule bans", line)
		}
	}
}
