package fsutil

import (
	"strings"
	"unicode/utf8"
)

func IsDisplaySafeName(name string) bool {
	if name == "" || name == "." || name == ".." || !utf8.ValidString(name) {
		return false
	}
	if strings.ContainsAny(name, "/\\") {
		return false
	}
	return strings.IndexFunc(name, IsControlRune) < 0
}

func IsSafeName(name string) bool {
	return IsDisplaySafeName(name) && isSafeNamePlatform(name)
}

func IsControlRune(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

func StripControl(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, IsControlRune) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if IsControlRune(r) {
			return -1
		}
		return r
	}, s)
}
