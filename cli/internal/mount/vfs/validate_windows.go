//go:build windows

package vfs

import "strings"

var reservedDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func isSafeNamePlatform(name string) bool {
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`<>:"|?*`, r) {
			return false
		}
	}
	if last := name[len(name)-1]; last == '.' || last == ' ' {
		return false
	}
	base := name
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		base = name[:dot]
	}
	return !reservedDeviceNames[strings.ToUpper(base)]
}
