//go:build !windows

package mount

func HideDir(_ string) {}

func HideMetaDir(_ string) {}
