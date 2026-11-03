//go:build !linux && !darwin

package transfer

func freeBytes(string) int64 { return -1 }
