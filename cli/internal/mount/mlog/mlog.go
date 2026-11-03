package mlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

const EnvVar = "PIGCLOUD_LOG_LEVEL"

var current atomic.Int32

func init() {
	if lvl, ok := ParseLevel(os.Getenv(EnvVar)); ok {
		current.Store(int32(lvl))
		return
	}
	current.Store(int32(LevelInfo))
}

func ParseLevel(name string) (Level, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "debug", "trace":
		return LevelDebug, true
	case "info":
		return LevelInfo, true
	case "warn", "warning":
		return LevelWarn, true
	case "error":
		return LevelError, true
	}
	return LevelInfo, false
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

func SetLevel(l Level) { current.Store(int32(l)) }

func SetOutput(w io.Writer) { log.SetOutput(w) }

func CurrentLevel() Level { return Level(current.Load()) }

func Enabled(l Level) bool { return l >= CurrentLevel() }

func emit(l Level, format string, args ...any) {
	if !Enabled(l) {
		return
	}
	log.Printf(l.String()+" "+format, args...)
}

func Debugf(format string, args ...any) { emit(LevelDebug, format, args...) }

func Infof(format string, args ...any) { emit(LevelInfo, format, args...) }

func Warnf(format string, args ...any) { emit(LevelWarn, format, args...) }

func Errorf(format string, args ...any) { emit(LevelError, format, args...) }

func Cause(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, os.ErrNotExist):
		return "not_found"
	case errors.Is(err, os.ErrPermission):
		return "permission"
	case errors.Is(err, os.ErrExist):
		return "exists"
	case errors.Is(err, syscall.ENOSPC):
		return "disk_full"
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network"
	}
	kind := "error"
	for e := err; e != nil; e = errors.Unwrap(e) {
		if t := fmt.Sprintf("%T", e); !strings.HasPrefix(t, "*fmt.") && !strings.HasPrefix(t, "*errors.") {
			kind = t
			break
		}
	}
	return kind
}

const panicStackBytes = 32 << 10

func RecoverPanic(name string) {
	if r := recover(); r != nil {
		LogPanic(name, r)
	}
}

func LogPanic(name string, r any) {
	buf := make([]byte, panicStackBytes)
	n := runtime.Stack(buf, false)
	Errorf("%s PANIC: %v\n%s", name, r, buf[:n])
}
