package mlog

import (
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
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
