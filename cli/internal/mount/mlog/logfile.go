package mlog

import (
	"os"
	"strings"
	"sync"
)

const MaxLogSize = 5 << 20

func FatalLogPath(logPath string) string {
	return strings.TrimSuffix(logPath, ".log") + ".fatal.log"
}

func OpenLog(path string) (*os.File, error) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > MaxLogSize {
		rotate(path)
	}
	return openAppend(path)
}

func rotate(path string) error {
	return os.Rename(path, path+".1")
}

type RotatingLog struct {
	mu     sync.Mutex
	path   string
	f      *os.File
	size   int64
	max    int64
	rename func(string) error
}

func NewRotatingLog(path string) (*RotatingLog, error) {
	f, err := OpenLog(path)
	if err != nil {
		return nil, err
	}
	return Rotating(path, f, MaxLogSize), nil
}

func Rotating(path string, f *os.File, max int64) *RotatingLog {
	var size int64
	if fi, statErr := f.Stat(); statErr == nil {
		size = fi.Size()
	}
	return &RotatingLog{path: path, f: f, size: size, max: max}
}

func (r *RotatingLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.max {
		r.rotateLocked()
	}
	if r.f == nil {
		return len(p), nil
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *RotatingLog) rotateLocked() {
	if r.f != nil {
		r.f.Close()
		r.f = nil
	}
	rename := r.rename
	if rename == nil {
		rename = rotate
	}
	rename(r.path)
	if f, err := openAppend(r.path); err == nil {
		r.f = f
		if info, statErr := f.Stat(); statErr == nil {
			r.size = info.Size()
		}
	}
}

func (r *RotatingLog) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}
