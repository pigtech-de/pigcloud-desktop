package syncer

import (
	"fmt"
	"os"
	"syscall"
)

func localFileID(fi os.FileInfo) string {
	if fi == nil {
		return ""
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d", st.Dev, st.Ino, st.Ctim.Nano())
}
