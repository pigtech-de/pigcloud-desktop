package output

import (
	"fmt"
	"io"
	"os"

	"github.com/schollz/progressbar/v3"
)

var quiet bool

func SetQuiet(q bool) { quiet = q }

func IsQuiet() bool { return quiet }

func NewProgressBar(total int64, description string) *progressbar.ProgressBar {
	writer := io.Writer(os.Stderr)
	if quiet {
		writer = io.Discard
	}
	return progressbar.NewOptions64(
		total,
		progressbar.OptionSetDescription(description),
		progressbar.OptionSetWriter(writer),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(40),
		progressbar.OptionThrottle(65),
		progressbar.OptionShowCount(),
		progressbar.OptionOnCompletion(func() {
			if !quiet {
				fmt.Fprint(os.Stderr, "\n")
			}
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)
}
