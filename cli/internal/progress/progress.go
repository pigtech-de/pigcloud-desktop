package progress

import (
	"fmt"
	"io"
	"os"

	"pigcloud/internal/output"

	"github.com/schollz/progressbar/v3"
)

func NewBar(total int64, description string) *progressbar.ProgressBar {
	quiet := output.IsQuiet()
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
			if !output.IsQuiet() {
				fmt.Fprint(os.Stderr, "\n")
			}
		}),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)
}
