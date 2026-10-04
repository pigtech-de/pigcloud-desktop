package progress

import (
	"testing"

	"pigcloud/internal/output"
)

func TestQuietBarStillDrives(t *testing.T) {
	output.SetQuiet(true)
	defer output.SetQuiet(false)

	bar := NewBar(100, "test")
	bar.Set64(50)
	bar.Finish()
}
