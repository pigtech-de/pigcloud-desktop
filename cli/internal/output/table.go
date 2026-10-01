package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/tw"
)

var jsonErrors bool

func SetJSONErrors(enabled bool) {
	jsonErrors = enabled
}

func Table(headers []string) *tablewriter.Table {
	return TableTo(os.Stdout, headers)
}

func TableTo(w io.Writer, headers []string) *tablewriter.Table {
	cell := tw.CellConfig{
		Formatting: tw.CellFormatting{AutoWrap: tw.WrapNone, AutoFormat: tw.Off},
		Alignment:  tw.CellAlignment{Global: tw.AlignLeft},
		Padding:    tw.CellPadding{Global: tw.Padding{Right: "  ", Overwrite: true}},
	}
	return tablewriter.NewTable(w,
		tablewriter.WithHeader(headers),
		tablewriter.WithRendition(tw.Rendition{
			Borders: tw.Border{Left: tw.Off, Right: tw.Off, Top: tw.Off, Bottom: tw.Off},
			Settings: tw.Settings{
				Separators: tw.Separators{ShowHeader: tw.Off, ShowFooter: tw.Off, BetweenRows: tw.Off, BetweenColumns: tw.Off},
				Lines:      tw.Lines{ShowTop: tw.Off, ShowBottom: tw.Off, ShowHeaderLine: tw.Off, ShowFooterLine: tw.Off},
			},
		}),
		tablewriter.WithConfig(tablewriter.Config{Header: cell, Row: cell}),
	)
}

func FormatSize(bytes *int64) string {
	if bytes == nil {
		return "-"
	}
	b := *bytes
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func FormatTime(isoTime *string) string {
	if isoTime == nil || *isoTime == "" {
		return "-"
	}
	t, err := time.Parse(time.RFC3339, *isoTime)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", *isoTime)
		if err != nil {
			return *isoTime
		}
	}
	return t.Local().Format("Jan 02 15:04")
}

func FormatType(fileType string, name string) string {
	switch fileType {
	case "directory":
		return color.BlueString(name + "/")
	case "image":
		return color.MagentaString(name)
	case "video":
		return color.MagentaString(name)
	case "audio":
		return color.CyanString(name)
	case "document":
		return color.WhiteString(name)
	case "archive":
		return color.RedString(name)
	case "code":
		return color.GreenString(name)
	default:
		return name
	}
}

func PrintSuccess(message string) {
	fmt.Fprintln(os.Stderr, color.GreenString("✓")+" "+message)
}

func PrintError(message string) {
	if jsonErrors {
		line, err := json.Marshal(map[string]any{"success": false, "message": message})
		if err == nil {
			fmt.Println(string(line))
			return
		}
	}
	fmt.Fprintln(os.Stderr, color.RedString("✗")+" "+message)
}

func PrintInfo(message string) {
	fmt.Fprintln(os.Stderr, color.CyanString("ℹ")+" "+message)
}

func PrintWarning(message string) {
	fmt.Fprintln(os.Stderr, color.YellowString("⚠")+" "+message)
}

func PrintPath(path string) string {
	if path == "/" {
		return color.CyanString("/")
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part != "" {
			parts[i] = color.CyanString(part)
		}
	}
	return strings.Join(parts, "/")
}
