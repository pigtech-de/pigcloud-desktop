package output

import (
	"fmt"
	"io"
	"strconv"

	"github.com/fatih/color"
)

type NameResolver func(sealedB64 string) string

const NameUnavailable = "(encrypted)"

func (resolve NameResolver) name(sealedB64 string) string {
	if resolve != nil {
		if plain := resolve(sealedB64); plain != "" {
			return plain
		}
	}
	return NameUnavailable
}

type DisplayBlock struct {
	Type    string            `json:"type"`
	Text    string            `json:"text,omitempty"`
	Style   string            `json:"style,omitempty"`
	Headers []string          `json:"headers,omitempty"`
	Rows    [][]DisplayCell   `json:"rows,omitempty"`
	Pairs   []DisplayPair     `json:"pairs,omitempty"`
	Tree    []DisplayTreeNode `json:"tree,omitempty"`
}

type DisplayTreeNode struct {
	Name     string            `json:"name"`
	FileType string            `json:"fileType"`
	Children []DisplayTreeNode `json:"children,omitempty"`
}

type DisplayCell struct {
	Text     string `json:"text,omitempty"`
	Value    string `json:"value,omitempty"`
	Format   string `json:"format,omitempty"`
	Name     string `json:"name,omitempty"`
	FileType string `json:"fileType,omitempty"`
	Style    string `json:"style,omitempty"`
	Align    string `json:"align,omitempty"`
}

type DisplayPair struct {
	Key      string `json:"key"`
	Text     string `json:"text,omitempty"`
	Value    string `json:"value,omitempty"`
	Format   string `json:"format,omitempty"`
	Name     string `json:"name,omitempty"`
	FileType string `json:"fileType,omitempty"`
	Style    string `json:"style,omitempty"`
}

func HasNameRefs(blocks []DisplayBlock) bool {
	for _, b := range blocks {
		for _, row := range b.Rows {
			for _, c := range row {
				if c.Name != "" {
					return true
				}
			}
		}
		for _, p := range b.Pairs {
			if p.Name != "" {
				return true
			}
		}
		if treeHasNameRefs(b.Tree) {
			return true
		}
	}
	return false
}

func treeHasNameRefs(nodes []DisplayTreeNode) bool {
	for _, n := range nodes {
		if n.Name != "" || treeHasNameRefs(n.Children) {
			return true
		}
	}
	return false
}

func RenderDisplay(w io.Writer, blocks []DisplayBlock, resolveName NameResolver) {
	for _, b := range blocks {
		switch b.Type {
		case "heading":
			fmt.Fprintln(w, headingText(b.Style, b.Text))
		case "text":
			fmt.Fprintln(w, applyStyle(b.Style, b.Text))
		case "table":
			renderTable(w, b.Headers, b.Rows, resolveName)
		case "keyvalue":
			renderKeyValue(w, b.Pairs, resolveName)
		case "tree":
			renderTree(w, b.Tree, "", resolveName)
		}
	}
}

func renderTree(w io.Writer, nodes []DisplayTreeNode, prefix string, resolveName NameResolver) {
	for i, n := range nodes {
		isLast := i == len(nodes)-1
		connector := "├── "
		childPrefix := prefix + "│   "
		if isLast {
			connector = "└── "
			childPrefix = prefix + "    "
		}
		fmt.Fprintf(w, "%s%s%s\n", prefix, connector, FormatType(n.FileType, resolveName.name(n.Name)))
		if len(n.Children) > 0 {
			renderTree(w, n.Children, childPrefix, resolveName)
		}
	}
}

func renderTable(w io.Writer, headers []string, rows [][]DisplayCell, resolveName NameResolver) {
	table := TableTo(w, headers)
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = c.resolve(resolveName)
		}
		table.Append(cells)
	}
	table.Render()
}

func renderKeyValue(w io.Writer, pairs []DisplayPair, resolveName NameResolver) {
	width := 0
	for _, p := range pairs {
		if n := len(p.Key); n > width {
			width = n
		}
	}
	for _, p := range pairs {
		cell := DisplayCell{Text: p.Text, Value: p.Value, Format: p.Format, Name: p.Name, FileType: p.FileType, Style: p.Style}
		label := fmt.Sprintf("%-*s", width+1, p.Key+":")
		fmt.Fprintf(w, "%s %s\n", color.CyanString(label), cell.resolve(resolveName))
	}
}

func (c DisplayCell) resolve(resolveName NameResolver) string {
	switch {
	case c.Name != "":
		return FormatType(c.FileType, resolveName.name(c.Name))
	case c.Format != "":
		return applyStyle(c.Style, formatValue(c.Format, c.Value))
	default:
		return applyStyle(c.Style, c.Text)
	}
}

func formatValue(format, value string) string {
	switch format {
	case "size":
		if value == "" {
			return "-"
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return value
		}
		return FormatSize(&n)
	case "time":
		if value == "" {
			return "-"
		}
		v := value
		return FormatTime(&v)
	default:
		return value
	}
}

func headingText(style, text string) string {
	if style == "path" {
		return PrintPath(text)
	}
	return applyStyle(style, text)
}

func applyStyle(style, s string) string {
	switch style {
	case "info", "accent":
		return color.CyanString(s)
	case "success":
		return color.GreenString(s)
	case "error", "danger":
		return color.RedString(s)
	case "warn", "count":
		return color.YellowString(s)
	case "muted":
		return color.HiBlackString(s)
	case "path":
		return PrintPath(s)
	default:
		return s
	}
}
