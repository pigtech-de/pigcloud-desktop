package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"

	"github.com/fatih/color"
)

type lsEntry struct {
	sealed   string
	plain    string
	fileType string
	size     *int64
	modified *string
	shared   bool
	direct   bool
	perm     *string
}

func i64(v int64) *int64 { return &v }
func s(v string) *string { return &v }

func lsFixture() (string, []lsEntry, NameResolver) {
	path := "/Documents"
	entries := []lsEntry{
		{sealed: "c2VhbGVkOlBob3Rvcw==", plain: "Photos", fileType: "directory", modified: s("2026-02-20T14:03:05+00:00")},
		{sealed: "c2VhbGVkOnJlcG9ydA==", plain: "report.pdf", fileType: "document", size: i64(48211), modified: s("2026-05-01T09:30:00+00:00"), shared: true, direct: true, perm: s("read")},
		{sealed: "c2VhbGVkOmJhY2t1cA==", plain: "backup.zip", fileType: "archive", size: i64(1572864), modified: s("2026-04-12T22:15:00+00:00"), shared: true, direct: false},
	}
	names := map[string]string{}
	for _, e := range entries {
		names[e.sealed] = e.plain
	}
	resolve := func(sealed string) string { return names[sealed] }
	return path, entries, resolve
}

func sharedCell(e lsEntry) (string, string) {
	if !e.shared {
		return "", ""
	}
	if e.direct {
		perm := "read"
		if e.perm != nil {
			perm = *e.perm
		}
		return fmt.Sprintf("[shared:%s]", perm), "warn"
	}
	return "[inherited]", "muted"
}

func legacyLs(path string, entries []lsEntry, resolve NameResolver, long bool) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s\n\n", PrintPath(path))

	var headers []string
	if long {
		headers = []string{"Name", "Size (bytes)", "Modified", "Type", "Sharing"}
	} else {
		headers = []string{"Name", "Size", "Modified", "Sharing"}
	}
	table := TableTo(&buf, headers)
	for _, e := range entries {
		name := FormatType(e.fileType, resolve(e.sealed))
		shareText, shareStyle := sharedCell(e)
		shared := applyStyle(shareStyle, shareText)
		if long {
			sizeBytes := ""
			if e.size != nil {
				sizeBytes = fmt.Sprintf("%d", *e.size)
			} else if e.fileType == "directory" {
				sizeBytes = "-"
			}
			modified := ""
			if e.modified != nil {
				modified = *e.modified
			}
			table.Append([]string{name, sizeBytes, modified, e.fileType, shared})
		} else {
			table.Append([]string{name, FormatSize(e.size), FormatTime(e.modified), shared})
		}
	}
	table.Render()
	fmt.Fprintf(&buf, "\n%d items\n", len(entries))
	return buf.String()
}

func serverBlocks(path string, entries []lsEntry, long bool) []DisplayBlock {
	var headers []string
	var rows [][]DisplayCell
	for _, e := range entries {
		name := DisplayCell{Name: e.sealed, FileType: e.fileType}
		shareText, shareStyle := sharedCell(e)
		share := DisplayCell{Text: shareText, Style: shareStyle}
		if long {
			sizeText := ""
			if e.size != nil {
				sizeText = strconv.FormatInt(*e.size, 10)
			} else if e.fileType == "directory" {
				sizeText = "-"
			}
			modText := ""
			if e.modified != nil {
				modText = *e.modified
			}
			rows = append(rows, []DisplayCell{
				name,
				{Text: sizeText, Align: "right"},
				{Text: modText},
				{Text: e.fileType},
				share,
			})
		} else {
			sizeVal := ""
			if e.size != nil {
				sizeVal = strconv.FormatInt(*e.size, 10)
			}
			modVal := ""
			if e.modified != nil {
				modVal = *e.modified
			}
			rows = append(rows, []DisplayCell{
				name,
				{Value: sizeVal, Format: "size", Align: "right"},
				{Value: modVal, Format: "time"},
				share,
			})
		}
	}
	if long {
		headers = []string{"Name", "Size (bytes)", "Modified", "Type", "Sharing"}
	} else {
		headers = []string{"Name", "Size", "Modified", "Sharing"}
	}
	return []DisplayBlock{
		{Type: "heading", Style: "path", Text: path},
		{Type: "text"},
		{Type: "table", Headers: headers, Rows: rows},
		{Type: "text"},
		{Type: "text", Text: fmt.Sprintf("%d items", len(entries))},
	}
}

func TestDisplayParityWithLegacyLs(t *testing.T) {
	old := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = old }()

	path, entries, resolve := lsFixture()

	for _, long := range []bool{false, true} {
		name := "short"
		if long {
			name = "long"
		}
		t.Run(name, func(t *testing.T) {
			want := legacyLs(path, entries, resolve, long)

			raw, err := json.Marshal(serverBlocks(path, entries, long))
			if err != nil {
				t.Fatalf("marshal blocks: %v", err)
			}
			var decoded []DisplayBlock
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatalf("unmarshal blocks: %v", err)
			}
			var buf bytes.Buffer
			RenderDisplay(&buf, decoded, resolve)
			got := buf.String()

			if got != want {
				t.Errorf("generic renderer drifted from legacy ls (%s layout)\n--- want (legacy) ---\n%q\n--- got (generic) ---\n%q", name, want, got)
			}
		})
	}
}

func TestDisplayTreeRender(t *testing.T) {
	old := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = old }()

	names := map[string]string{"s1": "src", "s2": "main.go", "s3": "docs", "s4": "readme.md"}
	resolve := func(s string) string { return names[s] }

	blocks := []DisplayBlock{
		{Type: "heading", Style: "path", Text: "/proj"},
		{Type: "tree", Tree: []DisplayTreeNode{
			{Name: "s1", FileType: "directory", Children: []DisplayTreeNode{
				{Name: "s2", FileType: "code"},
			}},
			{Name: "s3", FileType: "directory", Children: []DisplayTreeNode{
				{Name: "s4", FileType: "document"},
			}},
		}},
		{Type: "text"},
		{Type: "text", Text: "2 directories, 2 files"},
	}

	var buf bytes.Buffer
	RenderDisplay(&buf, blocks, resolve)
	got := buf.String()

	want := "/proj\n" +
		"├── src/\n" +
		"│   └── main.go\n" +
		"└── docs/\n" +
		"    └── readme.md\n" +
		"\n" +
		"2 directories, 2 files\n"
	if got != want {
		t.Errorf("tree render drifted\n--- want ---\n%q\n--- got ---\n%q", want, got)
	}
}

func TestHasNameRefs(t *testing.T) {
	cases := []struct {
		name   string
		blocks []DisplayBlock
		want   bool
	}{
		{"table name-ref", []DisplayBlock{{Type: "table", Rows: [][]DisplayCell{{{Name: "c2VhbGVk"}}}}}, true},
		{"keyvalue name-ref", []DisplayBlock{{Type: "keyvalue", Pairs: []DisplayPair{{Key: "Name", Name: "c2VhbGVk"}}}}, true},
		{"tree name-ref", []DisplayBlock{{Type: "tree", Tree: []DisplayTreeNode{{Name: "c2VhbGVk"}}}}, true},
		{"plain table", []DisplayBlock{{Type: "table", Rows: [][]DisplayCell{{{Text: "bob"}, {Value: "12", Format: "size"}}}}}, false},
		{"keyvalue no names", []DisplayBlock{{Type: "keyvalue", Pairs: []DisplayPair{{Key: "User", Text: "bob"}}}}, false},
	}
	for _, c := range cases {
		if got := HasNameRefs(c.blocks); got != c.want {
			t.Errorf("%s: HasNameRefs = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRenderDisplayWritesNothingForUnusableBlocks(t *testing.T) {
	var buf bytes.Buffer
	RenderDisplay(&buf, nil, nil)
	RenderDisplay(&buf, []DisplayBlock{{Type: "not-a-block-type", Text: "ignored"}}, nil)
	if buf.Len() != 0 {
		t.Errorf("nothing should have been written, got %q", buf.String())
	}
}
