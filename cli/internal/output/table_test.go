package output

import (
	"testing"
)

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes *int64
		want  string
	}{
		{nil, "-"},
		{ptr(0), "0 B"},
		{ptr(512), "512 B"},
		{ptr(1024), "1.0 KB"},
		{ptr(1536), "1.5 KB"},
		{ptr(1048576), "1.0 MB"},
		{ptr(1073741824), "1.0 GB"},
	}
	for _, tt := range tests {
		got := FormatSize(tt.bytes)
		if got != tt.want {
			label := "nil"
			if tt.bytes != nil {
				label = string(rune(*tt.bytes))
			}
			t.Errorf("FormatSize(%v) = %q, want %q", label, got, tt.want)
		}
	}
}

func TestFormatTime(t *testing.T) {
	tests := []struct {
		input *string
		want  string
	}{
		{nil, "-"},
		{strPtr(""), "-"},
		{strPtr("not-a-date"), "not-a-date"},
	}
	for _, tt := range tests {
		got := FormatTime(tt.input)
		if tt.want == "-" && got != "-" {
			t.Errorf("FormatTime(%v) = %q, want %q", tt.input, got, tt.want)
		}
		if tt.want == "not-a-date" && got != "not-a-date" {
			t.Errorf("FormatTime(not-a-date) = %q, want passthrough", got)
		}
	}

	rfc := "2026-03-28T14:30:00Z"
	got := FormatTime(&rfc)
	if got == rfc || got == "-" {
		t.Errorf("FormatTime(RFC3339) should format, got %q", got)
	}

	db := "2026-03-28 14:30:00"
	got = FormatTime(&db)
	if got == db || got == "-" {
		t.Errorf("FormatTime(DB format) should format, got %q", got)
	}
}

func TestFormatType(t *testing.T) {
	types := []string{"directory", "image", "video", "audio", "document", "archive", "code", "unknown"}
	for _, ft := range types {
		got := FormatType(ft, "test")
		if got == "" {
			t.Errorf("FormatType(%q, test) returned empty", ft)
		}
	}
	got := FormatType("directory", "docs")
	if len(got) == 0 {
		t.Error("FormatType(directory) is empty")
	}
}

func TestPrintPath(t *testing.T) {
	got := PrintPath("/")
	if got == "" {
		t.Error("PrintPath(/) returned empty")
	}
	got = PrintPath("/documents/photos")
	if got == "" {
		t.Error("PrintPath returned empty for nested path")
	}
}

func TestQuietMode(t *testing.T) {
	SetQuiet(true)
	defer SetQuiet(false)

	bar := NewProgressBar(100, "test")
	bar.Set64(50)
	bar.Finish()
}

func ptr(v int64) *int64      { return &v }
func strPtr(s string) *string { return &s }
