package cmd

import (
	"strings"
	"testing"
)

func TestReadStdinPassword(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"plain newline", "hunter2\n", "hunter2"},
		{"crlf", "hunter2\r\n", "hunter2"},
		{"eof no newline", "hunter2", "hunter2"},
		{"empty input", "", ""},
		{"multiline takes first line", "hunter2\nignored\nalso\n", "hunter2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readStdinPassword(strings.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestReadStdinPasswordEmptyIsErrorForCaller(t *testing.T) {
	got, err := readStdinPassword(strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("bare newline should read as empty password, got %q", got)
	}
}
