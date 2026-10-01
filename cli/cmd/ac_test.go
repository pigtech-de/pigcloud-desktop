package cmd

import (
	"testing"

	"pigcloud/internal/api"
)

func TestUnwrapEventSealedShape(t *testing.T) {
	event := api.ActivityEvent{
		EventType: "",
		Detail:    `{"type":"file_uploaded","payload":"/photos/pig.png\ncli"}`,
	}
	unwrapEvent(&event)
	if event.EventType != "file_uploaded" {
		t.Fatalf("EventType = %q, want file_uploaded", event.EventType)
	}
	if event.Detail != "/photos/pig.png" {
		t.Fatalf("Detail = %q, want /photos/pig.png", event.Detail)
	}
}

func TestUnwrapEventLegacyPlainDetail(t *testing.T) {
	event := api.ActivityEvent{EventType: "login", Detail: "Firefox\nWindows"}
	unwrapEvent(&event)
	if event.EventType != "login" || event.Detail != "Firefox\nWindows" {
		t.Fatalf("legacy event mangled: %q %q", event.EventType, event.Detail)
	}
}

func TestStripActivityMetaTag(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/a.txt\ncli", "/a.txt"},
		{"/a.txt\ncli:abc123", "/a.txt"},
		{"/a.txt\nassistant", "/a.txt"},
		{"/a.txt\nalice", "/a.txt\nalice"},
		{"cliff.txt", "cliff.txt"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := stripActivityMetaTag(tt.in); got != tt.want {
			t.Errorf("stripActivityMetaTag(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResolveNodeRefsLegacyMkdir(t *testing.T) {
	if got := resolveNodeRefs("node:mkdir"); got != "" {
		t.Fatalf("node:mkdir placeholder = %q, want empty", got)
	}
	if got := resolveNodeRefs("plain detail"); got != "plain detail" {
		t.Fatalf("no-ref detail changed: %q", got)
	}
}
