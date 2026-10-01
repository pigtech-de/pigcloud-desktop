package cmd

import (
	"testing"

	"pigcloud/internal/config"
)

func TestBuildWebURL(t *testing.T) {
	endpoint := config.DefaultEndpoint
	base := config.DefaultBaseURL
	cases := []struct {
		name     string
		fragment string
		want     string
	}{
		{"node token", "!n085103e3111345c9856db4a074fee524", base + "/cloud/#!n085103e3111345c9856db4a074fee524"},
		{"plain path (non-E2EE)", "photos/2026", base + "/cloud/#photos/2026"},
		{"root", "", base + "/cloud/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildWebURL(endpoint, tc.fragment)
			if got != tc.want {
				t.Fatalf("buildWebURL(%q) = %q, want %q", tc.fragment, got, tc.want)
			}
		})
	}
}

func TestBuildWebURLBadEndpoint(t *testing.T) {
	got := buildWebURL("://not a url", "!nabc123ff")
	want := config.DefaultBaseURL + "/cloud/#!nabc123ff"
	if got != want {
		t.Fatalf("fallback = %q, want %q", got, want)
	}
}
