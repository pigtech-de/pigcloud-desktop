package api

import (
	"testing"

	"pigcloud/internal/config"
)

func TestEndpointRemainsBoundToClientWhenConfigurationChanges(t *testing.T) {
	cfg := config.Get()
	original := cfg.Endpoint
	t.Cleanup(func() { cfg.Endpoint = original })
	cfg.Endpoint = "https://old.example/cloud/actions.php"
	client := NewClient()
	cfg.Endpoint = "https://pigcloud.de/cloud/actions.php"
	if got := client.Endpoint(); got != "https://old.example/cloud/actions.php" {
		t.Fatalf("running client changed origin with configuration: %q", got)
	}
}
