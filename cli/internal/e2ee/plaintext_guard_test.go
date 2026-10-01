package e2ee

import (
	"errors"
	"testing"

	"pigcloud/internal/api"
)

func TestRequireEncryptedDownloadRefusesAServerPlaintextClaim(t *testing.T) {
	cases := []struct {
		name   string
		result *api.DownloadResult
		want   error
	}{
		{"encrypted body passes", &api.DownloadResult{E2EE: true}, nil},
		{"plaintext claim is refused", &api.DownloadResult{E2EE: false}, ErrPlaintextResponse},
		{
			"signatures alongside the claim do not launder it",
			&api.DownloadResult{E2EE: false, SealedKey: "AAAA", SignatureEd25519: "BBBB"},
			ErrPlaintextResponse,
		},
		{"missing metadata is refused", nil, ErrDownloadMetadataMissing},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RequireEncryptedDownload(tc.result)
			if !errors.Is(got, tc.want) {
				t.Fatalf("RequireEncryptedDownload = %v, want %v", got, tc.want)
			}
		})
	}
}
