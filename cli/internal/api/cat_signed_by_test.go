package api

import (
	"encoding/json"
	"testing"
)

func TestCatPayloadCarriesTheSignerToTheVerifier(t *testing.T) {
	var p CatPayload
	body := `{"path":"/a.txt","content":"","e2ee":true,"sealed_key":"sk","signed_by":"alice"}`
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal cat payload: %v", err)
	}
	if p.SignedBy != "alice" {
		t.Fatalf("CatPayload.SignedBy = %q, want alice: the server named the signer and the client dropped it", p.SignedBy)
	}
	if got := p.AsDownloadResult().SignedBy; got != "alice" {
		t.Fatalf("AsDownloadResult().SignedBy = %q, want alice: the peer pin cannot resolve an anchor it is not given", got)
	}
}
