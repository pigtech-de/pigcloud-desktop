package transfer

import (
	"errors"
	"strings"
	"testing"

	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount/cache"
)

func TestClassifyVerifyError(t *testing.T) {
	pin := &e2ee.PeerPinError{Reason: "owner_signing_pk_untrusted", Peer: "bob"}
	got := ClassifyVerifyError("Shared/report.pdf", pin)
	if cache.IsPermanent(got) {
		t.Error("a grantable peer pin was latched permanent")
	}
	if !strings.Contains(got.Error(), "Shared/report.pdf") || !strings.Contains(got.Error(), "bob") {
		t.Errorf("classification lost context: %v", got)
	}

	for _, err := range []error{
		errors.New("signature verification failed"),
		errors.New("owner_signing_pk_untrusted"),
		errors.New("file_signature_missing"),
	} {
		if !cache.IsPermanent(ClassifyVerifyError("x", err)) {
			t.Errorf("%v was not latched permanent", err)
		}
	}
}
