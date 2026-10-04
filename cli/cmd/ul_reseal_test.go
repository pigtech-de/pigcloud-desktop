package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
)

func stubTeeSealWentStale(t *testing.T, fn func(context.Context, error, *crypto.PublicKeySet) (bool, error)) {
	t.Helper()
	saved := teeSealWentStale
	teeSealWentStale = fn
	t.Cleanup(func() { teeSealWentStale = saved })
}

func sealedArtifacts(t *testing.T) *e2ee.UploadArtifacts {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sealed.bin")
	if err := os.WriteFile(path, []byte("ciphertext"), 0600); err != nil {
		t.Fatal(err)
	}
	return &e2ee.UploadArtifacts{EncryptedPath: path, TeeKeySet: &crypto.PublicKeySet{}}
}

func TestAStaleSealIsResentAtMostOnce(t *testing.T) {
	stubTeeSealWentStale(t, func(context.Context, error, *crypto.PublicKeySet) (bool, error) { return true, nil })
	first := sealedArtifacts(t)
	sends, reseals := 0, 0
	refused := &api.APIError{Code: api.StaleTeeSealCode, Message: "scanner unavailable"}

	live, _, err := sendResealingOnce(context.Background(), "a.txt", first, func() *e2ee.UploadArtifacts {
		reseals++
		return sealedArtifacts(t)
	}, func() (*api.Response, error) {
		sends++
		return nil, refused
	})

	if sends != 2 || reseals != 1 {
		t.Fatalf("sends = %d, reseals = %d; a signal that stays stale must earn exactly one resend", sends, reseals)
	}
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the second refusal", err)
	}
	if live == first {
		t.Fatal("the caller would clean up the first seal twice and leak the second")
	}
	if _, statErr := os.Stat(first.EncryptedPath); !os.IsNotExist(statErr) {
		t.Fatal("the superseded ciphertext was left on disk")
	}
}

func TestAPinRefusalOnTheRefetchFailsTheUploadWithoutAResend(t *testing.T) {
	stubTeeSealWentStale(t, func(context.Context, error, *crypto.PublicKeySet) (bool, error) {
		return false, errors.New("tee_enclave_pk_changed: moved")
	})
	sends, reseals := 0, 0
	_, resp, err := sendResealingOnce(context.Background(), "a.txt", sealedArtifacts(t), func() *e2ee.UploadArtifacts {
		reseals++
		return sealedArtifacts(t)
	}, func() (*api.Response, error) {
		sends++
		return nil, &api.APIError{Code: api.StaleTeeSealCode}
	})

	if sends != 1 || reseals != 0 {
		t.Fatalf("sends = %d, reseals = %d; a pin refusal must not reseal", sends, reseals)
	}
	if resp != nil || err == nil || !strings.Contains(err.Error(), "tee_enclave_pk_changed") {
		t.Fatalf("resp = %v, err = %v; want the pin refusal as the upload's failure", resp, err)
	}
}
