package keyringstore

import (
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestMain(m *testing.M) {
	keyring.MockInit()
	m.Run()
}

func TestSecretsRoundTripThroughTheKeychain(t *testing.T) {
	keyring.MockInit()
	store := New()

	const key = "pigcloud.de"
	const value = "pc_live_7f3a2b91"

	if _, ok := store.GetSecret(key); ok {
		t.Fatal("a fresh keychain served a secret nobody stored")
	}
	if !store.SetSecret(key, value) {
		t.Fatal("the mock keychain refused a well-formed write")
	}

	got, ok := store.GetSecret(key)
	if !ok || got != value {
		t.Fatalf("read back %q (ok=%v), want %q", got, ok, value)
	}

	raw, err := keyring.Get(Service, key)
	if err != nil {
		t.Fatalf("the entry is not filed under %q/%q: %v", Service, key, err)
	}
	if raw != value {
		t.Errorf("the keychain holds %q under the service name, want %q", raw, value)
	}

	store.DeleteSecret(key)
	if _, ok := store.GetSecret(key); ok {
		t.Error("the secret survived DeleteSecret")
	}
}

func TestAnEmptyValueIsRefusedRatherThanStored(t *testing.T) {
	keyring.MockInit()
	store := New()

	if store.SetSecret("pigcloud.de", "") {
		t.Error("an empty secret was reported as stored; the caller would blank its config copy")
	}
	if _, ok := store.GetSecret("pigcloud.de"); ok {
		t.Error("the empty write reached the keychain anyway")
	}
}

func TestAFailingKeychainRefusesInsteadOfPanicking(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	t.Cleanup(keyring.MockInit)
	store := New()

	if store.SetSecret("pigcloud.de", "pc_live_key") {
		t.Error("a failing keychain reported a successful write")
	}
	if _, ok := store.GetSecret("pigcloud.de"); ok {
		t.Error("a failing keychain served a secret")
	}
	store.DeleteSecret("pigcloud.de")
}

func TestDeletingAnAbsentEntryIsNotAnError(t *testing.T) {
	keyring.MockInit()
	New().DeleteSecret("never-written")
}
