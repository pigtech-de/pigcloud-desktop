package e2ee

import (
	"errors"
	"testing"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func backgroundMaterial(t *testing.T) *crypto.BackgroundKeyMaterial {
	t.Helper()
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("hybrid keygen: %v", err)
	}
	signPub, signPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("signing keygen: %v", err)
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("name key: %v", err)
	}
	parentKey, err := crypto.DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("parent key: %v", err)
	}
	return &crypto.BackgroundKeyMaterial{
		NameKey:     nameKey,
		ParentKey:   parentKey,
		SigningPriv: signPriv,
		SigningPub:  signPub,
		Pub:         pub,
	}
}

func emptyConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	config.SetSecretStore(config.NewMemorySecretStore())
	config.SetConfigFile(dir + "/config.json")
	config.Load()
	t.Cleanup(func() {
		config.SetConfigFile("")
		config.SetSecretStore(nil)
	})
}

func TestBackgroundSessionSealsNamesWithoutWrappedKeysInConfig(t *testing.T) {
	emptyConfig(t)
	if config.HasEncryptionKeys() {
		t.Fatal("this test needs a config with no wrapped private key")
	}

	s := NewSession(nil, nil)
	if err := s.UnlockBackground(backgroundMaterial(t)); err != nil {
		t.Fatalf("UnlockBackground: %v", err)
	}

	options := map[string]string{}
	if err := s.AddE2eeNameFields(options, "IMG_0001.jpg", "Camera Roll/IMG_0001.jpg"); err != nil {
		t.Fatalf("AddE2eeNameFields: %v", err)
	}
	if options["e2ee_display_name"] == "" {
		t.Error("a background upload sent no sealed display name")
	}
	if options["e2ee_path_token"] == "" {
		t.Error("a background upload sent no path token, so the server cannot place it")
	}
}

func TestBackgroundSessionSignsButRefusesDecryptionKeys(t *testing.T) {
	emptyConfig(t)
	s := NewSession(nil, nil)
	material := backgroundMaterial(t)
	if err := s.UnlockBackground(material); err != nil {
		t.Fatalf("UnlockBackground: %v", err)
	}

	signPub, signPriv, err := s.SigningKeys()
	if err != nil {
		t.Fatalf("SigningKeys: %v", err)
	}
	if signPub == nil || signPriv == nil {
		t.Fatal("a background session must be able to sign")
	}

	var fault *Fault
	_, _, err = s.KeyPair()
	if !errors.As(err, &fault) || fault != ErrBackgroundUploadOnly {
		t.Errorf("KeyPair on a background session must refuse with ErrBackgroundUploadOnly, got %v", err)
	}
}

func TestBackgroundSessionRefusesIncompleteMaterial(t *testing.T) {
	emptyConfig(t)
	s := NewSession(nil, nil)

	material := backgroundMaterial(t)
	material.NameKey = material.NameKey[:8]
	if err := s.UnlockBackground(material); err != ErrBackgroundKeysIncomplete {
		t.Errorf("a short name key must be refused, got %v", err)
	}
	if s.IsBackground() {
		t.Error("a refused unlock left the session marked background")
	}
}

func TestClearCachedKeyDropsBackgroundMode(t *testing.T) {
	emptyConfig(t)
	s := NewSession(nil, nil)
	if err := s.UnlockBackground(backgroundMaterial(t)); err != nil {
		t.Fatalf("UnlockBackground: %v", err)
	}
	s.ClearCachedKey()

	if s.IsBackground() {
		t.Error("ClearCachedKey left the session in background mode")
	}
	options := map[string]string{}
	if err := s.AddE2eeNameFields(options, "IMG_0001.jpg", "Camera Roll/IMG_0001.jpg"); err != nil {
		t.Fatalf("AddE2eeNameFields: %v", err)
	}
	if len(options) != 0 {
		t.Errorf("a cleared session still sealed names: %v", options)
	}
}
