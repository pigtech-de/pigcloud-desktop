package e2ee

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

type fakeAgent struct {
	keys  *AgentKeys
	calls int
}

func (f *fakeAgent) Keys() *AgentKeys {
	f.calls++
	return f.keys
}

type fixedPrompter struct {
	password []byte
	calls    int
}

func (p *fixedPrompter) Password() ([]byte, error) {
	p.calls++
	if p.password == nil {
		return nil, nil
	}
	return append([]byte(nil), p.password...), nil
}

func (f *keyFixture) unlockedAgentKeys() *AgentKeys {
	return &AgentKeys{
		PublicKey:                f.pub.X25519,
		PrivateKey:               f.priv.X25519,
		KyberPublicKey:           append([]byte(nil), f.pub.Kyber...),
		KyberSeed:                append([]byte(nil), f.priv.Kyber...),
		NameKey:                  append([]byte(nil), f.nameKey...),
		SigningPublicKeyEd25519:  append([]byte(nil), f.signPub.Ed25519[:]...),
		SigningPrivateKeyEd25519: append([]byte(nil), f.signPriv.Ed25519...),
		SigningPublicKeyMldsa:    append([]byte(nil), f.signPub.Mldsa...),
		SigningPrivateKeyMldsa:   append([]byte(nil), f.signPriv.Mldsa...),
	}
}

func TestTwoSessionsShareNoKeyMaterial(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	unlocked := NewSession(&fakeAgent{keys: f.unlockedAgentKeys()}, nil)
	locked := NewSession(nil, nil)

	pub, priv, err := unlocked.KeyPair()
	if err != nil {
		t.Fatalf("agent-served session did not unlock: %v", err)
	}
	if priv.X25519 != f.priv.X25519 {
		t.Fatal("agent-served session returned the wrong private key")
	}

	if _, _, err := locked.KeyPair(); !errors.Is(err, ErrKeysLocked) {
		t.Fatalf("the second session unlocked off the first one's cache (err %v); a package global would do exactly that", err)
	}
	if locked.priv != nil || locked.nameKey != nil || locked.signingPriv != nil {
		t.Fatal("a session with no agent and no prompter still holds key material")
	}

	nameKey, err := unlocked.NameKey()
	if err != nil {
		t.Fatalf("name key from the agent-served session: %v", err)
	}
	if !bytes.Equal(nameKey, f.nameKey) {
		t.Fatal("agent-served session derived the wrong name key")
	}
	if pub == nil {
		t.Fatal("agent-served session returned no public key set")
	}

	unlocked.ClearCachedKey()
	if _, _, err := locked.KeyPair(); !errors.Is(err, ErrKeysLocked) {
		t.Fatalf("clearing one session changed the other's verdict (err %v)", err)
	}
}

func TestASecondSessionSeesNeitherTheSigningPinNorTheTeeMemos(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	first := NewSession(&fakeAgent{keys: f.unlockedAgentKeys()}, nil)
	second := NewSession(nil, nil)

	edPub, mlPub := first.resolveOwnSigningPubs()
	if len(edPub) == 0 || len(mlPub) == 0 {
		t.Fatal("the unlocked session resolved no own signing pubs; the assertions below would prove nothing")
	}
	if otherEd, otherMl := second.resolveOwnSigningPubs(); len(otherEd) != 0 || len(otherMl) != 0 {
		t.Error("a locked session resolved signing pubs off the first session's cache")
	}

	memo := &crypto.PublicKeySet{X25519: f.pub.X25519, Kyber: f.pub.Kyber}
	first.mu.Lock()
	first.teeEnclaveKeySet = memo
	first.teeEnclaveKeyRefusal = errors.New("refused earlier")
	first.mu.Unlock()

	if second.teeEnclaveKeySet != nil || second.TeeEnclaveKeyRefusal() != nil {
		t.Error("the second session already holds the first's TEE memos")
	}

	second.forgetTeeAttestationMemos()
	first.mu.Lock()
	survived := first.teeEnclaveKeySet
	refusal := first.teeEnclaveKeyRefusal
	first.mu.Unlock()
	if survived != memo {
		t.Error("forgetting one session's TEE memo cleared another session's")
	}
	if refusal == nil {
		t.Error("forgetting one session's refusal cleared another session's")
	}

	first.forgetTeeAttestationMemos()
	first.mu.Lock()
	defer first.mu.Unlock()
	if first.teeEnclaveKeySet != nil || first.teeEnclaveKeyRefusal != nil {
		t.Error("a session's own forget left its memos behind")
	}
}

func TestTheCacheSurvivesFourGoroutines(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	s := NewSession(&fakeAgent{keys: f.unlockedAgentKeys()}, nil)

	payload := filepath.Join(t.TempDir(), "ciphertext.bin")
	if err := os.WriteFile(payload, randKey(t, 4096), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
				s.ClearCachedKey()
			}
		}
	}()

	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 4 {
				if _, _, err := s.KeyPair(); err != nil {
					errs <- err
					return
				}
				if _, err := s.NameKey(); err != nil {
					errs <- err
					return
				}
				if _, err := s.ParentKey(); err != nil {
					errs <- err
					return
				}
				sigs, err := s.SignEncryptedFile(payload)
				if err != nil {
					errs <- err
					return
				}
				if err := verifyAgainst(payload, sigs, f.signPub); err != nil {
					errs <- err
					return
				}
				options := map[string]string{}
				if err := s.AddE2eeNameFields(options, "a.jpg", "Camera/a.jpg"); err != nil {
					errs <- err
					return
				}
				if err := s.AddPathTokensFor(options, "/Camera", SelfAndParent); err != nil {
					errs <- err
					return
				}
				s.resolveOwnSigningPubs()
				s.DecryptE2EEName("")
			}
		}()
	}
	workers.Wait()
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent key use failed: %v", err)
	}
}

func verifyAgainst(path string, sigs *UploadSignatures, want *crypto.SigningPublicKeySet) error {
	sigEd, err := base64.StdEncoding.DecodeString(sigs.SignatureEd25519B64)
	if err != nil {
		return err
	}
	sigMl, err := base64.StdEncoding.DecodeString(sigs.SignatureMldsaB64)
	if err != nil {
		return err
	}
	if sigs.SigningPkEd25519B64 != base64.StdEncoding.EncodeToString(want.Ed25519[:]) {
		return errors.New("the signature carries an Ed25519 public key that is not the account's")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return crypto.VerifyFileSignatures(f, sigEd, sigMl, want)
}

func TestRefusalsComeBackAsErrorsCarryingTheTerminalMessage(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T) *Session
		want    *Fault
		message string
	}{
		{
			name:    "no keys configured",
			message: "No encryption keys configured. Run 'pc li' to set up encryption.",
			setup: func(t *testing.T) *Session {
				isolateKeyEnv(t)
				return NewSession(nil, nil)
			},
			want: ErrNoEncryptionKeys,
		},
		{
			name:    "locked with no password source",
			message: "Keys are locked. Run 'pc uk' to unlock.",
			setup: func(t *testing.T) *Session {
				isolateKeyEnv(t)
				newKeyFixture(t).install(t)
				return NewSession(nil, &fixedPrompter{password: nil})
			},
			want: ErrKeysLocked,
		},
		{
			name:    "wrong password",
			message: "Wrong password",
			setup: func(t *testing.T) *Session {
				isolateKeyEnv(t)
				newKeyFixture(t).install(t)
				return NewSession(nil, &fixedPrompter{password: []byte("not the password")})
			},
			want: ErrWrongPassword,
		},
		{
			name:    "no signing keys",
			message: "Signing keys not configured for this account. Open the web app to complete E2EE setup.",
			setup: func(t *testing.T) *Session {
				isolateKeyEnv(t)
				f := newKeyFixture(t)
				f.installEncryptionOnly(t)
				return NewSession(&fakeAgent{keys: f.unlockedAgentKeys()}, nil)
			},
			want: ErrNoSigningKeys,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.setup(t)

			var err error
			if tc.want == ErrNoSigningKeys {
				_, _, err = s.SigningKeys()
			} else {
				_, _, err = s.KeyPair()
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got error %v, want %v", err, tc.want)
			}
			if err.Error() != tc.message {
				t.Errorf("Error() = %q, want the message the CLI printed before the seam (%q)", err.Error(), tc.message)
			}
		})
	}
}

var pinnedRefusalMessages = map[string]string{
	"ErrNoEncryptionKeys":     "No encryption keys configured. Run 'pc li' to set up encryption.",
	"ErrDeviceKeysLost":       "Encryption keys unavailable (device keychain locked or reset). Run 'pc login' again.",
	"ErrKeysLocked":           "Keys are locked. Run 'pc uk' to unlock.",
	"ErrWrongPassword":        "Wrong password",
	"ErrNoSigningKeys":        "Signing keys not configured for this account. Open the web app to complete E2EE setup.",
	"ErrSigningUnlockFailed":  "Failed to unlock signing keys. Re-run 'pc uk' to refresh, then retry.",
	"ErrScannerUnreachable":   "Security scanner is not reachable. Please try again shortly.",
	"ErrNoKeychainForDevice":  "no OS keychain available to hold the device key",
	"ErrScannerRefusedUpload": "Security scanner refused",
}

var pinnedFaultPrefixes = []string{
	"Failed to compute path token",
	"Failed to create temp file",
	"Failed to derive name key",
	"Failed to derive parent key",
	"Failed to encode encryption metadata",
	"Failed to encrypt file",
	"Failed to generate data key",
	"Failed to open encrypted file for signing",
	"Failed to read password",
	"Failed to seal data key",
	"Failed to seal data key to enclave",
	"Failed to seal display name",
	"Failed to sign encrypted file",
	"Invalid KDF salt in config",
	"Invalid encrypted key material in config",
	"Invalid public key in config",
}

func TestEverySentinelKeepsItsWording(t *testing.T) {
	live := map[string]*Fault{
		"ErrNoEncryptionKeys":     ErrNoEncryptionKeys,
		"ErrDeviceKeysLost":       ErrDeviceKeysLost,
		"ErrKeysLocked":           ErrKeysLocked,
		"ErrWrongPassword":        ErrWrongPassword,
		"ErrNoSigningKeys":        ErrNoSigningKeys,
		"ErrSigningUnlockFailed":  ErrSigningUnlockFailed,
		"ErrScannerUnreachable":   ErrScannerUnreachable,
		"ErrNoKeychainForDevice":  ErrNoKeychainForDevice,
		"ErrScannerRefusedUpload": ErrScannerRefusedUpload,
	}
	if len(live) != len(pinnedRefusalMessages) {
		t.Fatalf("the table covers %d sentinels and the package exports %d", len(pinnedRefusalMessages), len(live))
	}
	for name, want := range pinnedRefusalMessages {
		got, ok := live[name]
		if !ok {
			t.Errorf("%s is pinned but no longer exported", name)
			continue
		}
		if got.Error() != want {
			t.Errorf("%s reads %q, want %q", name, got.Error(), want)
		}
		if got.Unwrap() != nil {
			t.Errorf("%s carries a cause; a sentinel must be comparable", name)
		}
	}
}

func TestEveryFaultPrefixIsPinned(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var scanned int
	var found []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for _, m := range regexp.MustCompile(`fault\("([^"]*)"`).FindAllStringSubmatch(string(src), -1) {
			found = append(found, m[1])
		}
	}
	if scanned < 5 {
		t.Fatalf("the scan opened %d production files; the package is bigger than that", scanned)
	}
	if len(found) == 0 {
		t.Fatal("the scan found no fault() call sites; it would pass against an empty package")
	}
	slices.Sort(found)
	found = slices.Compact(found)

	want := slices.Clone(pinnedFaultPrefixes)
	slices.Sort(want)
	if !slices.Equal(found, want) {
		t.Errorf("fault() prefixes drifted from the pinned list.\n  in source: %q\n  pinned:    %q", found, want)
	}
}

func TestADecodeFailureKeepsItsCauseAndItsPrefix(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)
	config.Get().PublicKey = "!!!not base64!!!"

	_, _, err := NewSession(nil, nil).KeyPair()
	var refusal *Fault
	if !errors.As(err, &refusal) {
		t.Fatalf("got %T (%v), want a *Fault the CLI can print", err, err)
	}
	if refusal.Message != "Invalid public key in config" {
		t.Errorf("message = %q, want the pre-seam prefix", refusal.Message)
	}
	if refusal.Unwrap() == nil {
		t.Error("the decode cause was dropped; the user loses the reason")
	}
}
