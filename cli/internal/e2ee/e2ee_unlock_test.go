package e2ee

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/term"
	"pigcloud/internal/agent"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

const (
	testKDFOps uint32 = 1
	testKDFMem uint32 = 8 * 1024 * 1024
)

type keyFixture struct {
	pub      *crypto.PublicKeySet
	priv     *crypto.PrivateKeySet
	signPub  *crypto.SigningPublicKeySet
	signPriv *crypto.SigningPrivateKeySet
	nameKey  []byte
	password []byte
	salt     []byte
	pdk      []byte
}

func newKeyFixture(t *testing.T) *keyFixture {
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
		t.Fatalf("derive name key: %v", err)
	}
	salt := randKey(t, crypto.SaltSize)
	password := []byte("correct horse battery staple")
	return &keyFixture{
		pub:      pub,
		priv:     priv,
		signPub:  signPub,
		signPriv: signPriv,
		nameKey:  nameKey,
		password: password,
		salt:     salt,
		pdk:      crypto.DeriveKey(password, salt, testKDFOps, testKDFMem),
	}
}

func (f *keyFixture) install(t *testing.T) {
	t.Helper()
	enc, err := crypto.EncryptHybridPrivateKeyWithKey(f.priv, f.pdk)
	if err != nil {
		t.Fatalf("wrap encryption keys: %v", err)
	}
	sign, err := crypto.EncryptSigningPrivateKeysWithKey(f.signPriv, f.pdk)
	if err != nil {
		t.Fatalf("wrap signing keys: %v", err)
	}
	c := config.Get()
	c.PublicKey = b64(f.pub.X25519[:])
	c.PublicKeyKyber = b64(f.pub.Kyber)
	c.EncryptedPrivateKey = b64(enc.X25519Ciphertext)
	c.PrivateKeyNonce = b64(enc.X25519Nonce)
	c.EncryptedPrivateKeyKyber = b64(enc.KyberCiphertext)
	c.PrivateKeyKyberNonce = b64(enc.KyberNonce)
	c.KDFSalt = b64(f.salt)
	c.KDFOpsLimit = testKDFOps
	c.KDFMemLimit = testKDFMem
	c.SigningPublicKeyEd25519 = b64(f.signPub.Ed25519[:])
	c.SigningPublicKeyMldsa = b64(f.signPub.Mldsa)
	c.EncryptedSigningPrivateKeyEd25519 = b64(sign.Ed25519Ciphertext)
	c.SigningPrivateKeyEd25519Nonce = b64(sign.Ed25519Nonce)
	c.EncryptedSigningPrivateKeyMldsa = b64(sign.MldsaCiphertext)
	c.SigningPrivateKeyMldsaNonce = b64(sign.MldsaNonce)
	c.E2EEStorageMode = ""
}

func (f *keyFixture) installEncryptionOnly(t *testing.T) {
	t.Helper()
	f.install(t)
	c := config.Get()
	c.SigningPublicKeyEd25519 = ""
	c.SigningPublicKeyMldsa = ""
	c.EncryptedSigningPrivateKeyEd25519 = ""
	c.EncryptedSigningPrivateKeyMldsa = ""
}

func isolateKeyEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	origCfg := config.GetConfigPath()
	config.SetConfigFile(filepath.Join(dir, "pigcloud", "config.json"))
	config.Load()

	origStdin := os.Stdin
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	os.Stdin = devnull

	resetKeyCaches()
	suppliedPassword = nil

	t.Cleanup(func() {
		resetKeyCaches()
		suppliedPassword = nil
		os.Stdin = origStdin
		devnull.Close()
		config.SetConfigFile(origCfg)
		config.Load()
	})
}

func resetKeyCaches() {
	cachedPub = nil
	cachedPriv = nil
	cachedNameKey = nil
	cachedSigningPub = nil
	cachedSigningPriv = nil
	cachedTeeEnclaveKeySet = nil
}

func requireNonInteractiveStdin(t *testing.T) {
	t.Helper()
	if term.IsTerminal(int(syscall.Stdin)) {
		t.Skip("fd 0 is a terminal; the password prompt would block")
	}
}

func assertNoKeyState(t *testing.T, where string) {
	t.Helper()
	if cachedPub != nil {
		t.Errorf("%s: cachedPub populated after a failed unlock", where)
	}
	if cachedPriv != nil {
		t.Errorf("%s: cachedPriv populated after a failed unlock", where)
	}
	if cachedNameKey != nil {
		t.Errorf("%s: cachedNameKey populated after a failed unlock", where)
	}
	if cachedSigningPub != nil || cachedSigningPriv != nil {
		t.Errorf("%s: signing cache populated after a failed unlock", where)
	}
}

func TestGetKeyPairWithoutConfiguredKeysReturnsNoMaterial(t *testing.T) {
	isolateKeyEnv(t)

	exits := 0
	pub, priv := GetKeyPair(func() { exits++ })

	if pub != nil || priv != nil {
		t.Fatalf("unconfigured account produced key material (pub set=%v, priv set=%v)", pub != nil, priv != nil)
	}
	if exits == 0 {
		t.Fatal("GetKeyPair never signalled failure to the caller")
	}
	assertNoKeyState(t, "unconfigured")
}

func TestGetKeyPairRejectsMalformedPublicKey(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"x25519 not base64", func(c *config.Config) { c.PublicKey = "!!!not base64!!!" }},
		{"x25519 one byte short", func(c *config.Config) { c.PublicKey = b64(make([]byte, 31)) }},
		{"x25519 one byte long", func(c *config.Config) { c.PublicKey = b64(make([]byte, 33)) }},
		{"kyber not base64", func(c *config.Config) { c.PublicKeyKyber = "!!!not base64!!!" }},
		{"kyber one byte short", func(c *config.Config) {
			c.PublicKeyKyber = b64(make([]byte, crypto.KyberPublicKeySize-1))
		}},
		{"kyber one byte long", func(c *config.Config) {
			c.PublicKeyKyber = b64(make([]byte, crypto.KyberPublicKeySize+1))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			f := newKeyFixture(t)
			f.install(t)
			tc.mutate(config.Get())

			SetSuppliedPassword(append([]byte(nil), f.password...))

			exits := 0
			pub, priv := GetKeyPair(func() { exits++ })

			if pub != nil || priv != nil {
				t.Fatalf("malformed public key produced key material (pub set=%v, priv set=%v)", pub != nil, priv != nil)
			}
			if exits == 0 {
				t.Fatal("GetKeyPair never signalled failure to the caller")
			}
			if suppliedPassword == nil {
				t.Error("password was consumed before the public key was validated")
			}
			assertNoKeyState(t, tc.name)
		})
	}
}

func TestGetKeyPairWrongPasswordLeavesNoKeyMaterial(t *testing.T) {
	isolateKeyEnv(t)
	requireNonInteractiveStdin(t)
	f := newKeyFixture(t)
	f.install(t)

	SetSuppliedPassword([]byte("not the password"))
	exits := 0
	pub, priv := GetKeyPair(func() { exits++ })

	if pub != nil || priv != nil {
		t.Fatalf("wrong password produced key material (pub set=%v, priv set=%v)", pub != nil, priv != nil)
	}
	if exits == 0 {
		t.Fatal("GetKeyPair never signalled failure to the caller")
	}
	assertNoKeyState(t, "wrong password")

	if nk := GetNameKey(func() {}); nk != nil {
		t.Fatalf("GetNameKey returned %d bytes after a failed unlock", len(nk))
	}
}

func TestGetKeyPairRejectsCorruptWrappedKeys(t *testing.T) {
	flipLast := func(s string) string {
		raw, err := decodeB64Required(s, "blob")
		if err != nil {
			panic(err)
		}
		raw[len(raw)-1] ^= 0x01
		return b64(raw)
	}
	dropLast := func(s string) string {
		raw, err := decodeB64Required(s, "blob")
		if err != nil {
			panic(err)
		}
		return b64(raw[:len(raw)-1])
	}

	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"x25519 ciphertext bit flipped", func(c *config.Config) {
			c.EncryptedPrivateKey = flipLast(c.EncryptedPrivateKey)
		}},
		{"kyber ciphertext bit flipped", func(c *config.Config) {
			c.EncryptedPrivateKeyKyber = flipLast(c.EncryptedPrivateKeyKyber)
		}},
		{"x25519 ciphertext truncated", func(c *config.Config) {
			c.EncryptedPrivateKey = dropLast(c.EncryptedPrivateKey)
		}},
		{"kyber ciphertext truncated", func(c *config.Config) {
			c.EncryptedPrivateKeyKyber = dropLast(c.EncryptedPrivateKeyKyber)
		}},
		{"x25519 ciphertext emptied", func(c *config.Config) {
			c.EncryptedPrivateKey = b64(nil)
		}},
		{"kdf salt replaced", func(c *config.Config) {
			c.KDFSalt = b64(make([]byte, crypto.SaltSize))
		}},
		{"kdf salt not base64", func(c *config.Config) { c.KDFSalt = "!!!not base64!!!" }},
		{"kdf ops limit changed", func(c *config.Config) { c.KDFOpsLimit = testKDFOps + 1 }},
		{"encrypted blob not base64", func(c *config.Config) {
			c.EncryptedPrivateKey = "!!!not base64!!!"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			f := newKeyFixture(t)
			f.install(t)
			tc.mutate(config.Get())

			SetSuppliedPassword(append([]byte(nil), f.password...))
			exits := 0
			pub, priv := GetKeyPair(func() { exits++ })

			if pub != nil || priv != nil {
				t.Fatalf("corrupt key material produced key material (pub set=%v, priv set=%v)", pub != nil, priv != nil)
			}
			if exits == 0 {
				t.Fatal("GetKeyPair never signalled failure to the caller")
			}
			assertNoKeyState(t, tc.name)
		})
	}
}

func TestGetKeyPairUnlocksAndCachesUsableKeys(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	SetSuppliedPassword(append([]byte(nil), f.password...))
	exits := 0
	pub, priv := GetKeyPair(func() { exits++ })

	if exits != 0 {
		t.Fatalf("correct password still signalled failure %d time(s)", exits)
	}
	if pub == nil || priv == nil {
		t.Fatal("correct password returned no key material")
	}
	if pub.X25519 != f.pub.X25519 || !bytes.Equal(pub.Kyber, f.pub.Kyber) {
		t.Error("returned public key set does not match the configured one")
	}
	if priv.X25519 != f.priv.X25519 || !bytes.Equal(priv.Kyber, f.priv.Kyber) {
		t.Error("returned private key set does not match the wrapped one")
	}

	sealed, err := crypto.SealDataKey(f.nameKey, pub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	opened, err := crypto.UnsealDataKey(sealed, priv)
	if err != nil {
		t.Fatalf("unlocked private key cannot open a blob sealed to its own public key: %v", err)
	}
	if !bytes.Equal(opened, f.nameKey) {
		t.Error("unsealed plaintext differs from what was sealed")
	}

	if cachedSigningPub == nil || cachedSigningPriv == nil {
		t.Fatal("password unlock did not hydrate the signing key cache")
	}
	if cachedSigningPub.Ed25519 != f.signPub.Ed25519 {
		t.Error("hydrated signing public key does not match the configured one")
	}

	if suppliedPassword != nil {
		t.Error("supplied password was not consumed")
	}
}

func TestGetKeyPairDeviceWrappedWithoutKeychainNeverFallsBackToPassword(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)
	config.Get().E2EEStorageMode = "device"

	SetSuppliedPassword(append([]byte(nil), f.password...))
	exits := 0
	pub, priv := GetKeyPair(func() { exits++ })

	if pub != nil || priv != nil {
		t.Fatalf("device-wrapped keys unlocked without the keychain (pub set=%v, priv set=%v)", pub != nil, priv != nil)
	}
	if exits == 0 {
		t.Fatal("GetKeyPair never signalled failure to the caller")
	}
	if suppliedPassword == nil {
		t.Error("device-wrapped path consumed a password; it must fail closed instead")
	}
	assertNoKeyState(t, "device-wrapped without keychain")
}

func startTestAgent(t *testing.T, km *agent.KeyMaterial, ttl time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = agent.Serve(km, ttl)
	}()

	t.Cleanup(func() {
		_ = agent.Shutdown()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("test agent did not stop")
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for !agent.Ping() {
		if time.Now().After(deadline) {
			t.Fatal("test agent never came up")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (f *keyFixture) agentMaterial() *agent.KeyMaterial {
	return &agent.KeyMaterial{
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

func TestGetKeyPairServedByAgentNeverPrompts(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)
	startTestAgent(t, f.agentMaterial(), time.Minute)

	SetSuppliedPassword([]byte("this password must never be read"))
	exits := 0
	pub, priv := GetKeyPair(func() { exits++ })

	if exits != 0 {
		t.Fatalf("agent-served unlock signalled failure %d time(s)", exits)
	}
	if pub == nil || priv == nil {
		t.Fatal("running agent produced no key material")
	}
	if suppliedPassword == nil {
		t.Error("agent path consumed a password; the agent exists to avoid that")
	}
	if priv.X25519 != f.priv.X25519 || !bytes.Equal(priv.Kyber, f.priv.Kyber) {
		t.Error("agent-served private key does not match the unlocked account")
	}
	if !bytes.Equal(cachedNameKey, f.nameKey) {
		t.Error("agent-served name key does not match the account's derived name key")
	}
	if cachedSigningPub == nil || cachedSigningPriv == nil {
		t.Fatal("agent served signing keys but they were not cached")
	}
	if cachedSigningPub.Ed25519 != f.signPub.Ed25519 {
		t.Error("agent-served signing public key does not match the account's")
	}
}

func TestAgentServingShortNameKeyIsRefusedWholesale(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	km := f.agentMaterial()
	km.NameKey = km.NameKey[:crypto.NameKeySize-1]
	startTestAgent(t, km, time.Minute)

	if EnsureKeysFromAgent() {
		t.Fatal("agent material with a short name key was accepted")
	}
	if cachedNameKey != nil {
		t.Errorf("a %d-byte name key reached the cache; path tokens would silently diverge", len(cachedNameKey))
	}
	if cachedPriv != nil || cachedPub != nil {
		t.Error("encryption keys were cached from a payload that failed validation")
	}
}

func TestAgentServingFullNameKeyIsAccepted(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)
	startTestAgent(t, f.agentMaterial(), time.Minute)

	if !EnsureKeysFromAgent() {
		t.Fatal("well-formed agent material was refused")
	}
	if len(cachedNameKey) != crypto.NameKeySize {
		t.Fatalf("cached name key is %d bytes, want %d", len(cachedNameKey), crypto.NameKeySize)
	}
	want, err := crypto.DeriveNameKey(f.priv)
	if err != nil {
		t.Fatalf("derive name key: %v", err)
	}
	if !bytes.Equal(cachedNameKey, want) {
		t.Error("cached name key is not the one derived from the account private key")
	}
}

func TestAgentServingPartialSigningKeysLeavesSigningLocked(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	km := f.agentMaterial()
	km.SigningPrivateKeyMldsa = km.SigningPrivateKeyMldsa[:crypto.Mldsa44SKSize-1]
	startTestAgent(t, km, time.Minute)

	if !EnsureKeysFromAgent() {
		t.Fatal("encryption keys should still be usable when only signing keys are malformed")
	}
	if cachedSigningPub != nil || cachedSigningPriv != nil {
		t.Fatal("a partial signing key set was cached; signing would produce unverifiable output")
	}

	exits := 0
	signPub, signPriv := GetSigningKeys(func() { exits++ })
	if signPub != nil || signPriv != nil {
		t.Fatal("GetSigningKeys handed back keys it never unlocked")
	}
	if exits == 0 {
		t.Fatal("GetSigningKeys never signalled failure to the caller")
	}
}

func TestExpiredAgentFileFallsBackInsteadOfServingEmptyKeys(t *testing.T) {
	isolateKeyEnv(t)
	requireNonInteractiveStdin(t)
	f := newKeyFixture(t)
	f.install(t)

	agentPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "pigcloud", "agent.json")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stale, err := json.Marshal(agent.AgentInfo{
		Port:    1,
		Token:   "deadbeef",
		PID:     os.Getpid(),
		Expires: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal agent info: %v", err)
	}
	if err := os.WriteFile(agentPath, stale, 0600); err != nil {
		t.Fatalf("write agent file: %v", err)
	}

	if EnsureKeysFromAgent() {
		t.Fatal("an expired agent file was treated as a live agent")
	}
	assertNoKeyState(t, "expired agent")

	exits := 0
	pub, priv := GetKeyPair(func() { exits++ })
	if pub != nil || priv != nil {
		t.Fatalf("expired agent path produced key material (pub set=%v, priv set=%v)", pub != nil, priv != nil)
	}
	if exits == 0 {
		t.Fatal("GetKeyPair never signalled failure to the caller")
	}
	assertNoKeyState(t, "expired agent after fallback")
}

func TestUnreachableAgentFallsBackInsteadOfServingEmptyKeys(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	agentPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "pigcloud", "agent.json")
	if err := os.MkdirAll(filepath.Dir(agentPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	live, err := json.Marshal(agent.AgentInfo{
		Port:    1,
		Token:   "deadbeef",
		PID:     os.Getpid(),
		Expires: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("marshal agent info: %v", err)
	}
	if err := os.WriteFile(agentPath, live, 0600); err != nil {
		t.Fatalf("write agent file: %v", err)
	}

	if EnsureKeysFromAgent() {
		t.Fatal("an unreachable agent was treated as a live agent")
	}
	assertNoKeyState(t, "unreachable agent")

	SetSuppliedPassword(append([]byte(nil), f.password...))
	pub, priv := GetKeyPair(func() { t.Error("password fallback signalled failure") })
	if pub == nil || priv == nil {
		t.Fatal("password fallback produced no key material after an unreachable agent")
	}
	if priv.X25519 != f.priv.X25519 {
		t.Error("password fallback returned the wrong private key")
	}
}

func TestHydrateSigningFromAgentRequiresAllFourKeys(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	resetKeyCaches()
	hydrateSigningFromAgent(f.agentMaterial())
	if cachedSigningPub == nil || cachedSigningPriv == nil {
		t.Fatal("a complete signing key set was not cached")
	}
	payload := randKey(t, 512)
	sigEd, sigMl, err := crypto.SignFileBytes(bytes.NewReader(payload), cachedSigningPriv)
	if err != nil {
		t.Fatalf("sign with cached key: %v", err)
	}
	if err := crypto.VerifyFileSignatures(bytes.NewReader(payload), sigEd, sigMl, cachedSigningPub); err != nil {
		t.Fatalf("cached signing pair does not verify its own signature: %v", err)
	}

	truncations := []struct {
		name   string
		damage func(*agent.KeyMaterial)
	}{
		{"ed25519 public short", func(k *agent.KeyMaterial) {
			k.SigningPublicKeyEd25519 = k.SigningPublicKeyEd25519[:crypto.Ed25519PKSize-1]
		}},
		{"ed25519 private short", func(k *agent.KeyMaterial) {
			k.SigningPrivateKeyEd25519 = k.SigningPrivateKeyEd25519[:crypto.Ed25519SKSize-1]
		}},
		{"mldsa public short", func(k *agent.KeyMaterial) {
			k.SigningPublicKeyMldsa = k.SigningPublicKeyMldsa[:crypto.Mldsa44PKSize-1]
		}},
		{"mldsa private short", func(k *agent.KeyMaterial) {
			k.SigningPrivateKeyMldsa = k.SigningPrivateKeyMldsa[:crypto.Mldsa44SKSize-1]
		}},
		{"ed25519 public absent", func(k *agent.KeyMaterial) { k.SigningPublicKeyEd25519 = nil }},
		{"mldsa private absent", func(k *agent.KeyMaterial) { k.SigningPrivateKeyMldsa = nil }},
	}

	for _, tc := range truncations {
		t.Run(tc.name, func(t *testing.T) {
			resetKeyCaches()
			km := f.agentMaterial()
			tc.damage(km)
			hydrateSigningFromAgent(km)
			if cachedSigningPub != nil || cachedSigningPriv != nil {
				t.Fatal("partial signing material was cached; signing would emit unverifiable output")
			}
		})
	}

	t.Run("nil material", func(t *testing.T) {
		resetKeyCaches()
		hydrateSigningFromAgent(nil)
		if cachedSigningPub != nil || cachedSigningPriv != nil {
			t.Fatal("nil agent material populated the signing cache")
		}
	})
}

func TestHydrateSigningFromConfigRejectsWrongPDKAndMalformedFields(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*config.Config)
		wrongPDK bool
	}{
		{"wrong pdk", nil, true},
		{"ed25519 public one byte short", func(c *config.Config) {
			c.SigningPublicKeyEd25519 = b64(make([]byte, crypto.Ed25519PKSize-1))
		}, false},
		{"mldsa public one byte long", func(c *config.Config) {
			c.SigningPublicKeyMldsa = b64(make([]byte, crypto.Mldsa44PKSize+1))
		}, false},
		{"ed25519 nonce not base64", func(c *config.Config) {
			c.SigningPrivateKeyEd25519Nonce = "!!!not base64!!!"
		}, false},
		{"mldsa ciphertext bit flipped", func(c *config.Config) {
			raw, err := decodeB64Required(c.EncryptedSigningPrivateKeyMldsa, "blob")
			if err != nil {
				panic(err)
			}
			raw[0] ^= 0x01
			c.EncryptedSigningPrivateKeyMldsa = b64(raw)
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			f := newKeyFixture(t)
			f.install(t)
			if tc.mutate != nil {
				tc.mutate(config.Get())
			}
			pdk := f.pdk
			if tc.wrongPDK {
				pdk = randKey(t, crypto.KeySize)
			}

			resetKeyCaches()
			hydrateSigningFromConfigWithPDK(config.Get(), pdk)

			if cachedSigningPub != nil || cachedSigningPriv != nil {
				t.Fatal("signing keys were cached from material that should not unwrap")
			}
		})
	}
}

func TestGetSigningKeysRefusesWhenConfigHasNone(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.installEncryptionOnly(t)

	SetSuppliedPassword(append([]byte(nil), f.password...))
	exits := 0
	signPub, signPriv := GetSigningKeys(func() { exits++ })

	if signPub != nil || signPriv != nil {
		t.Fatal("GetSigningKeys returned keys for an account that has none")
	}
	if exits == 0 {
		t.Fatal("GetSigningKeys never signalled failure to the caller")
	}
	if pub, priv := GetSigningKeysIfAvailable(func() {
		t.Error("GetSigningKeysIfAvailable signalled failure for a legitimately keyless account")
	}); pub != nil || priv != nil {
		t.Fatal("GetSigningKeysIfAvailable invented keys")
	}
}

func TestClearCachedKeyZeroesSecretsAndDropsCaches(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.install(t)

	SetSuppliedPassword(append([]byte(nil), f.password...))
	if _, priv := GetKeyPair(func() { t.Fatal("unlock failed") }); priv == nil {
		t.Fatal("unlock produced no key material")
	}
	if GetNameKey(func() { t.Fatal("name key derivation failed") }) == nil {
		t.Fatal("no name key after unlock")
	}

	kyberSeed := cachedPriv.Kyber
	nameKey := cachedNameKey
	mldsaSK := cachedSigningPriv.Mldsa

	ClearCachedKey()

	if cachedPub != nil || cachedPriv != nil || cachedNameKey != nil {
		t.Error("ClearCachedKey left encryption state behind")
	}
	if cachedSigningPub != nil || cachedSigningPriv != nil {
		t.Error("ClearCachedKey left signing state behind")
	}
	for _, buf := range []struct {
		name  string
		bytes []byte
	}{{"kyber seed", kyberSeed}, {"name key", nameKey}, {"mldsa secret key", mldsaSK}} {
		if !allZero(buf.bytes) {
			t.Errorf("%s still holds non-zero bytes after ClearCachedKey", buf.name)
		}
	}
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}
