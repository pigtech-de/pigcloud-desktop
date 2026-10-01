package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	kyberPubLen  = 1184
	kyberSeedLen = 64
	nameKeyLen   = 32
	edPubLen     = 32
	edPrivLen    = 64
	mldsaPubLen  = 1312
	mldsaPrivLen = 2560
)

const fixtureToken = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return b
}

func testKeys(t *testing.T) *KeyMaterial {
	t.Helper()
	km := &KeyMaterial{
		KyberPublicKey:           randBytes(t, kyberPubLen),
		KyberSeed:                randBytes(t, kyberSeedLen),
		NameKey:                  randBytes(t, nameKeyLen),
		SigningPublicKeyEd25519:  randBytes(t, edPubLen),
		SigningPrivateKeyEd25519: randBytes(t, edPrivLen),
		SigningPublicKeyMldsa:    randBytes(t, mldsaPubLen),
		SigningPrivateKeyMldsa:   randBytes(t, mldsaPrivLen),
	}
	copy(km.PublicKey[:], randBytes(t, 32))
	copy(km.PrivateKey[:], randBytes(t, 32))
	return km
}

type convo struct {
	raw      json.RawMessage
	resp     Response
	timer    *time.Timer
	shutdown chan struct{}
}

func (c convo) shutdownFired(d time.Duration) bool {
	select {
	case <-c.shutdown:
		return true
	case <-time.After(d):
		return false
	}
}

func (c convo) timerStillArmed() bool {
	return c.timer.Stop()
}

func speak(t *testing.T, keys *KeyMaterial, token, payload string) convo {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })

	timer := time.NewTimer(time.Hour)
	t.Cleanup(func() { timer.Stop() })

	fired := make(chan struct{}, 1)
	shutdown := func(string) {
		select {
		case fired <- struct{}{}:
		default:
		}
	}

	go handleConn(server, newKeyGuard(keys), token, timer, shutdown)

	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(client, payload); err != nil {
		t.Fatalf("write request: %v", err)
	}

	var raw json.RawMessage
	if err := json.NewDecoder(client).Decode(&raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response %s: %v", raw, err)
	}
	return convo{raw: raw, resp: resp, timer: timer, shutdown: fired}
}

func assertNoKeyFields(t *testing.T, ctx string, resp Response) {
	t.Helper()
	v := reflect.ValueOf(resp)
	ty := v.Type()
	for i := 0; i < ty.NumField(); i++ {
		name := ty.Field(i).Name
		if name == "OK" || name == "Error" {
			continue
		}
		if v.Field(i).Kind() != reflect.String {
			t.Fatalf("Response.%s is %s, not a string; extend this guard", name, v.Field(i).Kind())
		}
		if n := len(v.Field(i).String()); n != 0 {
			t.Errorf("%s: Response.%s carried %d characters, want empty", ctx, name, n)
		}
	}
}

func assertNoKeyMaterial(t *testing.T, ctx string, raw []byte, keys *KeyMaterial) {
	t.Helper()
	material := []struct {
		label string
		b     []byte
	}{
		{"x25519 private key", keys.PrivateKey[:]},
		{"ml-kem seed", keys.KyberSeed},
		{"name key", keys.NameKey},
		{"ed25519 signing private key", keys.SigningPrivateKeyEd25519},
		{"ml-dsa signing private key", keys.SigningPrivateKeyMldsa},
		{"x25519 public key", keys.PublicKey[:]},
		{"ml-kem public key", keys.KyberPublicKey},
		{"ed25519 signing public key", keys.SigningPublicKeyEd25519},
		{"ml-dsa signing public key", keys.SigningPublicKeyMldsa},
	}
	for _, m := range material {
		if len(m.b) == 0 {
			continue
		}
		encodings := map[string][]byte{
			"hex":    []byte(hex.EncodeToString(m.b)),
			"base64": []byte(base64.StdEncoding.EncodeToString(m.b)),
			"raw":    m.b,
		}
		for enc, needle := range encodings {
			if bytes.Contains(raw, needle) {
				t.Errorf("%s: response leaked the %s as %s", ctx, m.label, enc)
			}
		}
	}
}

func TestHandleConnServesKeysOnlyForTheExactToken(t *testing.T) {
	keys := testKeys(t)

	rejected := []struct {
		name string
		body string
	}{
		{"token field absent", `{"action":"keys"}`},
		{"token is null", `{"token":null,"action":"keys"}`},
		{"empty token", `{"token":"","action":"keys"}`},
		{"different token of the same length", `{"token":"` + strings.Repeat("a", len(fixtureToken)) + `","action":"keys"}`},
		{"correct prefix, wrong final character", `{"token":"` + fixtureToken[:len(fixtureToken)-1] + `1","action":"keys"}`},
		{"correct token missing its last character", `{"token":"` + fixtureToken[:len(fixtureToken)-1] + `","action":"keys"}`},
		{"correct token with a character appended", `{"token":"` + fixtureToken + `0","action":"keys"}`},
		{"correct token, uppercased", `{"token":"` + strings.ToUpper(fixtureToken) + `","action":"keys"}`},
		{"correct token with surrounding whitespace", `{"token":" ` + fixtureToken + ` ","action":"keys"}`},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			c := speak(t, keys, fixtureToken, tc.body)
			if c.resp.OK {
				t.Errorf("agent accepted %s", tc.name)
			}
			if c.resp.Error != "unauthorized" {
				t.Errorf("error = %q, want %q", c.resp.Error, "unauthorized")
			}
			assertNoKeyFields(t, tc.name, c.resp)
			assertNoKeyMaterial(t, tc.name, c.raw, keys)
			if c.shutdownFired(200 * time.Millisecond) {
				t.Errorf("%s stopped the agent", tc.name)
			}
			if !c.timerStillArmed() {
				t.Errorf("%s disarmed the expiry timer", tc.name)
			}
		})
	}

	t.Run("exact token", func(t *testing.T) {
		c := speak(t, keys, fixtureToken, `{"token":"`+fixtureToken+`","action":"keys"}`)
		if !c.resp.OK {
			t.Fatalf("agent refused the correct token: %q", c.resp.Error)
		}

		want := map[string]string{
			"PublicKey":                hex.EncodeToString(keys.PublicKey[:]),
			"PrivateKey":               hex.EncodeToString(keys.PrivateKey[:]),
			"KyberPublicKey":           hex.EncodeToString(keys.KyberPublicKey),
			"KyberSeed":                hex.EncodeToString(keys.KyberSeed),
			"NameKey":                  hex.EncodeToString(keys.NameKey),
			"SigningPublicKeyEd25519":  hex.EncodeToString(keys.SigningPublicKeyEd25519),
			"SigningPrivateKeyEd25519": hex.EncodeToString(keys.SigningPrivateKeyEd25519),
			"SigningPublicKeyMldsa":    hex.EncodeToString(keys.SigningPublicKeyMldsa),
			"SigningPrivateKeyMldsa":   hex.EncodeToString(keys.SigningPrivateKeyMldsa),
		}

		v := reflect.ValueOf(c.resp)
		ty := v.Type()
		covered := 0
		for i := 0; i < ty.NumField(); i++ {
			name := ty.Field(i).Name
			if name == "OK" || name == "Error" {
				continue
			}
			covered++
			exp, ok := want[name]
			if !ok {
				t.Errorf("Response gained field %s; this test has no expectation for it", name)
				continue
			}
			if got := v.Field(i).String(); got != exp {
				t.Errorf("Response.%s served %d characters, want the %d-character fixture value", name, len(got), len(exp))
			}
		}
		if covered != len(want) {
			t.Errorf("checked %d key fields, expectations cover %d", covered, len(want))
		}
		if c.shutdownFired(200 * time.Millisecond) {
			t.Error("a keys request stopped the agent")
		}
		if !c.timerStillArmed() {
			t.Error("a keys request disarmed the expiry timer")
		}
	})
}

func TestHandleConnLeaksNoKeyMaterialOnNonKeyActions(t *testing.T) {
	keys := testKeys(t)

	cases := []struct {
		name      string
		body      string
		wantOK    bool
		wantError string
	}{
		{"ping", `{"token":"` + fixtureToken + `","action":"ping"}`, true, ""},
		{"missing action", `{"token":"` + fixtureToken + `"}`, false, "unknown action"},
		{"unknown action", `{"token":"` + fixtureToken + `","action":"dump"}`, false, "unknown action"},
		{"action case variant", `{"token":"` + fixtureToken + `","action":"KEYS"}`, false, "unknown action"},
		{"action with whitespace", `{"token":"` + fixtureToken + `","action":" keys"}`, false, "unknown action"},
		{"not json", `garbage`, false, "invalid request"},
		{"json array", `[1,2,3]`, false, "invalid request"},
		{"wrong token type", `{"token":42,"action":"keys"}`, false, "invalid request"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := speak(t, keys, fixtureToken, tc.body)
			if c.resp.OK != tc.wantOK {
				t.Errorf("ok = %v, want %v (error %q)", c.resp.OK, tc.wantOK, c.resp.Error)
			}
			if c.resp.Error != tc.wantError {
				t.Errorf("error = %q, want %q", c.resp.Error, tc.wantError)
			}
			assertNoKeyFields(t, tc.name, c.resp)
			assertNoKeyMaterial(t, tc.name, c.raw, keys)
		})
	}
}

func TestShutdownActionRequiresTheToken(t *testing.T) {
	keys := testKeys(t)

	bad := speak(t, keys, fixtureToken, `{"token":"`+strings.Repeat("b", len(fixtureToken))+`","action":"shutdown"}`)
	if bad.resp.OK {
		t.Error("agent accepted a shutdown request with a wrong token")
	}
	if bad.shutdownFired(400 * time.Millisecond) {
		t.Fatal("a request with a wrong token stopped the agent")
	}
	if !bad.timerStillArmed() {
		t.Error("a request with a wrong token disarmed the expiry timer")
	}

	good := speak(t, keys, fixtureToken, `{"token":"`+fixtureToken+`","action":"shutdown"}`)
	if !good.resp.OK {
		t.Fatalf("agent refused an authorized shutdown: %q", good.resp.Error)
	}
	assertNoKeyFields(t, "shutdown", good.resp)
	if !good.shutdownFired(3 * time.Second) {
		t.Error("an authorized shutdown did not stop the agent")
	}
	if good.timerStillArmed() {
		t.Error("shutdown left the expiry timer armed")
	}
}
