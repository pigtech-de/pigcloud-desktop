package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/crypto"
)

func TestReadAgentFileRejectsAnUnusableRecord(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty object", `{}`},
		{"json null", `null`},
		{"port but no token", `{"port":4711}`},
		{"token but no port", `{"token":"` + fixtureToken + `"}`},
		{"empty token with a live expiry", `{"port":4711,"token":"","expires":"2099-01-01T00:00:00Z"}`},
		{"zero port with a live expiry", `{"port":0,"token":"` + fixtureToken + `","expires":"2099-01-01T00:00:00Z"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAgentDir(t)
			path := agentFilePath()
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			if got := ReadAgentFile(); got != nil {
				t.Errorf("ReadAgentFile accepted %s: port=%d token=%q expires=%v",
					tc.name, got.Port, got.Token, got.Expires)
			}
		})
	}
}

func TestReadAgentFileStillAcceptsAUsableRecord(t *testing.T) {
	isolateAgentDir(t)

	want := &AgentInfo{Port: 4711, Token: fixtureToken, PID: 99, Expires: time.Now().Add(time.Hour)}
	if err := writeAgentFile(want); err != nil {
		t.Fatalf("writeAgentFile: %v", err)
	}
	got := ReadAgentFile()
	if got == nil {
		t.Fatal("ReadAgentFile rejected a usable record; the rejections above prove nothing")
	}
	if got.Port != want.Port || got.Token != want.Token {
		t.Errorf("round-trip lost data: port=%d token=%q", got.Port, got.Token)
	}
}

func TestRequestKeysRejectsAWrongSizedNameKey(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*KeyMaterial)
	}{
		{"one byte short", func(k *KeyMaterial) { k.NameKey = k.NameKey[:crypto.NameKeySize-1] }},
		{"one byte long", func(k *KeyMaterial) { k.NameKey = append(k.NameKey, 0) }},
		{"absent", func(k *KeyMaterial) { k.NameKey = nil }},
		{"empty", func(k *KeyMaterial) { k.NameKey = []byte{} }},
		{"half length", func(k *KeyMaterial) { k.NameKey = k.NameKey[:crypto.NameKeySize/2] }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateAgentDir(t)
			keys := testKeys(t)
			tc.corrupt(keys)

			serveInBackground(t, keys, 30*time.Second)
			waitForAgent(t)

			if got := RequestKeys(); got != nil {
				t.Errorf("RequestKeys accepted a %d-byte name key, want exactly %d",
					len(got.NameKey), crypto.NameKeySize)
			}
		})
	}
}

func TestRequestKeysAcceptsTheExactNameKeyLength(t *testing.T) {
	isolateAgentDir(t)

	keys := testKeys(t)
	serveInBackground(t, keys, 30*time.Second)
	waitForAgent(t)

	got := RequestKeys()
	if got == nil {
		t.Fatal("RequestKeys refused a correctly sized name key; the rejections above prove nothing")
	}
	if len(got.NameKey) != crypto.NameKeySize {
		t.Errorf("name key = %d bytes, want %d", len(got.NameKey), crypto.NameKeySize)
	}
}

func TestAgentTokenIsComparedInConstantTime(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	var handler *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "handleConn" {
			handler = fn
		}
		return true
	})
	if handler == nil {
		t.Fatal("no handleConn in agent.go; this guard is stale and proves nothing")
	}

	constantTime := false
	ast.Inspect(handler, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "subtle" && sel.Sel.Name == "ConstantTimeCompare" {
			constantTime = true
		}
		return true
	})
	if !constantTime {
		t.Error("handleConn does not compare the token with subtle.ConstantTimeCompare")
	}

	ast.Inspect(handler, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.NEQ && bin.Op != token.EQL) {
			return true
		}
		if refersToToken(bin.X) && refersToToken(bin.Y) {
			t.Errorf("%s: token compared with %s; use subtle.ConstantTimeCompare",
				fset.Position(bin.Pos()), bin.Op)
		}
		return true
	})
}

func refersToToken(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "token"
	case *ast.SelectorExpr:
		return v.Sel.Name == "Token"
	}
	return false
}

func TestHandleConnTouchesKeyMaterialOnlyThroughTheGuard(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "agent.go", nil, 0)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	var handler *ast.FuncDecl
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if ok && fn.Name.Name == "handleConn" {
			handler = fn
		}
		return true
	})
	if handler == nil {
		t.Fatal("no handleConn in agent.go; this guard is stale and proves nothing")
	}

	banned := map[string]string{
		"mu":   "locks the guard directly instead of using its accessors",
		"keys": "reads guard key material directly, outside the lock",
	}
	ast.Inspect(handler, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok || id.Name != "guard" {
			return true
		}
		if why, bad := banned[sel.Sel.Name]; bad {
			t.Errorf("%s: handleConn %s (guard.%s)", fset.Position(sel.Pos()), why, sel.Sel.Name)
		}
		return true
	})

	if got := countHexEncodeCalls(handler); got != 0 {
		t.Errorf("handleConn hex-encodes key material directly in %d place(s); rendering belongs under the guard lock", got)
	}
}

func countHexEncodeCalls(fn *ast.FuncDecl) int {
	n := 0
	ast.Inspect(fn, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if ok && pkg.Name == "hex" && sel.Sel.Name == "EncodeToString" {
			n++
		}
		return true
	})
	return n
}
