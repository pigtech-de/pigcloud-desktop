package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAgentTokensComeFromCryptoRand(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "agent.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse agent.go: %v", err)
	}

	imported := make(map[string]bool, len(file.Imports))
	for _, imp := range file.Imports {
		path, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			t.Fatalf("unquote import %s: %v", imp.Path.Value, uerr)
		}
		imported[path] = true
	}

	if !imported["crypto/rand"] {
		t.Error("agent.go no longer imports crypto/rand; the agent bearer token must not come from a predictable source")
	}
	for _, weak := range []string{"math/rand", "math/rand/v2"} {
		if imported[weak] {
			t.Errorf("agent.go imports %s; a guessable token hands the decrypted keys to any local process", weak)
		}
	}
}

func TestAgentListensOnLoopbackLiteral(t *testing.T) {
	var files []string
	err := filepath.Walk("../..", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}

	found := 0
	for _, path := range files {
		found += checkListenAddrs(t, path)
	}

	if found < 2 {
		t.Fatalf("found %d net.Listen calls in the module; the agent and daemon.listenIPC both listen, so this guard is stale", found)
	}
}

func checkListenAddrs(t *testing.T, path string) int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	found := 0
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "net" || sel.Sel.Name != "Listen" {
			return true
		}
		found++

		where := fset.Position(call.Pos())
		if len(call.Args) != 2 {
			t.Errorf("%s: net.Listen takes %d arguments; cannot check the bind address", where, len(call.Args))
			return true
		}
		switch arg := call.Args[1].(type) {
		case *ast.BasicLit:
			addr, uerr := strconv.Unquote(arg.Value)
			if uerr != nil {
				t.Fatalf("%s: unquote %s: %v", where, arg.Value, uerr)
			}
			if !strings.HasPrefix(addr, "127.0.0.1:") {
				t.Errorf("%s: listens on %q; a non-loopback bind exposes the token-guarded IPC surface to the local network", where, addr)
			}
		case *ast.SelectorExpr:
			pkg, _ := arg.X.(*ast.Ident)
			if pkg == nil || pkg.Name != "netutil" || arg.Sel.Name != "LoopbackAny" {
				t.Errorf("%s: net.Listen address is neither a loopback literal nor netutil.LoopbackAny, so the loopback bind is no longer statically provable", where)
			}
		default:
			t.Errorf("%s: net.Listen address is not a string literal, so the loopback bind is no longer statically provable", where)
		}
		return true
	})
	return found
}
