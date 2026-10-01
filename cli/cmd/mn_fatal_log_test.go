package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func funcBody(t *testing.T, file, name string) string {
	t.Helper()

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", file, err)
	}

	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name || fn.Body == nil {
			continue
		}
		var out strings.Builder
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					out.WriteString(pkg.Name)
					out.WriteString(".")
					out.WriteString(sel.Sel.Name)
					out.WriteString("\n")
				}
			}
			return true
		})
		return out.String()
	}

	t.Fatalf("%s is not declared in %s; this guard would be vacuous", name, file)
	return ""
}

func TestTeardownRemovesTheFatalLogAndStopKeepsIt(t *testing.T) {
	const call = "mount.RemoveFatalLog"

	for _, site := range []struct{ file, fn string }{
		{"mn.go", "runMountClean"},
		{"lo.go", "runLogout"},
	} {
		if !strings.Contains(funcBody(t, site.file, site.fn), call) {
			t.Errorf("%s does not call %s. It clears the mount's other leftovers, so the fatal sink "+
				"is the one file that accumulates one per crashed mount and is never reclaimed",
				site.fn, call)
		}
	}

	if strings.Contains(funcBody(t, "mn.go", "stopEntry"), call) {
		t.Error("stopEntry deletes the fatal log. `mn stop` is the path a user takes after a daemon " +
			"died, and the start hint points them at exactly that file for the post-mortem")
	}
}
