package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var pathPreambleExceptions = map[string]string{
	"pl.go runLinkCreate": "seals a link key over the request context between the token step and the request, and the helper owns that context",
}

var pathPreambleSteps = []string{
	"cmdutil.StartAuthed(ExitWithError)",
	"defer cancel()",
	"resolvedPath := cmdutil.ResolvePath(",
	`"source":`,
	`"mode":`,
	"cmdutil.AddPathTokensFor(",
	"cmdutil.ExecuteCommand[",
	"cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload)",
}

func TestSinglePathCommandsUseTheSharedPreamble(t *testing.T) {
	funcs := commandFuncBodies(t)

	var offenders []string
	for key, body := range funcs {
		if spellsWholePreamble(body) {
			offenders = append(offenders, key)
		}
	}
	sort.Strings(offenders)

	excused := make([]string, 0, len(pathPreambleExceptions))
	for key := range pathPreambleExceptions {
		excused = append(excused, key)
	}
	sort.Strings(excused)

	if strings.Join(offenders, "|") != strings.Join(excused, "|") {
		t.Errorf("the sites still spelling the single-path preamble by hand must equal the exception list exactly.\n"+
			"  hand-spelled: %s\n  excused:      %s\n"+
			"A site on the left only is one cmdutil.RunPathCommand should absorb; one on the right only is a stale exception.",
			strings.Join(offenders, ", "), strings.Join(excused, ", "))
	}
}

func spellsWholePreamble(body string) bool {
	for _, step := range pathPreambleSteps {
		if !strings.Contains(body, step) {
			return false
		}
	}
	return true
}

func commandFuncBodies(t *testing.T) map[string]string {
	t.Helper()
	bodies := map[string]string{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read cmd dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(filepath.Join(".", name))
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		file, parseErr := parser.ParseFile(fset, name, src, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			start := fset.Position(fn.Pos()).Offset
			end := fset.Position(fn.End()).Offset
			bodies[name+" "+funcKey(fn)] = string(src[start:end])
		}
	}
	return bodies
}

func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + exprText(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func exprText(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		return "*" + exprText(e.X)
	case *ast.Ident:
		return e.Name
	case *ast.IndexExpr:
		return exprText(e.X)
	case *ast.SelectorExpr:
		return exprText(e.X) + "." + e.Sel.Name
	default:
		return "?"
	}
}
