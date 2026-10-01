package daemon

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestEveryDaemonRegistryEntryUsesItsTransferClientEndpoint(t *testing.T) {
	for _, source := range []string{"daemon.go", "sync_daemon.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), source, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			typeName, ok := literal.Type.(*ast.SelectorExpr)
			if !ok || typeName.Sel.Name != "MountInfo" {
				return true
			}
			found++
			bound := false
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := field.Key.(*ast.Ident)
				if !ok || key.Name != "Endpoint" {
					continue
				}
				call, ok := field.Value.(*ast.CallExpr)
				if !ok || len(call.Args) != 0 {
					continue
				}
				method, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || method.Sel.Name != "Endpoint" {
					continue
				}
				client, ok := method.X.(*ast.SelectorExpr)
				if !ok || client.Sel.Name != "client" {
					continue
				}
				runtime, ok := client.X.(*ast.Ident)
				bound = ok && runtime.Name == "rt"
			}
			if !bound {
				t.Errorf("%s registry identity is not bound to the running transfer client's endpoint", source)
			}
			return true
		})
		if found == 0 {
			t.Fatalf("%s has no inspected registry entry", source)
		}
	}
}
