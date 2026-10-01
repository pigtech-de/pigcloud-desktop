package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestRemoteParentDirAlwaysNamesADirectory(t *testing.T) {
	cases := map[string]string{
		"/Backups/payload/a.txt": "/Backups/payload",
		"/a.txt":                 "/",
		"a.txt":                  "/",
		"":                       "/",
		"/":                      "/",
		"/deep/nest/ed/f.bin":    "/deep/nest/ed",
		"/with space/f.txt":      "/with space",
		"/ümlaut/dätei.txt":      "/ümlaut",
		"/trailing/dir/":         "/trailing/dir",
	}
	for in, want := range cases {
		if got := remoteParentDir(in); got != want {
			t.Errorf("remoteParentDir(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRemoteParentDirSplitsWithPathNotFilepath(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "ul.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ul.go: %v", err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == "remoteParentDir" {
			fn = d
			break
		}
	}
	if fn == nil {
		t.Fatal("remoteParentDir not found in ul.go; this guard stopped guarding")
	}

	calls := 0
	ast.Inspect(fn, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkg.Name == "filepath" {
			t.Errorf("remoteParentDir calls filepath.%s; remote paths are always slash-separated", sel.Sel.Name)
		}
		if pkg.Name == "path" {
			calls++
		}
		return true
	})
	if calls == 0 {
		t.Error("remoteParentDir no longer reaches the path package at all")
	}

	const in = `/Backups/a\b.txt`
	if got := remoteParentDir(in); got != "/Backups" {
		t.Errorf("remoteParentDir(%q) = %q; a backslash is a filename character remotely, not a separator", in, got)
	}
}

func TestRemoteParentDirPropertiesHoldOverRandomPaths(t *testing.T) {
	segments := []string{"a", "Backups", "2026", "with space", "ü", "f.txt"}
	for range 200 {
		parts := make([]string, 0, 5)
		for i := 0; i < 1+randInt(t, 5); i++ {
			parts = append(parts, segments[randInt(t, len(segments))])
		}
		in := "/" + strings.Join(parts, "/")

		got := remoteParentDir(in)
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("remoteParentDir(%q) = %q, must be absolute", in, got)
		}
		if got == in {
			t.Fatalf("remoteParentDir(%q) returned the input; the file path would resolve as a directory", in)
		}
		if !strings.HasPrefix(path.Clean(in), path.Clean(got)) {
			t.Fatalf("remoteParentDir(%q) = %q is not an ancestor", in, got)
		}
		if up := remoteParentDir(got); !strings.HasPrefix(up, "/") {
			t.Fatalf("remoteParentDir(%q) = %q escaped the root", got, up)
		}
	}
}

func TestCollectDirsReturnsEverySubdirectoryButNotTheRoot(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"a", "a/b", "a/b/c", "empty", "z"} {
		if err := os.MkdirAll(filepath.Join(root, rel), 0700); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "a/f.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := collectDirs(root)
	sort.Strings(got)
	want := []string{"a", "empty", "z", filepath.Join("a", "b"), filepath.Join("a", "b", "c")}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("collectDirs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	for _, d := range got {
		if d == "." || filepath.IsAbs(d) {
			t.Errorf("%q must be a root-relative path, not the root or an absolute path", d)
		}
	}
}

func TestCollectDirsOnAFlatDirectoryIsEmpty(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "only.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := collectDirs(root); len(got) != 0 {
		t.Errorf("a directory with only files has no subdirectories, got %v", got)
	}
	if got := collectDirs(filepath.Join(root, "absent")); len(got) != 0 {
		t.Errorf("a missing root must yield nothing, got %v", got)
	}
}

func TestCollectDirsListsParentsBeforeChildren(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"a/b/c/d", "x/y"} {
		if err := os.MkdirAll(filepath.Join(root, rel), 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	got := collectDirs(root)
	seen := map[string]int{}
	for i, d := range got {
		seen[d] = i
	}
	for d, idx := range seen {
		parent := filepath.Dir(d)
		if parent == "." {
			continue
		}
		pIdx, ok := seen[parent]
		if !ok {
			t.Errorf("%q listed without its parent %q", d, parent)
			continue
		}
		if pIdx > idx {
			t.Errorf("%q (index %d) precedes its parent %q (index %d): %v", d, idx, parent, pIdx, got)
		}
	}
}

func TestRelativePathFallsBackToTheBasename(t *testing.T) {
	base := filepath.Join("home", "u", "payload")
	if got := relativePath(base, filepath.Join(base, "sub", "f.txt")); got != filepath.Join("sub", "f.txt") {
		t.Errorf("relativePath = %q, want sub/f.txt", got)
	}
	if got := relativePath(base, base); got != "." {
		t.Errorf("relativePath of the base itself = %q, want .", got)
	}
	if got := relativePath("relative/base", string(filepath.Separator)+"absolute/f.txt"); got != "f.txt" {
		t.Errorf("unrelatable path = %q, want the basename f.txt", got)
	}
}

func TestApplyPreserveTimestampsAlwaysSendsSourceMtime(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(local, []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stat, err := os.Stat(local)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	opts := map[string]string{}
	applyPreserveTimestamps(opts, stat, local)
	if opts["source_mtime"] != strconv.FormatInt(stat.ModTime().Unix(), 10) {
		t.Errorf("source_mtime = %q, want the file's own mtime %d; the mount reports this field as st_mtime", opts["source_mtime"], stat.ModTime().Unix())
	}
	if _, ok := opts["captured_at"]; ok {
		t.Errorf("captured_at must only appear for files that carry one: %v", opts)
	}
}

func TestApplyPreserveTimestampsToleratesANilMap(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(local, []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stat, _ := os.Stat(local)
	applyPreserveTimestamps(nil, stat, local)
}
