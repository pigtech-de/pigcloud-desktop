package cmdutil

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"path"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
)

type GlobMatch struct {
	ID   string
	Name string
	Path string
	Type string
}

func IsGlobArg(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func ExpandRemoteGlob(ctx context.Context, pattern string, exitFn func()) []GlobMatch {
	resolved := ResolvePath(pattern)
	parent := path.Dir(resolved)
	base := path.Base(resolved)
	if IsGlobArg(parent) {
		output.PrintError("Glob patterns are only supported in the last path segment: " + pattern)
		exitFn()
	}
	if !e2ee.EnsureNamesReadable() {
		exitFn()
	}
	matcher, err := CompileMatcher(base, MatchGlob, false)
	if err != nil {
		output.PrintError("Invalid pattern: " + err.Error())
		exitFn()
	}

	options := map[string]string{"source": parent, "all": "true", "limit": "1000"}
	e2ee.AddPathTokensFor(options, parent, e2ee.SelfAndParent, exitFn)
	_, payload := ExecuteCommand[api.ListPayload](ctx, "ls", options, exitFn)

	var matches []GlobMatch
	for i := range payload.Entries {
		entry := &payload.Entries[i]
		name := entry.Name
		if entry.E2EEDisplayName != "" {
			name = e2ee.DecryptE2EEName(entry.E2EEDisplayName)
		}
		if name == "" || name == "(encrypted)" || !matcher.MatchString(name) {
			continue
		}
		matches = append(matches, GlobMatch{ID: entry.ID, Name: name, Path: path.Join(parent, name), Type: entry.Type})
	}
	return matches
}

func ExpandPathArgs(ctx context.Context, args []string, exitFn func()) []string {
	var out []string
	for _, arg := range args {
		if !IsGlobArg(arg) {
			out = append(out, arg)
			continue
		}
		matches := ExpandRemoteGlob(ctx, arg, exitFn)
		if len(matches) == 0 {
			output.PrintWarning("No matches for pattern: " + arg)
			continue
		}
		for _, m := range matches {
			out = append(out, m.Path)
		}
	}
	return out
}

func ForEachExpandedPath(args []string, fn func(string), exitFn func()) {
	RequireLogin(exitFn)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	for _, p := range ExpandPathArgs(ctx, args, exitFn) {
		fn(p)
	}
}

func GlobMatchIDsJSON(matches []GlobMatch) string {
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.ID
	}
	encoded, _ := json.Marshal(ids)
	return string(encoded)
}
