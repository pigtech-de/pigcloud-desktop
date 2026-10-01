package completion

import (
	"context"
	"encoding/json"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/filetypes"
	"pigcloud/internal/tree"

	"github.com/spf13/cobra"
)

var (
	cache      = make(map[string]cacheEntry)
	cacheMutex sync.Mutex
	cacheTTL   = 10 * time.Second
)

type cacheEntry struct {
	entries   []api.ListEntry
	timestamp time.Time
}

func RemotePathCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if !config.IsLoggedIn() {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var dirPath, prefix string
	if toComplete == "" {
		dirPath = config.GetCwd()
		prefix = ""
	} else if toComplete == "/" {
		dirPath = "/"
		prefix = ""
	} else if strings.HasSuffix(toComplete, "/") {
		dirPath = toComplete
		prefix = ""
	} else {
		dirPath = path.Dir(toComplete)
		prefix = path.Base(toComplete)
	}

	if dirPath != "/" && !strings.HasPrefix(dirPath, "/") {
		dirPath = path.Join(config.GetCwd(), dirPath)
	}

	dirPath = path.Clean(dirPath)
	if dirPath == "." {
		dirPath = config.GetCwd()
	}

	entries := getDirectoryListing(dirPath)
	if entries == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var completions []string
	for _, entry := range entries {
		name := entry.Name
		if name == "" || name == "(encrypted)" {
			continue
		}
		if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			continue
		}

		var completionPath string
		if strings.HasPrefix(toComplete, "/") {
			completionPath = path.Join(dirPath, name)
		} else if toComplete == "" {
			completionPath = name
		} else if strings.Contains(toComplete, "/") {
			completionPath = path.Join(path.Dir(toComplete), name)
		} else {
			completionPath = name
		}

		if entry.Type == "directory" {
			completionPath += "/"
			completions = append(completions, completionPath+"\tdir")
		} else {
			ext := strings.TrimPrefix(filepath.Ext(name), ".")
			cat := filetypes.TypeOf(strings.ToLower(ext))
			if cat == "other" {
				completions = append(completions, completionPath)
			} else {
				completions = append(completions, completionPath+"\t"+cat)
			}
		}
	}

	return completions, cobra.ShellCompDirectiveNoSpace | cobra.ShellCompDirectiveNoFileComp
}

func getDirectoryListing(dirPath string) []api.ListEntry {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	if entry, ok := cache[dirPath]; ok {
		if time.Since(entry.timestamp) < cacheTTL {
			return entry.entries
		}
	}

	options := map[string]string{"source": dirPath}

	if e2ee.HasE2EEKeys() {
		trimmed := strings.TrimPrefix(dirPath, "/")
		var paths []string
		if trimmed != "" {
			paths = append(paths, trimmed)
			if parent := filepath.Dir(trimmed); parent != "." && parent != "" {
				paths = append(paths, parent)
			}
		}
		noExit := func() {}
		canonical, legacy := e2ee.ComputePathTokenMaps(paths, noExit)
		if canonical != "" {
			options["path_tokens"] = canonical
		}
		if legacy != "" {
			options["path_tokens_legacy"] = legacy
		}
	}

	client := api.NewClient()
	if e2ee.HasE2EEKeys() {
		addCompletionScope(options, dirPath)
	}
	resp, err := client.Execute(context.Background(), "ls", options)
	if err != nil || !resp.Success {
		return nil
	}

	var payload api.ListPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return nil
	}

	for i := range payload.Entries {
		entry := &payload.Entries[i]
		if entry.E2EEDisplayName != "" {
			entry.Name = e2ee.DecryptE2EEName(entry.E2EEDisplayName)
		}
	}

	cache[dirPath] = cacheEntry{
		entries:   payload.Entries,
		timestamp: time.Now(),
	}

	return payload.Entries
}

func addCompletionScope(options map[string]string, dirPath string) {
	noExit := func() {}
	_, priv := e2ee.GetKeyPair(noExit)
	if priv == nil {
		return
	}
	parentKey := e2ee.GetParentKey(noExit)
	if parentKey == nil {
		return
	}
	built, err := tree.Load(context.Background(), api.NewClient(), tree.Keys{Priv: priv, ParentKey: parentKey})
	if err != nil {
		return
	}
	parentID := ""
	if trimmed := strings.Trim(dirPath, "/"); trimmed != "" {
		node, err := built.Resolve(trimmed)
		if err != nil || node == nil || !node.IsDir {
			return
		}
		parentID = node.ID
	}
	ids := []string{}
	for _, child := range built.Children(parentID) {
		ids = append(ids, child.ID)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return
	}
	options["scope_node_ids"] = string(encoded)
}
