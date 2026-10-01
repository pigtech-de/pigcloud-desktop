package filetypes

import (
	_ "embed"
	"encoding/json"
)

//go:embed file-types.json
var rawJSON []byte

type extEntry struct {
	Type string `json:"type"`
}

type registry struct {
	Extensions map[string]extEntry `json:"extensions"`
}

var typeMap map[string]string

func init() {
	var reg registry
	if err := json.Unmarshal(rawJSON, &reg); err != nil {
		panic("filetypes: failed to parse embedded file-types.json: " + err.Error())
	}
	typeMap = make(map[string]string, len(reg.Extensions))
	for ext, entry := range reg.Extensions {
		typeMap[ext] = entry.Type
	}
}

func TypeOf(ext string) string {
	if t, ok := typeMap[ext]; ok {
		return t
	}
	return "other"
}

func IsText(ext string) bool {
	return TypeOf(ext) == "text"
}

func Extensions() []string {
	out := make([]string, 0, len(typeMap))
	for ext := range typeMap {
		out = append(out, ext)
	}
	return out
}
