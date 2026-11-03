package filetypes

import (
	_ "embed"
	"encoding/json"
)

//go:embed file-types.json
var rawJSON []byte

type extEntry struct {
	Type string `json:"type"`
	Cap  struct {
		Edit string `json:"edit"`
	} `json:"cap"`
}

type registry struct {
	Extensions map[string]extEntry `json:"extensions"`
}

var typeMap map[string]string
var plainText map[string]bool

func init() {
	var reg registry
	if err := json.Unmarshal(rawJSON, &reg); err != nil {
		panic("filetypes: failed to parse embedded file-types.json: " + err.Error())
	}
	typeMap = make(map[string]string, len(reg.Extensions))
	plainText = make(map[string]bool)
	for ext, entry := range reg.Extensions {
		typeMap[ext] = entry.Type
		if entry.Cap.Edit == "native" {
			plainText[ext] = true
		}
	}
}

func TypeOf(ext string) string {
	if t, ok := typeMap[ext]; ok {
		return t
	}
	return "other"
}

func IsPlainText(ext string) bool {
	return plainText[ext]
}

func Extensions() []string {
	out := make([]string, 0, len(typeMap))
	for ext := range typeMap {
		out = append(out, ext)
	}
	return out
}
