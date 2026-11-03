package syncer

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"pigcloud/internal/api"
)

type uploadedContent struct {
	digest string
	etag   string
	nodeID string
}

func confirmedUploadContent(response *api.Response, digest string) uploadedContent {
	result := uploadedContent{digest: digest}
	var payload api.UploadPayload
	if response == nil || !response.Success || json.Unmarshal(response.Raw, &payload) != nil {
		return result
	}
	if decoded, err := hex.DecodeString(payload.ETag); err == nil && len(decoded) == 32 {
		result.etag = payload.ETag
	}
	if decoded, err := hex.DecodeString(payload.NodeID); err == nil && len(decoded) == 16 {
		result.nodeID = strings.ToLower(payload.NodeID)
	}
	return result
}
