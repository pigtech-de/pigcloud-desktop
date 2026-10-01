package syncer

import (
	"encoding/hex"
	"encoding/json"

	"pigcloud/internal/api"
)

type uploadedContent struct {
	digest string
	etag   string
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
	return result
}
