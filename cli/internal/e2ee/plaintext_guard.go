package e2ee

import (
	"errors"

	"pigcloud/internal/api"
)

var ErrPlaintextResponse = errors.New("the server claims this file is not encrypted")

var ErrDownloadMetadataMissing = errors.New("download response carried no metadata")

func RequireEncryptedDownload(dlResult *api.DownloadResult) error {
	if dlResult == nil {
		return ErrDownloadMetadataMissing
	}
	if !dlResult.E2EE {
		return ErrPlaintextResponse
	}
	return nil
}
