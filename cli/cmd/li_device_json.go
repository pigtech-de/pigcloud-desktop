package cmd

import (
	"encoding/json"
	"io"
)

func writeDeviceAuthorization(writer io.Writer, userCode, verificationURL string) error {
	return json.NewEncoder(writer).Encode(struct {
		Event           string `json:"event"`
		UserCode        string `json:"userCode"`
		VerificationURL string `json:"verificationUrl"`
	}{"device_authorization", userCode, verificationURL})
}
