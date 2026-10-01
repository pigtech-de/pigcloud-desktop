package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeviceAuthorizationJSONContainsOnlyApprovalFields(t *testing.T) {
	var output bytes.Buffer
	url := withCommitmentFragment("https://pigcloud.de/activate?code=ABCD-EFGH", strings.Repeat("A", 43))
	if err := writeDeviceAuthorization(&output, "ABCD-EFGH", url); err != nil {
		t.Fatal(err)
	}
	var event map[string]string
	if err := json.Unmarshal(output.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if len(event) != 3 || event["event"] != "device_authorization" || event["userCode"] != "ABCD-EFGH" || event["verificationUrl"] != url {
		t.Fatalf("unexpected approval event: %v", event)
	}
	if output.Bytes()[output.Len()-1] != '\n' {
		t.Fatal("authorization event is not newline delimited")
	}
	flag := loginCmd.Flags().Lookup("device")
	if flag == nil || flag.DefValue != "false" || flag.Value.Type() != "bool" {
		t.Fatal("device login must be explicitly opt-in for piped stdin")
	}
}
