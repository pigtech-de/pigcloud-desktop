package cmd

import (
	"strings"
	"testing"
)

func funcSource(t *testing.T, file, name string) string {
	t.Helper()
	body, ok := commandFuncBodies(t)[file+" "+name]
	if !ok {
		t.Fatalf("no func %s in %s; this guard would be vacuous", name, file)
	}
	return body
}

func TestRevokeAllNeedsATerminalOrForce(t *testing.T) {
	if ssRevokeAllCmd.Flags().Lookup("force") == nil {
		t.Fatal("ss revoke-all has no --force, so a script has no way to say it meant it")
	}
	body := funcSource(t, "ss.go", "runSessionRevokeAll")
	if !strings.Contains(body, "cmdutil.ConfirmActionStrict(") {
		t.Error("revoking every other session must decline without a terminal, not assume yes")
	}
	if !strings.Contains(body, "hadTerminal") || !strings.Contains(body, "ExitWithError()") {
		t.Error("the no-terminal branch must exit instead of falling through to the request")
	}
}

func TestPublicLinkUpdateHonoursJSON(t *testing.T) {
	if !strings.Contains(funcSource(t, "pl.go", "runLinkUpdate"), "JSON: GetJSONOutput()") {
		t.Error("pl set silently ignores --json")
	}
}

func TestShareDeclineSendsTheNodeID(t *testing.T) {
	if !strings.Contains(funcSource(t, "sr.go", "runShareDecline"), `options["node_id"]`) {
		t.Error("sr decline sends no node id, so the server resolves nothing under name obfuscation")
	}
	if !strings.Contains(funcSource(t, "sr.go", "receivedShareNodeID"), `"mode": "inbox"`) {
		t.Error("the node id has to come from the inbox the recipient can actually read")
	}
}
