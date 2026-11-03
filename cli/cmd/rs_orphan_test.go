package cmd

import (
	"context"
	"testing"
)

func TestOrphanFallbackDropsTheNamedParentForARootRef(t *testing.T) {
	nodeID, parentID, parentKey := testNodeID(t), testNodeID(t), testParentKey(t)

	first, err := restoreOptions(nodeID, restoreTarget{parentID: parentID}, parentKey)
	if err != nil || first["restore_parent_id"] != parentID {
		t.Fatalf("first attempt: %v %v", first, err)
	}
	if got := decideRootRestore("orphaned", false, true); got != restoreAsk {
		t.Fatalf("an orphaned named parent must offer the root landing, got %v", got)
	}

	retry := restoreRequest(context.Background(), nodeID, true, parentKey)
	if retry["to_root"] != "1" {
		t.Errorf("retry to_root = %q, want 1", retry["to_root"])
	}
	if _, named := retry["restore_parent_id"]; named {
		t.Error("the retry still names the orphaned parent")
	}
	if parent := openSentRef(t, retry, nodeID, parentKey); parent != nil {
		t.Errorf("retry ref names %x, want root", parent)
	}
}

func TestOrphanRestoreDecision(t *testing.T) {
	cases := []struct {
		name        string
		errorCode   string
		toRoot      bool
		interactive bool
		want        rootRestoreDecision
	}{
		{"any other refusal is not ours to reinterpret", "duplicate", false, true, restoreAbort},
		{"a plain failure with no code aborts", "", false, true, restoreAbort},
		{"an interactive session gets the prompt", "orphaned", false, true, restoreAsk},
		{"a script must opt in explicitly, not be prompted into it", "orphaned", false, false, restoreAbort},
		{"--to-root is the opt-in, so no second round trip", "orphaned", true, false, restoreProceed},
		{"--to-root in a terminal skips the prompt too", "orphaned", true, true, restoreProceed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideRootRestore(tc.errorCode, tc.toRoot, tc.interactive)
			if got != tc.want {
				t.Fatalf("decideRootRestore(%q, toRoot=%v, interactive=%v) = %v, want %v",
					tc.errorCode, tc.toRoot, tc.interactive, got, tc.want)
			}
		})
	}
}
