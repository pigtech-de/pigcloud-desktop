package cmd

import "testing"

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
