package cmd

import (
	"strings"
	"testing"
)

func TestWithCommitmentFragmentKeepsTheValueOutOfTheQuery(t *testing.T) {
	const commit = "Q29tbWl0bWVudA"

	got := withCommitmentFragment("https://pigcloud.de/activate?code=ABCD", commit)
	if !strings.Contains(got, "#k="+commit) {
		t.Fatalf("commitment not in the fragment: %q", got)
	}
	hash := strings.Index(got, "#")
	if hash < 0 {
		t.Fatalf("no fragment at all: %q", got)
	}
	if strings.Contains(got[:hash], commit) {
		t.Errorf("commitment leaked into the server-visible part of %q", got)
	}
	if !strings.HasPrefix(got, "https://pigcloud.de/activate?code=ABCD") {
		t.Errorf("the original URL was rewritten: %q", got)
	}
}

func TestWithCommitmentFragmentAppendsToAnExistingFragment(t *testing.T) {
	got := withCommitmentFragment("https://pigcloud.de/activate#existing", "TOKEN")
	if got != "https://pigcloud.de/activate#existing&k=TOKEN" {
		t.Fatalf("got %q, want the commitment joined into the existing fragment", got)
	}
	if strings.Count(got, "#") != 1 {
		t.Errorf("a second '#' is fragment text, not a separator: %q", got)
	}
}

func TestWithCommitmentFragmentPassesThroughWhenEitherHalfIsEmpty(t *testing.T) {
	const url = "https://pigcloud.de/activate?code=ABCD"
	if got := withCommitmentFragment(url, ""); got != url {
		t.Errorf("no commitment must leave the URL alone, got %q", got)
	}
	if got := withCommitmentFragment("", "TOKEN"); got != "" {
		t.Errorf("no URL must stay empty rather than become a bare fragment, got %q", got)
	}
	if got := withCommitmentFragment("", ""); got != "" {
		t.Errorf("both empty = empty, got %q", got)
	}
}

func TestWithCommitmentFragmentPreservesBase64Payloads(t *testing.T) {
	for _, commit := range []string{"AAAA", "AA==", "a+b/c=", strings.Repeat("A", 44)} {
		got := withCommitmentFragment("https://x/y", commit)
		if !strings.HasSuffix(got, "#k="+commit) {
			t.Errorf("commitment %q came back as %q", commit, got)
		}
	}
}

func TestDeviceErrorMessageExplainsKnownCodesAndEchoesTheRest(t *testing.T) {
	cases := map[string]string{
		"rate_limited":    "too many attempts; wait a minute and try again",
		"invalid_request": "the server rejected the request",
		"server_error":    "the server had a problem; try again shortly",
		"":                "unexpected empty response",
	}
	for code, want := range cases {
		if got := deviceErrorMessage(code); got != want {
			t.Errorf("deviceErrorMessage(%q) = %q, want %q", code, got, want)
		}
	}

	for _, code := range []string{"authorization_pending", "some_new_server_code", "slow_down"} {
		if got := deviceErrorMessage(code); got != code {
			t.Errorf("deviceErrorMessage(%q) = %q, an unmapped code must echo verbatim", code, got)
		}
	}
}

func TestDeviceErrorMessageIsNeverEmpty(t *testing.T) {
	for _, code := range []string{"", "x", "rate_limited", "unknown", " "} {
		if got := deviceErrorMessage(code); got == "" {
			t.Errorf("deviceErrorMessage(%q) returned an empty string; the failure would print with no reason", code)
		}
	}
}

func TestDeviceLabelIsAlwaysANonEmptyName(t *testing.T) {
	got := deviceLabel()
	if strings.TrimSpace(got) == "" {
		t.Fatal("the device label names the minted API key in the web UI; it must never be blank")
	}
}
