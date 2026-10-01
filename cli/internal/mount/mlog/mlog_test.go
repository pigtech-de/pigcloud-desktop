package mlog

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	prevLevel := CurrentLevel()
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
		SetLevel(prevLevel)
	})
	return buf
}

func TestDefaultLevelDropsPerFileChatterButKeepsIncidents(t *testing.T) {
	buf := capture(t)
	SetLevel(LevelInfo)

	Debugf("downloader: saved %s (%d bytes)", "/Photos/a.jpg", 12)
	Infof("sync daemon ready")
	Warnf("downloader: %s stalled", "/Photos/a.jpg")
	Errorf("mount returned error: %v", "boom")

	out := buf.String()
	if strings.Contains(out, "saved") {
		t.Errorf("per-file debug chatter must be off by default, got %q", out)
	}
	for _, want := range []string{"INFO sync daemon ready", "WARN downloader:", "ERROR mount returned error"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}

func TestDebugLevelRaisesDetailForASupportCase(t *testing.T) {
	buf := capture(t)
	SetLevel(LevelDebug)

	Debugf("downloader: saved %s", "/Photos/a.jpg")

	if !strings.Contains(buf.String(), "DEBUG downloader: saved /Photos/a.jpg") {
		t.Errorf("debug level must emit the per-file lines, got %q", buf.String())
	}
}

func TestErrorLevelQuietsEverythingBelowIt(t *testing.T) {
	buf := capture(t)
	SetLevel(LevelError)

	Debugf("d")
	Infof("i")
	Warnf("w")
	Errorf("e")

	out := buf.String()
	if strings.Contains(out, "INFO") || strings.Contains(out, "WARN") || strings.Contains(out, "DEBUG") {
		t.Errorf("level filter leaked lower levels: %q", out)
	}
	if !strings.Contains(out, "ERROR e") {
		t.Errorf("errors must always survive, got %q", out)
	}
}

func TestParseLevelAcceptsTheDocumentedNames(t *testing.T) {
	cases := map[string]Level{
		"debug": LevelDebug, "TRACE": LevelDebug,
		"info": LevelInfo, " Info ": LevelInfo,
		"warn": LevelWarn, "warning": LevelWarn,
		"error": LevelError,
	}
	for name, want := range cases {
		got, ok := ParseLevel(name)
		if !ok || got != want {
			t.Errorf("ParseLevel(%q) = %v,%v; want %v,true", name, got, ok, want)
		}
	}
	if _, ok := ParseLevel("chatty"); ok {
		t.Error("an unknown level must report not-ok so the caller can fall back")
	}
}

func TestLevelStringsAreStableForLogGreps(t *testing.T) {
	for lvl, want := range map[Level]string{
		LevelDebug: "DEBUG", LevelInfo: "INFO", LevelWarn: "WARN", LevelError: "ERROR",
	} {
		if lvl.String() != want {
			t.Errorf("Level(%d).String() = %q, want %q", lvl, lvl.String(), want)
		}
	}
}
