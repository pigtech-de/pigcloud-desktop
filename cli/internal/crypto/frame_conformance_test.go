package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type frameVectorFile struct {
	VectorKind  string `json:"vector_kind"`
	SpecVersion int    `json:"spec_version"`
	Cases       []struct {
		Name       string `json:"name"`
		Note       string `json:"note"`
		FramedB64  string `json:"framed_b64"`
		ExpectJSON string `json:"expect_json"`
	} `json:"cases"`
}

func loadFrameVector(t *testing.T) frameVectorFile {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	vectorPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "tests", "vectors", "sealed_index_frame_v1.json")
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read frame vector: %v", err)
	}
	var v frameVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse frame vector: %v", err)
	}
	return v
}

func TestConformance_SealedIndexFrameV1(t *testing.T) {
	v := loadFrameVector(t)
	if v.VectorKind != "sealed_index_frame" {
		t.Fatalf("unexpected vector_kind %q", v.VectorKind)
	}
	if len(v.Cases) == 0 {
		t.Fatal("frame vector has no cases")
	}
	for _, c := range v.Cases {
		framed, err := base64.StdEncoding.DecodeString(c.FramedB64)
		if err != nil {
			t.Fatalf("%s: base64 decode: %v", c.Name, err)
		}
		body, err := UnframeIndexBody(framed)
		if err != nil {
			t.Fatalf("%s: UnframeIndexBody: %v", c.Name, err)
		}
		if string(body) != c.ExpectJSON {
			t.Errorf("%s: body mismatch\n got: %s\nwant: %s", c.Name, string(body), c.ExpectJSON)
		}
	}
}

func TestUnframeIndexBody_Rejections(t *testing.T) {
	cases := [][]byte{
		{},
		{4, 0xff, 0xff, 0xff, 0xff, 1, 2},
		{4, 0, 0},
		{0x42, 9, 9},
	}
	for i, in := range cases {
		if _, err := UnframeIndexBody(in); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}
