package crypto

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameVersionJSON     = 1
	frameVersionGzip     = 2
	frameVersionPadded   = 4
	frameVersionBareJSON = 0x7b
	padHeaderBytes = 5
)

func UnframeIndexBody(framed []byte) ([]byte, error) {
	if len(framed) == 0 {
		return nil, fmt.Errorf("empty framed payload")
	}
	if framed[0] == frameVersionPadded {
		if len(framed) < padHeaderBytes {
			return nil, fmt.Errorf("truncated padded frame")
		}
		innerLen := int(binary.BigEndian.Uint32(framed[1:padHeaderBytes]))
		if innerLen < 0 || innerLen > len(framed)-padHeaderBytes {
			return nil, fmt.Errorf("padded frame inner length out of range")
		}
		framed = framed[padHeaderBytes : padHeaderBytes+innerLen]
		if len(framed) == 0 {
			return nil, fmt.Errorf("empty inner frame")
		}
	}
	switch framed[0] {
	case frameVersionJSON:
		return framed[1:], nil
	case frameVersionBareJSON:
		return framed, nil
	case frameVersionGzip:
		gz, err := gzip.NewReader(bytes.NewReader(framed[1:]))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(gz)
	default:
		return nil, fmt.Errorf("unknown frame version 0x%x", framed[0])
	}
}
