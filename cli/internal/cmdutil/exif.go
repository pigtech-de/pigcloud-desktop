package cmdutil

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"time"
)

var tiffRawExtensions = map[string]bool{
	".tif": true, ".tiff": true, ".cr2": true, ".nef": true, ".dng": true,
	".arw": true, ".orf": true, ".pef": true, ".rw2": true, ".srw": true, ".nrw": true,
}

func ParseExifCaptureDate(path string) int64 {
	lower := strings.ToLower(path)
	ext := ""
	if dot := strings.LastIndex(lower, "."); dot >= 0 {
		ext = lower[dot:]
	}
	isJpeg := ext == ".jpg" || ext == ".jpeg"
	isPng := ext == ".png"
	isWebp := ext == ".webp"
	isHeic := ext == ".heic" || ext == ".heif"
	isTiffRaw := tiffRawExtensions[ext]
	if !isJpeg && !isPng && !isWebp && !isHeic && !isTiffRaw {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	head := make([]byte, 256*1024)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return 0
	}
	b := head[:n]
	switch {
	case isJpeg:
		return parseJpegExif(b)
	case isPng:
		return parsePngExif(b)
	case isWebp:
		return parseWebpExif(b)
	case isTiffRaw:
		return walkExifTiff(b, 0)
	case isHeic:
		return parseHeicExif(b)
	}
	return 0
}

func parseHeicExif(b []byte) int64 {
	for i := 0; i+8 <= len(b); i++ {
		b0 := b[i]
		if b0 != 0x49 && b0 != 0x4D {
			continue
		}
		ll := b0 == 0x49 && b[i+1] == 0x49 && b[i+2] == 0x2A && b[i+3] == 0x00
		bb := b0 == 0x4D && b[i+1] == 0x4D && b[i+2] == 0x00 && b[i+3] == 0x2A
		if !ll && !bb {
			continue
		}
		if ts := walkExifTiff(b, i); ts > 0 {
			return ts
		}
	}
	return 0
}

func parseJpegExif(b []byte) int64 {
	if len(b) < 4 || b[0] != 0xFF || b[1] != 0xD8 {
		return 0
	}
	off := 2
	for off < len(b)-4 {
		if b[off] != 0xFF {
			return 0
		}
		marker := b[off+1]
		segLen := int(b[off+2])<<8 | int(b[off+3])
		if marker == 0xE1 {
			app1Start := off + 4
			app1End := off + 2 + segLen
			if app1End > len(b) {
				return 0
			}
			if !bytes.HasPrefix(b[app1Start:], []byte("Exif\x00\x00")) {
				return 0
			}
			return walkExifTiff(b[:app1End], app1Start+6)
		}
		if marker == 0xDA || marker == 0xD9 {
			return 0
		}
		off += 2 + segLen
	}
	return 0
}

func parsePngExif(b []byte) int64 {
	sig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(b) < 8 || !bytes.HasPrefix(b, sig) {
		return 0
	}
	off := 8
	for off+8 <= len(b) {
		length := int(binary.BigEndian.Uint32(b[off:]))
		ctype := string(b[off+4 : off+8])
		dataStart := off + 8
		dataEnd := dataStart + length
		if dataEnd+4 > len(b) {
			return 0
		}
		if ctype == "eXIf" {
			return walkExifTiff(b[:dataEnd], dataStart)
		}
		if ctype == "IEND" || ctype == "IDAT" {
			return 0
		}
		off = dataEnd + 4
	}
	return 0
}

func parseWebpExif(b []byte) int64 {
	if len(b) < 12 {
		return 0
	}
	if !bytes.HasPrefix(b, []byte("RIFF")) || string(b[8:12]) != "WEBP" {
		return 0
	}
	off := 12
	for off+8 <= len(b) {
		ctype := string(b[off : off+4])
		length := int(binary.LittleEndian.Uint32(b[off+4:]))
		dataStart := off + 8
		dataEnd := dataStart + length
		if dataEnd > len(b) {
			return 0
		}
		if ctype == "EXIF" {
			return walkExifTiff(b[:dataEnd], dataStart)
		}
		off = dataEnd + (length & 1)
	}
	return 0
}

func walkExifTiff(buf []byte, tiffStart int) int64 {
	if tiffStart+8 > len(buf) {
		return 0
	}
	var bo binary.ByteOrder
	switch binary.BigEndian.Uint16(buf[tiffStart:]) {
	case 0x4949:
		bo = binary.LittleEndian
	case 0x4D4D:
		bo = binary.BigEndian
	default:
		return 0
	}
	if bo.Uint16(buf[tiffStart+2:]) != 0x002A {
		return 0
	}
	ifd0Off := int(bo.Uint32(buf[tiffStart+4:]))
	ifd0 := tiffStart + ifd0Off
	if ifd0+2 > len(buf) {
		return 0
	}
	ifd0Count := int(bo.Uint16(buf[ifd0:]))
	exifIfdOff := -1
	for i := range ifd0Count {
		entry := ifd0 + 2 + i*12
		if entry+12 > len(buf) {
			return 0
		}
		tag := bo.Uint16(buf[entry:])
		if tag == 0x8769 {
			exifIfdOff = int(bo.Uint32(buf[entry+8:]))
			break
		}
	}
	if exifIfdOff < 0 {
		return 0
	}
	exifIfd := tiffStart + exifIfdOff
	if exifIfd+2 > len(buf) {
		return 0
	}
	exifCount := int(bo.Uint16(buf[exifIfd:]))
	for i := range exifCount {
		entry := exifIfd + 2 + i*12
		if entry+12 > len(buf) {
			return 0
		}
		tag := bo.Uint16(buf[entry:])
		if tag != 0x9003 && tag != 0x9004 {
			continue
		}
		if bo.Uint16(buf[entry+2:]) != 2 {
			continue
		}
		count := int(bo.Uint32(buf[entry+4:]))
		if count < 19 {
			continue
		}
		strOff := tiffStart + int(bo.Uint32(buf[entry+8:]))
		if strOff+19 > len(buf) {
			continue
		}
		if ts := parseExifDate(string(buf[strOff : strOff+19])); ts > 0 {
			return ts
		}
	}
	return 0
}

func parseExifDate(s string) int64 {
	if len(s) < 19 || s[4] != ':' || s[7] != ':' || s[10] != ' ' || s[13] != ':' || s[16] != ':' {
		return 0
	}
	t, err := time.Parse("2006:01:02 15:04:05", s)
	if err != nil {
		return 0
	}
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC).Unix()
}
