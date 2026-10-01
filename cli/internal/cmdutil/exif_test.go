package cmdutil

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const exifTestDate = "2023:06:15 10:20:30"

var exifTestUnix = time.Date(2023, 6, 15, 10, 20, 30, 0, time.UTC).Unix()

func buildTiff(bo binary.ByteOrder, dateTag uint16, date string) []byte {
	var buf bytes.Buffer
	if bo == binary.LittleEndian {
		buf.WriteString("II")
	} else {
		buf.WriteString("MM")
	}
	w := func(v any) { binary.Write(&buf, bo, v) }
	w(uint16(0x002A))
	w(uint32(8))

	w(uint16(1))
	w(uint16(0x8769))
	w(uint16(4))
	w(uint32(1))
	w(uint32(22))

	w(uint16(1))
	w(dateTag)
	w(uint16(2))
	w(uint32(len(date) + 1))
	w(uint32(36))

	buf.WriteString(date)
	buf.WriteByte(0)
	return buf.Bytes()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func jpegWithExif(tiff []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8})
	payload := append([]byte("Exif\x00\x00"), tiff...)
	segLen := 2 + len(payload)
	buf.Write([]byte{0xFF, 0xE1, byte(segLen >> 8), byte(segLen)})
	buf.Write(payload)
	buf.Write([]byte{0xFF, 0xD9})
	return buf.Bytes()
}

func pngWithExif(tiff []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(tiff)))
	buf.Write(length[:])
	buf.WriteString("eXIf")
	buf.Write(tiff)
	buf.Write([]byte{0, 0, 0, 0})
	return buf.Bytes()
}

func webpWithExif(tiff []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(4+8+len(tiff)))
	buf.Write(size[:])
	buf.WriteString("WEBP")
	buf.WriteString("EXIF")
	var clen [4]byte
	binary.LittleEndian.PutUint32(clen[:], uint32(len(tiff)))
	buf.Write(clen[:])
	buf.Write(tiff)
	return buf.Bytes()
}

func TestParseExifCaptureDatePerContainer(t *testing.T) {
	tiff := buildTiff(binary.LittleEndian, 0x9003, exifTestDate)
	cases := []struct {
		name string
		data []byte
	}{
		{"photo.jpg", jpegWithExif(tiff)},
		{"photo.jpeg", jpegWithExif(tiff)},
		{"photo.png", pngWithExif(tiff)},
		{"photo.webp", webpWithExif(tiff)},
		{"photo.dng", tiff},
		{"photo.tif", tiff},
		{"photo.heic", append([]byte("....ftypheic....junkjunk"), tiff...)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeTemp(t, c.name, c.data)
			if got := ParseExifCaptureDate(p); got != exifTestUnix {
				t.Errorf("ParseExifCaptureDate = %d, want %d", got, exifTestUnix)
			}
		})
	}
}

func TestParseExifCaptureDateBigEndianAndDigitizedTag(t *testing.T) {
	be := buildTiff(binary.BigEndian, 0x9003, exifTestDate)
	p := writeTemp(t, "be.jpg", jpegWithExif(be))
	if got := ParseExifCaptureDate(p); got != exifTestUnix {
		t.Errorf("big-endian TIFF: %d", got)
	}

	digitized := buildTiff(binary.LittleEndian, 0x9004, exifTestDate)
	p = writeTemp(t, "dig.jpg", jpegWithExif(digitized))
	if got := ParseExifCaptureDate(p); got != exifTestUnix {
		t.Errorf("DateTimeDigitized fallback: %d", got)
	}
}

func TestParseExifCaptureDateRejects(t *testing.T) {
	tiff := buildTiff(binary.LittleEndian, 0x9003, exifTestDate)
	cases := []struct {
		name string
		data []byte
	}{
		{"unsupported.txt", jpegWithExif(tiff)},
		{"noexif.jpg", []byte{0xFF, 0xD8, 0xFF, 0xD9}},
		{"notjpeg.jpg", []byte("plain text")},
		{"truncated.jpg", jpegWithExif(tiff)[:8]},
		{"nosig.png", tiff},
		{"noexifchunk.png", pngWithExif(tiff)[:8]},
		{"notriff.webp", []byte("RIFXaaaaWEBP")},
		{"emptytiff.dng", []byte("II")},
		{"wrongmagic.dng", []byte("II\x00\x00\x08\x00\x00\x00")},
		{"baddate.jpg", jpegWithExif(buildTiff(binary.LittleEndian, 0x9003, "2023-06-15 10:20:30"))},
		{"wrongtag.jpg", jpegWithExif(buildTiff(binary.LittleEndian, 0x1234, exifTestDate))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := writeTemp(t, c.name, c.data)
			if got := ParseExifCaptureDate(p); got != 0 {
				t.Errorf("ParseExifCaptureDate = %d, want 0", got)
			}
		})
	}

	if got := ParseExifCaptureDate(filepath.Join(t.TempDir(), "missing.jpg")); got != 0 {
		t.Errorf("missing file: %d", got)
	}
}

func TestParseExifDate(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{exifTestDate, exifTestUnix},
		{exifTestDate + " trailing junk", 0},
		{"", 0},
		{"2023:06:15", 0},
		{"2023-06-15 10:20:30", 0},
		{"2023:06:15T10:20:30", 0},
		{"2023:13:99 10:20:30", 0},
		{"0000:00:00 00:00:00", 0},
	}
	for _, c := range cases {
		if got := parseExifDate(c.in); got != c.want {
			t.Errorf("parseExifDate(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseExifDateUsesUTC(t *testing.T) {
	got := parseExifDate("2020:01:01 00:00:00")
	want := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	if got != want {
		t.Errorf("timezone leaked into parse: got %d, want %d", got, want)
	}
}
