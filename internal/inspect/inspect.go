// Package inspect tells the user what a link contains before it is
// downloaded: the real file type (from its first bytes), the files inside
// a ZIP archive (read from the archive's directory with a few small range
// requests), the tensors in a .safetensors model, or the files in a web
// folder listing.
//
// Only names, sizes and types are returned. File content is never passed
// on to any interface.
package inspect

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

// Type is the detected file type.
type Type struct {
	Kind        string `json:"kind"`        // archive, model, video, audio, image, document, executable, text, html, data, unknown
	Description string `json:"description"` // e.g. "ZIP archive", "Windows program (.exe)"
	Ext         string `json:"ext,omitempty"`
	Executable  bool   `json:"executable,omitempty"`
}

type magic struct {
	off  int
	sig  []byte
	typ  Type
	exts []string // extensions consistent with this type
}

var magics = []magic{
	{0, []byte("PK\x03\x04"), Type{Kind: "archive", Description: "ZIP archive", Ext: ".zip"}, []string{".zip", ".jar", ".whl", ".apk", ".docx", ".xlsx", ".pptx", ".odt", ".epub", ".nupkg", ".vsix", ".cbz", ".pth", ".pt", ".ckpt", ".npz", ".xpi", ".ipa", ".3mf", ".kmz", ".aar"}},
	{0, []byte("PK\x05\x06"), Type{Kind: "archive", Description: "empty ZIP archive", Ext: ".zip"}, []string{".zip"}},
	{0, []byte{0x1f, 0x8b}, Type{Kind: "archive", Description: "gzip-compressed file", Ext: ".gz"}, []string{".gz", ".tgz", ".svgz"}},
	{0, []byte("7z\xbc\xaf\x27\x1c"), Type{Kind: "archive", Description: "7-Zip archive", Ext: ".7z"}, []string{".7z"}},
	{0, []byte("Rar!\x1a\x07"), Type{Kind: "archive", Description: "RAR archive", Ext: ".rar"}, []string{".rar"}},
	{0, []byte{0xfd, '7', 'z', 'X', 'Z', 0}, Type{Kind: "archive", Description: "XZ-compressed file", Ext: ".xz"}, []string{".xz", ".txz"}},
	{0, []byte{0x28, 0xb5, 0x2f, 0xfd}, Type{Kind: "archive", Description: "Zstandard-compressed file", Ext: ".zst"}, []string{".zst", ".tzst"}},
	{0, []byte("BZh"), Type{Kind: "archive", Description: "bzip2-compressed file", Ext: ".bz2"}, []string{".bz2", ".tbz2"}},
	{257, []byte("ustar"), Type{Kind: "archive", Description: "TAR archive", Ext: ".tar"}, []string{".tar"}},
	{0, []byte("MSCF"), Type{Kind: "archive", Description: "Windows cabinet (.cab)", Ext: ".cab"}, []string{".cab", ".msu"}},
	{0, []byte("GGUF"), Type{Kind: "model", Description: "GGUF model (llama.cpp)", Ext: ".gguf"}, []string{".gguf"}},
	{0, []byte("%PDF-"), Type{Kind: "document", Description: "PDF document", Ext: ".pdf"}, []string{".pdf"}},
	{0, []byte("\x89PNG\r\n\x1a\n"), Type{Kind: "image", Description: "PNG image", Ext: ".png"}, []string{".png"}},
	{0, []byte{0xff, 0xd8, 0xff}, Type{Kind: "image", Description: "JPEG image", Ext: ".jpg"}, []string{".jpg", ".jpeg", ".jfif"}},
	{0, []byte("GIF8"), Type{Kind: "image", Description: "GIF image", Ext: ".gif"}, []string{".gif"}},
	{0, []byte("RIFF"), Type{Kind: "data", Description: "RIFF container (WAV/AVI/WebP)"}, []string{".wav", ".avi", ".webp", ".ani"}},
	{4, []byte("ftyp"), Type{Kind: "video", Description: "MP4/MOV video", Ext: ".mp4"}, []string{".mp4", ".m4v", ".m4a", ".mov", ".3gp", ".heic", ".avif"}},
	{0, []byte{0x1a, 0x45, 0xdf, 0xa3}, Type{Kind: "video", Description: "Matroska/WebM video", Ext: ".mkv"}, []string{".mkv", ".webm", ".mka"}},
	{0, []byte("OggS"), Type{Kind: "audio", Description: "Ogg audio/video", Ext: ".ogg"}, []string{".ogg", ".oga", ".ogv", ".opus"}},
	{0, []byte("fLaC"), Type{Kind: "audio", Description: "FLAC audio", Ext: ".flac"}, []string{".flac"}},
	{0, []byte("ID3"), Type{Kind: "audio", Description: "MP3 audio", Ext: ".mp3"}, []string{".mp3"}},
	{0, []byte("SQLite format 3\x00"), Type{Kind: "data", Description: "SQLite database", Ext: ".sqlite"}, []string{".sqlite", ".db", ".sqlite3"}},
	{0, []byte("\x93NUMPY"), Type{Kind: "data", Description: "NumPy array", Ext: ".npy"}, []string{".npy"}},
	{0, []byte("\x89HDF\r\n\x1a\n"), Type{Kind: "data", Description: "HDF5 file", Ext: ".h5"}, []string{".h5", ".hdf5", ".keras"}},
	{0, []byte("MZ"), Type{Kind: "executable", Description: "Windows program (.exe/.dll)", Ext: ".exe", Executable: true}, []string{".exe", ".dll", ".sys", ".scr", ".efi", ".mui", ".ocx", ".cpl"}},
	{0, []byte("\x7fELF"), Type{Kind: "executable", Description: "Linux program (ELF)", Executable: true}, []string{"", ".so", ".bin", ".run", ".appimage", ".elf"}},
	{0, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, Type{Kind: "document", Description: "Office/MSI compound file", Ext: ".msi"}, []string{".msi", ".doc", ".xls", ".ppt", ".msg"}},
	{0, []byte("d8:announce"), Type{Kind: "data", Description: "BitTorrent .torrent file", Ext: ".torrent"}, []string{".torrent"}},
	{0, []byte("#!"), Type{Kind: "executable", Description: "script (#!)", Executable: true}, []string{".sh", ".py", ".pl", ".rb", ""}},
}

// Sniff detects the type from the first bytes, the file name and the
// server's Content-Type. If the bytes contradict the extension (e.g. a
// ".jpg" that is really a program), Mismatch explains it.
func Sniff(head []byte, name, contentType string) (Type, string) {
	ext := strings.ToLower(path.Ext(name))
	for _, m := range magics {
		if m.typ.Kind == "" || len(head) < m.off+len(m.sig) {
			continue
		}
		if !bytes.Equal(head[m.off:m.off+len(m.sig)], m.sig) {
			continue
		}
		t := m.typ
		if ext != "" {
			t.Ext = ext
		}
		ok := false
		for _, e := range m.exts {
			if e == ext {
				ok = true
			}
		}
		mismatch := ""
		if !ok && ext != "" {
			mismatch = fmt.Sprintf("the name says %s but the content is a %s", ext, m.typ.Description)
			if t.Executable {
				mismatch = "WARNING: " + mismatch + " (disguised program?)"
			}
		}
		// Special-case ZIP-based formats with known names.
		if m.typ.Description == "ZIP archive" {
			switch ext {
			case ".whl":
				t.Description = "Python wheel (ZIP)"
			case ".jar":
				t.Description = "Java archive (ZIP)"
			case ".apk":
				t.Description = "Android app (ZIP)"
				t.Executable = true
			case ".docx", ".xlsx", ".pptx":
				t.Kind, t.Description = "document", "Office document (ZIP)"
			case ".pth", ".pt", ".ckpt":
				t.Kind, t.Description = "model", "PyTorch checkpoint (ZIP, may contain pickled code)"
			}
		}
		if t.Kind == "data" && m.typ.Description == "RIFF container (WAV/AVI/WebP)" && len(head) >= 12 {
			switch string(head[8:12]) {
			case "WAVE":
				t.Kind, t.Description = "audio", "WAV audio"
			case "AVI ":
				t.Kind, t.Description = "video", "AVI video"
			case "WEBP":
				t.Kind, t.Description = "image", "WebP image"
			}
		}
		return t, mismatch
	}
	if st, ok := safetensorsHeaderLen(head); ok && st > 0 {
		t := Type{Kind: "model", Description: "safetensors model", Ext: ext}
		mm := ""
		if ext != ".safetensors" && ext != "" {
			mm = "the name says " + ext + " but the content is a safetensors model"
		}
		return t, mm
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch {
	case ct == "text/html" || ct == "application/xhtml+xml" || looksHTML(head):
		return Type{Kind: "html", Description: "web page (HTML)", Ext: ext}, ""
	case strings.HasPrefix(ct, "video/"):
		return Type{Kind: "video", Description: ct, Ext: ext}, ""
	case strings.HasPrefix(ct, "audio/"):
		return Type{Kind: "audio", Description: ct, Ext: ext}, ""
	case strings.HasPrefix(ct, "image/"):
		return Type{Kind: "image", Description: ct, Ext: ext}, ""
	case ct == "application/json" || (len(head) > 0 && (head[0] == '{' || head[0] == '[') && json.Valid(trimToValid(head))):
		return Type{Kind: "text", Description: "JSON", Ext: ext}, ""
	case isText(head):
		return Type{Kind: "text", Description: "text file", Ext: ext}, ""
	}
	if len(head) == 0 {
		return Type{Kind: "unknown", Description: "unknown (server sent no sample)", Ext: ext}, ""
	}
	return Type{Kind: "data", Description: "binary data", Ext: ext}, ""
}

func trimToValid(b []byte) []byte { return bytes.TrimSpace(b) }

func looksHTML(b []byte) bool {
	s := strings.ToLower(string(bytes.TrimSpace(b[:min(len(b), 512)])))
	return strings.HasPrefix(s, "<!doctype html") || strings.HasPrefix(s, "<html") || strings.Contains(s, "<head>")
}

func isText(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	n := min(len(b), 4096)
	for _, c := range b[:n] {
		if c == 0 {
			return false
		}
		if c < 0x09 || (c > 0x0d && c < 0x20 && c != 0x1b) {
			return false
		}
	}
	return true
}

// ---- safetensors ----

const maxSafetensorsHeader = 32 << 20

// safetensorsHeaderLen reads the 8-byte little-endian header length and
// checks that the JSON header starts right after it.
func safetensorsHeaderLen(head []byte) (int64, bool) {
	if len(head) < 10 {
		return 0, false
	}
	n := int64(binary.LittleEndian.Uint64(head[:8]))
	if n < 2 || n > maxSafetensorsHeader || head[8] != '{' {
		return 0, false
	}
	return n, true
}

// Tensors summarises a safetensors header.
type Tensors struct {
	Count      int               `json:"count"`
	DTypes     map[string]int    `json:"dtypes"`
	Parameters int64             `json:"parameters"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Sample     []string          `json:"sample,omitempty"` // first few tensor names
}

// ParseSafetensors reads the JSON header (header must include all
// 8+headerLen bytes).
func ParseSafetensors(header []byte) (*Tensors, error) {
	n, ok := safetensorsHeaderLen(header)
	if !ok {
		return nil, fmt.Errorf("not a safetensors file")
	}
	if int64(len(header)) < 8+n {
		return nil, fmt.Errorf("header incomplete")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(header[8:8+n], &raw); err != nil {
		return nil, err
	}
	t := &Tensors{DTypes: map[string]int{}}
	var names []string
	for k, v := range raw {
		if k == "__metadata__" {
			var md map[string]string
			if json.Unmarshal(v, &md) == nil && len(md) > 0 {
				t.Metadata = map[string]string{}
				for mk, mv := range md {
					if len(mv) > 200 {
						mv = mv[:200] + "..."
					}
					t.Metadata[mk] = mv
					if len(t.Metadata) >= 10 {
						break
					}
				}
			}
			continue
		}
		var info struct {
			DType string  `json:"dtype"`
			Shape []int64 `json:"shape"`
		}
		if json.Unmarshal(v, &info) != nil {
			continue
		}
		t.Count++
		t.DTypes[info.DType]++
		p := int64(1)
		for _, d := range info.Shape {
			p *= d
		}
		t.Parameters += p
		names = append(names, k)
	}
	sort.Strings(names)
	t.Sample = names[:min(len(names), 5)]
	return t, nil
}

// Summary is a short human description, e.g. "1,095 tensors, 5.0B params, F16".
func (t *Tensors) Summary() string {
	var dts []string
	for k := range t.DTypes {
		dts = append(dts, k)
	}
	sort.Strings(dts)
	return fmt.Sprintf("%s tensors, %s parameters, %s", commas(int64(t.Count)), humanCount(t.Parameters), strings.Join(dts, "/"))
}

func commas(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func humanCount(n int64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	}
	return fmt.Sprint(n)
}
