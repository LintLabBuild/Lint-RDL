package inspect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSniff(t *testing.T) {
	cases := []struct {
		head     []byte
		name, ct string
		kind     string
		mismatch bool
	}{
		{[]byte("PK\x03\x04rest"), "a.zip", "", "archive", false},
		{[]byte("MZ\x90\x00"), "photo.jpg", "image/jpeg", "executable", true},
		{[]byte("MZ\x90\x00"), "setup.exe", "", "executable", false},
		{[]byte("%PDF-1.7"), "doc.pdf", "", "document", false},
		{[]byte("GGUF\x03"), "llama.gguf", "", "model", false},
		{[]byte("\x89PNG\r\n\x1a\n"), "x.png", "", "image", false},
		{[]byte("<!DOCTYPE html><html>"), "model.safetensors", "text/html", "html", false},
		{[]byte("hello world\n"), "readme.txt", "text/plain", "text", false},
		{[]byte(`{"a":1}`), "config.json", "", "text", false},
		{append([]byte("\x00\x00\x00\x00ftypisom"), 0), "clip.mp4", "", "video", false},
		{[]byte("PK\x03\x04"), "model.pth", "", "model", false},
	}
	for _, c := range cases {
		typ, mm := Sniff(c.head, c.name, c.ct)
		if typ.Kind != c.kind || (mm != "") != c.mismatch {
			t.Errorf("%s: got %+v %q", c.name, typ, mm)
		}
	}
	st := safetensorsBytes(t)
	if typ, _ := Sniff(st, "m.safetensors", ""); typ.Kind != "model" {
		t.Fatalf("%+v", typ)
	}
}

func safetensorsBytes(t *testing.T) []byte {
	hdr := []byte(`{"__metadata__":{"format":"pt"},"a.weight":{"dtype":"F16","shape":[1000,1000],"data_offsets":[0,2000000]},"b.bias":{"dtype":"F32","shape":[1000],"data_offsets":[2000000,2004000]}}`)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(len(hdr)))
	return append(b, hdr...)
}

func TestSafetensors(t *testing.T) {
	ts, err := ParseSafetensors(safetensorsBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	if ts.Count != 2 || ts.Parameters != 1001000 || ts.DTypes["F16"] != 1 || ts.Metadata["format"] != "pt" {
		t.Fatalf("%+v", ts)
	}
	if s := ts.Summary(); !strings.Contains(s, "2 tensors") || !strings.Contains(s, "1.0M") {
		t.Fatal(s)
	}
}

func makeZip(t *testing.T, files map[string]int) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, size := range files {
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		w.Write(bytes.Repeat([]byte{'x'}, size))
	}
	zw.Close()
	return buf.Bytes()
}

func TestListZipOverHTTP(t *testing.T) {
	data := makeZip(t, map[string]int{"models/a.safetensors": 300000, "README.md": 100, "tools/run.bat": 10, "../evil.txt": 1})
	var gets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets++
		http.ServeContent(w, r, "x.zip", time.Time{}, bytes.NewReader(data))
	}))
	defer srv.Close()
	ra := &RangeReaderAt{Ctx: context.Background(), Client: srv.Client(), URL: srv.URL, Size: int64(len(data))}
	c, err := ListZip(ra, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Files != 4 || c.TotalSize != 300111 {
		t.Fatalf("%+v", c)
	}
	if !strings.Contains(c.Summary, "1 program") || !strings.Contains(c.Summary, "zip-slip") {
		t.Fatal(c.Summary)
	}
	if ra.fetched >= int64(len(data)) {
		t.Fatalf("fetched %d of %d bytes: listing must not download the archive", ra.fetched, len(data))
	}
	// Budget is enforced.
	ra2 := &RangeReaderAt{Ctx: context.Background(), Client: srv.Client(), URL: srv.URL, Size: int64(len(data)), MaxBytes: 10}
	if _, err := ListZip(ra2, int64(len(data))); err == nil {
		t.Fatal("budget not enforced")
	}
}

func TestFolderListing(t *testing.T) {
	page := []byte(`<html><head><title>Index of /models/</title></head><body>
<a href="../">Parent Directory</a>
<a href="?C=N;O=D">Name</a>
<a href="vae/">vae/</a>
<a href="model.safetensors">model.safetensors</a>
<a href="/models/config.json">config.json</a>
<a href="https://evil.example/x.exe">x</a>
<a href="/other/secret.bin">secret</a>
<a href="sub/deeper/file.bin">deep</a>
<a href="file%20name.zip">file name.zip</a>
</body></html>`)
	if !IsFolderListing(page) {
		t.Fatal("not detected")
	}
	base, _ := url.Parse("https://example.com/models/")
	c := ParseFolderListing(base, page)
	names := []string{}
	for _, e := range c.Entries {
		names = append(names, e.Name)
	}
	got := strings.Join(names, ",")
	if got != "vae,model.safetensors,config.json,file name.zip" || c.Folders != 1 || c.Files != 3 {
		t.Fatalf("%s %+v", got, c)
	}
	if IsFolderListing([]byte("<html><title>My blog</title>")) {
		t.Fatal("false positive")
	}
}
