package inspect

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Entry is one file or folder inside an archive, a folder listing or a
// repository.
type Entry struct {
	Name string `json:"name"`
	Size int64  `json:"size"` // -1 unknown
	Dir  bool   `json:"dir,omitempty"`
	URL  string `json:"url,omitempty"` // folder listings: link to the file
}

// Contents describes what a link holds, like a torrent's file list.
type Contents struct {
	Kind      string  `json:"kind"` // zip | folder | git | safetensors
	Files     int     `json:"files"`
	Folders   int     `json:"folders"`
	TotalSize int64   `json:"total_size"` // uncompressed / sum of known sizes, -1 unknown
	Entries   []Entry `json:"entries"`    // possibly truncated
	Truncated bool    `json:"truncated,omitempty"`
	Summary   string  `json:"summary"`
}

// MaxEntries caps how many entries are returned.
const MaxEntries = 500

// ---- ZIP listing over HTTP ranges ----

// RangeReaderAt reads a remote file with HTTP range requests. It caches
// blocks and stops after a budget so a hostile server can't make rdl fetch
// the whole file.
type RangeReaderAt struct {
	Ctx      context.Context
	Client   *http.Client
	URL      string
	Size     int64
	MaxBytes int64 // total budget (default 8 MB)
	MaxReqs  int   // default 24
	UA       string

	fetched int64
	reqs    int
	blocks  map[int64][]byte
}

const blockSize = 64 << 10

// ErrBudget means the listing would need too much data.
var ErrBudget = errors.New("archive directory too large to list remotely")

// ReadAt implements io.ReaderAt.
func (r *RangeReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.blocks == nil {
		r.blocks = map[int64][]byte{}
	}
	if r.MaxBytes == 0 {
		r.MaxBytes = 8 << 20
	}
	if r.MaxReqs == 0 {
		r.MaxReqs = 24
	}
	if off >= r.Size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off+int64(n) < r.Size {
		pos := off + int64(n)
		bi := pos / blockSize
		b, ok := r.blocks[bi]
		if !ok {
			// Fetch this block and following ones the read needs, in one request.
			lastByte := min(off+int64(len(p))-1, r.Size-1)
			lastBlock := lastByte / blockSize
			var err error
			if err = r.fetch(bi, lastBlock); err != nil {
				return n, err
			}
			b = r.blocks[bi]
		}
		inBlock := pos - bi*blockSize
		if inBlock >= int64(len(b)) {
			return n, io.ErrUnexpectedEOF
		}
		c := copy(p[n:], b[inBlock:])
		n += c
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (r *RangeReaderAt) fetch(first, last int64) error {
	// Skip already cached blocks at the start/end.
	for first <= last {
		if _, ok := r.blocks[first]; !ok {
			break
		}
		first++
	}
	start := first * blockSize
	end := min((last+1)*blockSize, r.Size) - 1
	if start > end {
		return nil
	}
	if r.reqs >= r.MaxReqs || r.fetched+(end-start+1) > r.MaxBytes {
		return ErrBudget
	}
	r.reqs++
	req, err := http.NewRequestWithContext(r.Ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	req.Header.Set("Accept-Encoding", "identity")
	if r.UA != "" {
		req.Header.Set("User-Agent", r.UA)
	}
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return fmt.Errorf("server did not honour range request (%d)", resp.StatusCode)
	}
	want := end - start + 1
	data, err := io.ReadAll(io.LimitReader(resp.Body, want))
	if err != nil {
		return err
	}
	if int64(len(data)) != want {
		return io.ErrUnexpectedEOF
	}
	r.fetched += want
	for i := int64(0); i*blockSize < want; i++ {
		lo := i * blockSize
		hi := min(lo+blockSize, want)
		r.blocks[first+i] = data[lo:hi]
	}
	return nil
}

// ListZip reads only the ZIP central directory through ra.
func ListZip(ra io.ReaderAt, size int64) (*Contents, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, err
	}
	c := &Contents{Kind: "zip"}
	for _, f := range zr.File {
		name := f.Name
		if f.FileInfo().IsDir() {
			c.Folders++
		} else {
			c.Files++
			c.TotalSize += int64(f.UncompressedSize64)
		}
		if len(c.Entries) < MaxEntries {
			c.Entries = append(c.Entries, Entry{Name: name, Size: int64(f.UncompressedSize64), Dir: f.FileInfo().IsDir()})
		} else {
			c.Truncated = true
		}
	}
	c.Summary = fmt.Sprintf("ZIP with %d files in %d folders, %s unpacked", c.Files, c.Folders, human(c.TotalSize))
	if warn := zipWarnings(c.Entries); warn != "" {
		c.Summary += "; " + warn
	}
	return c, nil
}

func zipWarnings(es []Entry) string {
	var exe, unsafe int
	for _, e := range es {
		ln := strings.ToLower(e.Name)
		if strings.HasPrefix(ln, "/") || strings.Contains(ln, "../") || strings.Contains(ln, `..\`) || strings.Contains(ln, ":") {
			unsafe++
		}
		for _, x := range []string{".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".scr", ".lnk", ".js", ".hta", ".dll"} {
			if strings.HasSuffix(ln, x) {
				exe++
				break
			}
		}
	}
	var w []string
	if exe > 0 {
		w = append(w, fmt.Sprintf("contains %d program/script files", exe))
	}
	if unsafe > 0 {
		w = append(w, fmt.Sprintf("WARNING: %d entries with unsafe paths (zip-slip)", unsafe))
	}
	return strings.Join(w, ", ")
}

// ---- web folder listings ("Index of /") ----

var (
	hrefRe  = regexp.MustCompile(`(?is)<a\s[^>]*?href\s*=\s*["']([^"'#?]+)["'][^>]*>`)
	titleRe = regexp.MustCompile(`(?is)<title>\s*(index of|directory listing for|listing of)`)
)

// IsFolderListing reports an auto-generated directory index page
// (Apache, nginx, lighttpd, IIS, python http.server, GitHub Pages-style).
func IsFolderListing(page []byte) bool {
	return titleRe.Match(page[:min(len(page), 4096)])
}

// ParseFolderListing extracts the files and subfolders linked from an
// index page. Only links that stay below the page's own URL are kept
// (no parent folder, no other sites, no query links).
func ParseFolderListing(base *url.URL, page []byte) *Contents {
	c := &Contents{Kind: "folder", TotalSize: -1}
	seen := map[string]bool{}
	basePath := base.Path
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	for _, m := range hrefRe.FindAllSubmatch(page, -1) {
		href := html.UnescapeString(string(m[1]))
		u, err := base.Parse(href)
		if err != nil || u.Host != base.Host || u.Scheme != base.Scheme {
			continue
		}
		if !strings.HasPrefix(u.Path, basePath) || u.Path == basePath {
			continue
		}
		rel := strings.TrimPrefix(u.Path, basePath)
		dir := strings.HasSuffix(rel, "/")
		rel = strings.TrimSuffix(rel, "/")
		if rel == "" || strings.Contains(rel, "/") || seen[rel] {
			continue // only direct children
		}
		seen[rel] = true
		u.RawQuery, u.Fragment = "", ""
		e := Entry{Name: rel, Size: -1, Dir: dir, URL: u.String()}
		if dir {
			c.Folders++
		} else {
			c.Files++
		}
		if len(c.Entries) < MaxEntries {
			c.Entries = append(c.Entries, e)
		} else {
			c.Truncated = true
		}
	}
	c.Summary = fmt.Sprintf("web folder with %d files and %d subfolders", c.Files, c.Folders)
	return c
}

func human(n int64) string {
	if n < 0 {
		return "unknown size"
	}
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(n)/float64(div), "KMGTP"[exp])
}
