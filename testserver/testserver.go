// Package testserver is a fake HTTP file server that misbehaves on
// purpose. Every engine edge case in the spec (§5.4) has a switch here.
package testserver

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options switches on misbehaviour.
type Options struct {
	IgnoreRange       bool  // answer 200 with the whole file to range requests
	WrongContentRange bool  // answer 206 starting one byte after the requested start
	ChangeAfter       int   // after N GET requests the file (and ETag) changes; 0 = never
	Gzip              bool  // Content-Encoding: gzip even when identity is asked
	NoLength          bool  // no Content-Length (chunked), no range support
	NoValidators      bool  // no ETag, no Last-Modified
	WeakETag          bool  // send a weak ETag (W/"...")
	BusyFirst         int   // first N GETs answer 429 with Retry-After: 1
	ExpireAfterBytes  int64 // /signed?t=N links stop working after this many bytes were served on them
	HTMLError         bool  // answer 200 text/html "<html>error</html>"
	StallAfter        int64 // send this many bytes per request, then hang (0 = off)
	CutEvery          int64 // close the connection after this many bytes per request (0 = off)
	Multipart         bool  // answer range requests with multipart/byteranges
	HEADForbidden     bool  // HEAD answers 405
	Disposition       string
	ContentType       string // default application/octet-stream
	Status            int    // force this status for every GET (e.g. 404)
}

// Server serves one file at /file.bin (and friends).
type Server struct {
	*httptest.Server
	Opts Options

	mu       sync.Mutex
	content  []byte
	version  int
	gets     int
	signed   map[string]int64 // token -> bytes served
	nextTok  int
	stop     chan struct{}
	stopOnce sync.Once
	Log      []string
}

// Content returns deterministic pseudo-random bytes.
func Content(size int, seed int64) []byte {
	b := make([]byte, size)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// SHA256 returns the hex SHA-256 of b.
func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// New starts a server for content.
func New(content []byte, o Options) *Server {
	s := &Server{Opts: o, content: content, signed: map[string]int64{}, stop: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/file.bin", s.serveFile)
	mux.HandleFunc("/model.safetensors", s.serveFile)
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/file.bin", http.StatusFound)
	})
	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.nextTok++
		tok := strconv.Itoa(s.nextTok)
		s.signed[tok] = 0
		s.mu.Unlock()
		http.Redirect(w, r, "/signed?X-Amz-Signature=abc&t="+tok, http.StatusFound)
	})
	mux.HandleFunc("/signed", func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		s.mu.Lock()
		served, ok := s.signed[tok]
		exp := s.Opts.ExpireAfterBytes
		s.mu.Unlock()
		if !ok || (exp > 0 && served >= exp) {
			http.Error(w, "expired", http.StatusForbidden)
			return
		}
		s.serveFileTok(w, r, tok)
	})
	s.Server = httptest.NewServer(mux)
	return s
}

// Close also releases stalled handlers.
func (s *Server) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.Server.CloseClientConnections()
	s.Server.Close()
}

// URL of the file.
func (s *Server) FileURL() string { return s.URL + "/file.bin" }

// CurrentContent returns the bytes currently served (they change if
// ChangeAfter triggers).
func (s *Server) CurrentContent() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.content
}

// Gets returns the number of GET requests seen.
func (s *Server) Gets() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets
}

func (s *Server) etag() string {
	sum := sha256.Sum256(s.content)
	return `"` + hex.EncodeToString(sum[:8]) + `-` + strconv.Itoa(s.version) + `"`
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request) { s.serveFileTok(w, r, "") }

// Update changes the options while the server runs.
func (s *Server) Update(f func(*Options)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.Opts)
}

func (s *Server) serveFileTok(w http.ResponseWriter, r *http.Request, tok string) {
	s.mu.Lock()
	o := s.Opts
	if r.Method == http.MethodGet {
		s.gets++
		if o.ChangeAfter > 0 && s.gets == o.ChangeAfter+1 {
			s.version++
			c := append([]byte{}, s.content...)
			for i := range c {
				c[i] ^= 0x5a
			}
			s.content = c
		}
	}
	gets := s.gets
	content := s.content
	etag := s.etag()
	s.Log = append(s.Log, fmt.Sprintf("%s range=%q if-range=%q", r.Method, r.Header.Get("Range"), r.Header.Get("If-Range")))
	s.mu.Unlock()

	if r.Method == http.MethodHead && o.HEADForbidden {
		http.Error(w, "no HEAD", http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodGet && gets <= o.BusyFirst {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	if o.Status != 0 && r.Method == http.MethodGet {
		http.Error(w, http.StatusText(o.Status), o.Status)
		return
	}
	if o.HTMLError {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Please log in</body></html>"))
		return
	}
	h := w.Header()
	ct := o.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	h.Set("Content-Type", ct)
	if o.Disposition != "" {
		h.Set("Content-Disposition", o.Disposition)
	}
	lastMod := time.Date(2025, 7, 28, 0, 0, s.version, 0, time.UTC).Format(http.TimeFormat)
	if !o.NoValidators {
		if o.WeakETag {
			h.Set("ETag", "W/"+etag)
		} else {
			h.Set("ETag", etag)
		}
		h.Set("Last-Modified", lastMod)
	}

	if o.Gzip {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		gz.Write(content)
		gz.Close()
		h.Set("Content-Encoding", "gzip")
		h.Set("Content-Length", strconv.Itoa(buf.Len()))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			s.write(w, o, buf.Bytes(), tok)
		}
		return
	}
	if o.NoLength {
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			s.write(w, o, content, tok)
		}
		return
	}

	h.Set("Accept-Ranges", "bytes") // even when ignoring ranges: servers lie
	start, end, isRange := int64(0), int64(len(content))-1, false
	if rh := r.Header.Get("Range"); rh != "" && !o.IgnoreRange {
		ifr := r.Header.Get("If-Range")
		if ifr == "" || ifr == etag || ifr == lastMod {
			if a, b, ok := parseRange(rh, int64(len(content))); ok {
				start, end, isRange = a, b, true
			} else {
				h.Set("Content-Range", "bytes */"+strconv.Itoa(len(content)))
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
		}
	}
	if isRange && o.Multipart {
		h.Set("Content-Type", "multipart/byteranges; boundary=XYZ")
		w.WriteHeader(http.StatusPartialContent)
		return
	}
	if isRange {
		if o.WrongContentRange && start+1 <= end {
			start++
		}
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(content)))
		h.Set("Content-Length", strconv.FormatInt(end-start+1, 10))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		h.Set("Content-Length", strconv.Itoa(len(content)))
		w.WriteHeader(http.StatusOK)
	}
	if r.Method == http.MethodGet {
		s.write(w, o, content[start:end+1], tok)
	}
}

func (s *Server) write(w http.ResponseWriter, o Options, b []byte, tok string) {
	limit := int64(len(b))
	if o.CutEvery > 0 && o.CutEvery < limit {
		limit = o.CutEvery
	}
	if o.StallAfter > 0 && o.StallAfter < limit {
		limit = o.StallAfter
	}
	if tok != "" && o.ExpireAfterBytes > 0 {
		s.mu.Lock()
		left := o.ExpireAfterBytes - s.signed[tok]
		if left < limit {
			limit = max(left, 0)
		}
		s.signed[tok] += limit
		s.mu.Unlock()
	}
	w.Write(b[:limit])
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	if o.StallAfter > 0 && limit < int64(len(b)) {
		select {
		case <-s.stop:
		case <-time.After(time.Minute):
		}
	}
	// Returning with fewer bytes than Content-Length closes the connection.
}

func parseRange(h string, size int64) (int64, int64, bool) {
	if !strings.HasPrefix(h, "bytes=") || strings.Contains(h, ",") {
		return 0, 0, false
	}
	spec := strings.TrimPrefix(h, "bytes=")
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false
	}
	a, b := spec[:dash], spec[dash+1:]
	if a == "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n <= 0 {
			return 0, 0, false
		}
		return max(size-n, 0), size - 1, true
	}
	start, err := strconv.ParseInt(a, 10, 64)
	if err != nil || start >= size {
		return 0, 0, false
	}
	end := size - 1
	if b != "" {
		e, err := strconv.ParseInt(b, 10, 64)
		if err != nil || e < start {
			return 0, 0, false
		}
		end = min(e, size-1)
	}
	return start, end, true
}
