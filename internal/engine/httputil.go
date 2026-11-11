package engine

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/policy"
)

// contentRange is a parsed "Content-Range: bytes a-b/total" header.
type contentRange struct {
	Start, End int64
	Total      int64 // -1 if "*"
	Unsat      bool  // "bytes */total"
}

func parseContentRange(h string) (contentRange, error) {
	cr := contentRange{Total: -1}
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(h, "bytes ") {
		return cr, fmt.Errorf("bad Content-Range %q", h)
	}
	h = strings.TrimSpace(h[len("bytes "):])
	slash := strings.IndexByte(h, '/')
	if slash < 0 {
		return cr, fmt.Errorf("bad Content-Range %q", h)
	}
	rng, total := h[:slash], h[slash+1:]
	if total != "*" {
		t, err := strconv.ParseInt(total, 10, 64)
		if err != nil || t < 0 {
			return cr, fmt.Errorf("bad Content-Range total %q", total)
		}
		cr.Total = t
	}
	if rng == "*" {
		cr.Unsat = true
		return cr, nil
	}
	dash := strings.IndexByte(rng, '-')
	if dash < 0 {
		return cr, fmt.Errorf("bad Content-Range %q", h)
	}
	s, err1 := strconv.ParseInt(rng[:dash], 10, 64)
	e, err2 := strconv.ParseInt(rng[dash+1:], 10, 64)
	if err1 != nil || err2 != nil || s < 0 || e < s {
		return cr, fmt.Errorf("bad Content-Range %q", h)
	}
	if cr.Total >= 0 && e >= cr.Total {
		return cr, fmt.Errorf("bad Content-Range %q", h)
	}
	cr.Start, cr.End = s, e
	return cr, nil
}

// parseRetryAfter parses seconds or an HTTP date; zero if absent/invalid.
func parseRetryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(h); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// isStrongETag reports whether an ETag may be used in If-Range.
func isStrongETag(e string) bool {
	return e != "" && !strings.HasPrefix(e, "W/") && strings.HasPrefix(e, `"`)
}

// filenameFromDisposition extracts the filename from Content-Disposition
// (filename* is decoded by mime.ParseMediaType).
func filenameFromDisposition(h string) string {
	if h == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(h)
	if err != nil {
		return ""
	}
	return params["filename"]
}

// filenameFromURL returns the unescaped last path segment.
func filenameFromURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	return policy.FilenameFromURLPath(u.Path)
}

// isHTMLType reports an HTML content type.
func isHTMLType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	}
	return mt == "text/html" || mt == "application/xhtml+xml"
}

func wantsHTML(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".html") || strings.HasSuffix(l, ".htm") || strings.HasSuffix(l, ".xhtml")
}

// signedInfo detects signed (expiring) URLs and estimates the expiry.
func signedInfo(u *url.URL, now time.Time) (signed bool, expires time.Duration) {
	if u == nil {
		return false, 0
	}
	q := u.Query()
	for k := range q {
		lk := strings.ToLower(k)
		switch lk {
		case "x-amz-signature", "signature", "sig", "x-goog-signature", "se", "token", "policy", "key-pair-id":
			signed = true
		}
	}
	if !signed {
		return false, 0
	}
	if d, e := q.Get("X-Amz-Date"), q.Get("X-Amz-Expires"); d != "" && e != "" {
		if t, err := time.Parse("20060102T150405Z", d); err == nil {
			if n, err := strconv.Atoi(e); err == nil {
				return true, t.Add(time.Duration(n) * time.Second).Sub(now)
			}
		}
	}
	if e := q.Get("Expires"); e != "" {
		if n, err := strconv.ParseInt(e, 10, 64); err == nil {
			return true, time.Unix(n, 0).Sub(now)
		}
	}
	return true, 0
}

// errorKind classifies attempt failures.
type errorKind int

const (
	kindRetry     errorKind = iota // network trouble etc.: back off and retry
	kindPermanent                  // needs user action
	kindDisk                       // not enough space: pause until it returns
	kindNoDir                      // save folder vanished: pause
	kindRestart                    // partial data invalid: restart from 0 now
)

type attemptError struct {
	kind  errorKind
	wait  time.Duration // for Retry-After
	err   error
	auth  bool // 401/403/410 (maybe an expired signed link)
	reset bool // partial file was discarded
}

func (e *attemptError) Error() string { return e.err.Error() }
func (e *attemptError) Unwrap() error { return e.err }

func retryErr(format string, a ...any) error {
	return &attemptError{kind: kindRetry, err: fmt.Errorf(format, a...)}
}

func permErr(format string, a ...any) error {
	return &attemptError{kind: kindPermanent, err: fmt.Errorf(format, a...)}
}

func classify(err error) *attemptError {
	var ae *attemptError
	if errors.As(err, &ae) {
		return ae
	}
	if errors.Is(err, policy.ErrBlocked) || errors.Is(err, policy.ErrPathBlocked) {
		return &attemptError{kind: kindPermanent, err: err}
	}
	if errors.Is(err, policy.ErrDiskSpace) {
		return &attemptError{kind: kindDisk, err: err}
	}
	return &attemptError{kind: kindRetry, err: err}
}
