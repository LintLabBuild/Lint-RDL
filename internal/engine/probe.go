package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/policy"
)

// Resumable verdicts.
const (
	ResumableYes          = "YES"
	ResumableNoRanges     = "NO (server ignores ranges)"
	ResumableNoLength     = "NO (size unknown / streamed)"
	ResumableRiskyEncoded = "RISKY (compressed transfer)"
	ResumableRiskyNoTag   = "RISKY (no ETag or Last-Modified)"
)

// ProbeResult is what `rdl probe` reports, without downloading the file.
type ProbeResult struct {
	URL            string        `json:"url"`
	FinalURL       string        `json:"final_url"`
	Redirects      int           `json:"redirects"`
	Signed         bool          `json:"signed,omitempty"`
	ExpiresIn      time.Duration `json:"expires_in,omitempty"`
	Status         int           `json:"status"`
	Size           int64         `json:"size"` // -1 unknown
	Resumable      string        `json:"resumable"`
	CanResume      bool          `json:"can_resume"`
	ETag           string        `json:"etag,omitempty"`
	LastModified   string        `json:"last_modified,omitempty"`
	SHA256         string        `json:"sha256,omitempty"`
	ContentType    string        `json:"content_type,omitempty"`
	Encoding       string        `json:"encoding,omitempty"`
	Filename       string        `json:"filename"`
	FilenameSource string        `json:"filename_source"`
	Verdict        string        `json:"verdict"`
	Notes          []string      `json:"notes,omitempty"`
}

func newReq(ctx context.Context, method, u string, ua string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", ua)
	return req, nil
}

// Probe inspects a URL: final location, size, resumability, version
// stamps, checksum hints and the file name, without downloading it.
func Probe(ctx context.Context, client *http.Client, up *policy.URLPolicy, rawURL, userAgent string) (*ProbeResult, error) {
	u, err := up.CheckRawURL(rawURL)
	if err != nil {
		return nil, err
	}
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	res := &ProbeResult{URL: u.String(), Size: -1}
	countRedirects := func(r *http.Response) int {
		n := 0
		for req := r.Request; req != nil && req.Response != nil; req = req.Response.Request {
			n++
		}
		return n
	}

	// Step 1: HEAD, falling back to GET bytes=0-0 if HEAD is refused.
	var head *http.Response
	req, err := newReq(ctx, http.MethodHead, u.String(), userAgent)
	if err != nil {
		return nil, err
	}
	head, err = client.Do(req)
	if err == nil && (head.StatusCode == http.StatusMethodNotAllowed || head.StatusCode == http.StatusForbidden || head.StatusCode == http.StatusNotImplemented) {
		head.Body.Close()
		head = nil
		res.Notes = append(res.Notes, "server refused HEAD; used a 1-byte GET instead")
	} else if err != nil {
		if policyErr(err) {
			return nil, err
		}
		res.Notes = append(res.Notes, "HEAD failed: "+shortErr(err))
		head = nil
	}
	if head == nil {
		req, err := newReq(ctx, http.MethodGet, u.String(), userAgent)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Range", "bytes=0-0")
		head, err = client.Do(req)
		if err != nil {
			return nil, err
		}
		io.Copy(io.Discard, io.LimitReader(head.Body, 4096))
		head.Body.Close()
		if head.StatusCode == http.StatusPartialContent {
			if cr, err := parseContentRange(head.Header.Get("Content-Range")); err == nil {
				res.Size = cr.Total
			}
		} else if head.StatusCode == http.StatusOK {
			res.Size = head.ContentLength
		}
	} else {
		head.Body.Close()
		if head.StatusCode == http.StatusOK {
			res.Size = head.ContentLength
		}
	}
	res.Status = head.StatusCode
	res.FinalURL = head.Request.URL.String()
	res.Redirects = countRedirects(head)
	res.Signed, res.ExpiresIn = signedInfo(head.Request.URL, time.Now())
	res.ETag = head.Header.Get("ETag")
	res.LastModified = head.Header.Get("Last-Modified")
	res.ContentType = head.Header.Get("Content-Type")
	res.Encoding = head.Header.Get("Content-Encoding")
	if x := strings.Trim(head.Header.Get("X-Linked-ETag"), `"`); isHexSHA256(x) {
		res.SHA256 = strings.ToLower(x)
	} else if isHexSHA256(strings.Trim(res.ETag, `"`)) {
		res.SHA256 = strings.ToLower(strings.Trim(res.ETag, `"`))
		res.Notes = append(res.Notes, "ETag looks like a SHA-256; will be checked at the end")
	}
	if xs := head.Header.Get("X-Linked-Size"); xs != "" && res.Size < 0 {
		fmt.Sscan(xs, &res.Size)
	}

	if head.StatusCode >= 400 {
		res.Resumable = "NO"
		res.Verdict = fmt.Sprintf("Server answered %d %s. Check the link.", head.StatusCode, http.StatusText(head.StatusCode))
		pickName(res, head, u)
		return res, nil
	}

	// Step 2: GET bytes=1-1. Only a real 206 with a matching Content-Range counts.
	req, err = newReq(ctx, http.MethodGet, u.String(), userAgent)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", "bytes=1-1")
	rr, err := client.Do(req)
	rangeOK := false
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(rr.Body, 4096))
		rr.Body.Close()
		if rr.StatusCode == http.StatusPartialContent {
			cr, err := parseContentRange(rr.Header.Get("Content-Range"))
			if err == nil && cr.Start == 1 && cr.End == 1 && !strings.Contains(rr.Header.Get("Content-Type"), "multipart/byteranges") {
				rangeOK = true
				if res.Size < 0 {
					res.Size = cr.Total
				}
			}
		}
		if res.Encoding == "" {
			res.Encoding = rr.Header.Get("Content-Encoding")
		}
	} else if policyErr(err) {
		return nil, err
	} else {
		res.Notes = append(res.Notes, "range test failed: "+shortErr(err))
	}

	encoded := res.Encoding != "" && !strings.EqualFold(res.Encoding, "identity")
	switch {
	case !rangeOK:
		res.Resumable = ResumableNoRanges
		if res.Size < 0 {
			res.Resumable = ResumableNoLength
		}
	case res.Size < 0:
		res.Resumable = ResumableNoLength
	case encoded:
		res.Resumable = ResumableRiskyEncoded
	case res.ETag == "" && res.LastModified == "":
		res.Resumable = ResumableRiskyNoTag
		res.CanResume = true
	default:
		res.Resumable = ResumableYes
		res.CanResume = true
	}
	pickName(res, head, u)

	var v []string
	if isHTMLType(res.ContentType) && !wantsHTML(res.Filename) {
		v = append(v, "Warning: server sends a web page (text/html), not a file. It may be a login or error page.")
	}
	switch {
	case res.CanResume && res.Resumable == ResumableYes:
		v = append(v, "Safe to download. Resume will work.")
	case res.CanResume:
		v = append(v, "Resume should work, but rdl can't detect a changed file; the SHA-256 check at the end is the safety net.")
	default:
		v = append(v, "Download works, but an interruption restarts it from zero.")
	}
	if res.Signed {
		v = append(v, "Signed URL: rdl re-requests the original link when it expires.")
	}
	res.Verdict = strings.Join(v, " ")
	return res, nil
}

func pickName(res *ProbeResult, resp *http.Response, orig *url.URL) {
	if n := filenameFromDisposition(resp.Header.Get("Content-Disposition")); n != "" {
		res.Filename = policy.SanitizeFilename(n, "")
		res.FilenameSource = "Content-Disposition"
	}
	fromURL := policy.SanitizeFilename(filenameFromURL(orig), "")
	if res.Filename == "" {
		res.Filename = fromURL
		res.FilenameSource = "URL"
	} else if fromURL != "" && fromURL == res.Filename {
		res.FilenameSource = "URL; Content-Disposition agrees"
	}
	if res.Filename == "" {
		res.Filename = "download"
		res.FilenameSource = "none (default)"
	}
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func policyErr(err error) bool {
	return classify(err).kind == kindPermanent
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}
