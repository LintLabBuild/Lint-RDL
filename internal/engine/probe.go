package engine

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/gitdl"
	"github.com/lintlabbuild/lint-rdl/internal/inspect"
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

	// Kind is "file", "folder" (a web folder listing) or "git".
	Kind     string            `json:"kind"`
	Type     *inspect.Type     `json:"type,omitempty"`
	Contents *inspect.Contents `json:"contents,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
	Git      *GitProbe         `json:"git,omitempty"`
}

// GitProbe describes a repository link.
type GitProbe struct {
	Repo         gitdl.Repo  `json:"repo"`
	GitInstalled bool        `json:"git_installed"`
	Info         *gitdl.Info `json:"info,omitempty"`
}

// Probe inspects a link with the manager's policies: files, web folders
// and Git repositories.
func (m *Manager) Probe(ctx context.Context, rawURL string) (*ProbeResult, error) {
	u, err := m.o.URLPolicy.CheckRawURL(rawURL)
	if err != nil {
		return nil, err
	}
	var notes []string
	if raw, ok := gitdl.RewriteBlob(u); ok {
		notes = append(notes, "file view link turned into the raw file link: "+raw.String())
		u = raw
	}
	if repo, ok := gitdl.Detect(u, m.o.GitHosts); ok {
		res := &ProbeResult{URL: u.String(), Kind: "git", Size: -1, Resumable: "NO (Git clone restarts if interrupted)",
			Git: &GitProbe{Repo: *repo, GitInstalled: m.o.GitPath != ""}, Filename: policy.SanitizeFilename(repo.Name, "repo"), FilenameSource: "repository name"}
		res.Type = &inspect.Type{Kind: "repository", Description: "Git repository"}
		if info, err := gitdl.ProbeGitHub(ctx, m.client, repo); err == nil {
			res.Git.Info = info
			if info.FileCount > 0 {
				res.Size = info.FilesSize
				c := &inspect.Contents{Kind: "git", Files: info.FileCount, Folders: info.FolderCount, TotalSize: info.FilesSize, Truncated: info.Truncated}
				for _, f := range info.Files {
					c.Entries = append(c.Entries, inspect.Entry{Name: f.Path, Size: f.Size})
				}
				c.Summary = fmt.Sprintf("repository with %d files in %d folders, %s", info.FileCount, info.FolderCount, policy.HumanBytes(info.FilesSize))
				res.Contents = c
			}
		} else {
			notes = append(notes, "file list unavailable: "+err.Error())
		}
		if m.o.GitPath == "" {
			res.Verdict = gitdl.ErrNoGit.Error()
		} else {
			hist := "latest commit only; set git_full_history: true for the full history"
			if m.o.GitFullHistory {
				hist = "full history"
			}
			res.Verdict = "Will be cloned with your Git (" + hist + "). Nothing in it is run. If interrupted, the clone starts over."
		}
		res.Notes = notes
		return res, nil
	}
	res, err := probeHTTP(ctx, m.client, u, m.o.UserAgent)
	if res != nil {
		res.Notes = append(notes, res.Notes...)
	}
	return res, err
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

// Probe inspects a plain URL (no Git handling): final location, size,
// resumability, version stamps, checksum hints, file name, type and
// contents, without downloading it.
func Probe(ctx context.Context, client *http.Client, up *policy.URLPolicy, rawURL, userAgent string) (*ProbeResult, error) {
	u, err := up.CheckRawURL(rawURL)
	if err != nil {
		return nil, err
	}
	return probeHTTP(ctx, client, u, userAgent)
}

func probeHTTP(ctx context.Context, client *http.Client, u *url.URL, userAgent string) (*ProbeResult, error) {
	var err error
	if userAgent == "" {
		userAgent = DefaultUserAgent
	}
	res := &ProbeResult{URL: u.String(), Size: -1, Kind: "file"}
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
		switch head.StatusCode {
		case http.StatusNotFound, http.StatusGone:
			res.Verdict = fmt.Sprintf("The file doesn't exist at this link (%d): wrong link, removed, or an expired temporary link.", head.StatusCode)
		case http.StatusUnauthorized, http.StatusForbidden:
			res.Verdict = fmt.Sprintf("Access denied (%d): the link may have expired, or it needs a login.", head.StatusCode)
		default:
			res.Verdict = fmt.Sprintf("Server answered %d %s. Check the link.", head.StatusCode, http.StatusText(head.StatusCode))
		}
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
	inspectContent(ctx, client, res, rangeOK, userAgent)
	if res.Kind == "folder" {
		res.Resumable = "-"
		res.Verdict = fmt.Sprintf("This is a %s. Download its files with `rdl get --all <url>` (subfolders are not included).", res.Contents.Summary)
		return res, nil
	}
	if policy.IsStreamManifest(res.ContentType, res.Filename) {
		return nil, fmt.Errorf("%w: %s", policy.ErrBlocked, policy.ErrStreamManifest)
	}

	var v []string
	if (isHTMLType(res.ContentType) || (res.Type != nil && res.Type.Kind == "html")) && !wantsHTML(res.Filename) {
		v = append(v, "Warning: this link opens a web page, not a file (maybe a login, error or player page); rdl will refuse to save it.")
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

// sampleSize is how much of the start of a file probe reads to detect its
// type (the bytes are only inspected, never passed on).
const sampleSize = 64 << 10

func readSample(ctx context.Context, client *http.Client, u, ua string, n int64, ranged bool) ([]byte, error) {
	req, err := newReq(ctx, http.MethodGet, u, ua)
	if err != nil {
		return nil, err
	}
	if ranged {
		req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", n-1))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil, fmt.Errorf("compressed transfer")
	}
	return io.ReadAll(io.LimitReader(resp.Body, n))
}

// inspectContent fills Type, Contents and Warnings.
func inspectContent(ctx context.Context, client *http.Client, res *ProbeResult, rangeOK bool, ua string) {
	sample, err := readSample(ctx, client, res.FinalURL, ua, sampleSize, rangeOK)
	if err != nil {
		res.Notes = append(res.Notes, "could not read a sample to detect the type: "+shortErr(err))
	}
	typ, mismatch := inspect.Sniff(sample, res.Filename, res.ContentType)
	res.Type = &typ
	if mismatch != "" {
		res.Warnings = append(res.Warnings, mismatch+".")
	}
	if typ.Executable {
		res.Warnings = append(res.Warnings, "This is a program or script. rdl never runs it; on Windows it is marked as downloaded from the internet.")
	}
	switch {
	case typ.Kind == "html":
		if final, err := url.Parse(res.FinalURL); err == nil && inspect.IsFolderListing(sample) {
			res.Kind = "folder"
			res.Contents = inspect.ParseFolderListing(final, sample)
		}
	case typ.Description == "ZIP archive" || strings.Contains(typ.Description, "(ZIP"):
		if !rangeOK || res.Size <= 0 {
			res.Notes = append(res.Notes, "archive contents can't be listed: server doesn't support ranges")
			return
		}
		ra := &inspect.RangeReaderAt{Ctx: ctx, Client: client, URL: res.FinalURL, Size: res.Size, UA: ua}
		if c, err := inspect.ListZip(ra, res.Size); err == nil {
			res.Contents = c
		} else {
			res.Notes = append(res.Notes, "archive contents not listed: "+shortErr(err))
		}
	case typ.Description == "safetensors model":
		hdr := sample
		if n, err := safetensorsLen(sample); err == nil && int64(len(sample)) < 8+n {
			if !rangeOK {
				return
			}
			if hdr, err = readSample(ctx, client, res.FinalURL, ua, 8+n, true); err != nil {
				return
			}
		}
		if ts, err := inspect.ParseSafetensors(hdr); err == nil {
			res.Contents = &inspect.Contents{Kind: "safetensors", Files: 1, TotalSize: res.Size, Summary: ts.Summary()}
			for _, name := range ts.Sample {
				res.Contents.Entries = append(res.Contents.Entries, inspect.Entry{Name: name, Size: -1})
			}
		}
	}
}

func safetensorsLen(b []byte) (int64, error) {
	if len(b) < 8 {
		return 0, fmt.Errorf("short")
	}
	n := int64(b[0]) | int64(b[1])<<8 | int64(b[2])<<16 | int64(b[3])<<24 | int64(b[4])<<32 | int64(b[5])<<40 | int64(b[6])<<48 | int64(b[7])<<56
	if n < 2 || n > 32<<20 {
		return 0, fmt.Errorf("bad header")
	}
	return n, nil
}
