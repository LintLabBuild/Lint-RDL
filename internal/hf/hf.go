// Package hf looks up file sizes and SHA-256 hashes from the Hugging Face
// API so rdl can verify model downloads (spec §5.3).
package hf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// BaseURL is the Hugging Face hub (overridable for tests).
var BaseURL = "https://huggingface.co"

// File describes one file in a repo.
type File struct {
	Repo   string `json:"repo"`
	Rev    string `json:"rev"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"` // only for LFS files
	URL    string `json:"url"`
}

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
	revRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

// ValidateRepo checks "owner/name".
func ValidateRepo(repo string) error {
	if !repoRe.MatchString(repo) || strings.Contains(repo, "..") {
		return fmt.Errorf("invalid Hugging Face repo %q (expected owner/name)", repo)
	}
	return nil
}

func cleanPath(p string) (string, error) {
	p = strings.TrimPrefix(strings.ReplaceAll(p, `\`, "/"), "/")
	c := path.Clean(p)
	if c == "." || c != p || strings.HasPrefix(c, "../") || c == ".." || strings.Contains(c, "/../") {
		return "", fmt.Errorf("invalid file path %q", p)
	}
	return c, nil
}

type treeEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	LFS  *struct {
		Oid  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"lfs"`
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// Lookup returns size and hash for each path. Paths in the same folder
// share one API call. token may be empty (public repos).
func Lookup(ctx context.Context, client *http.Client, repo, rev string, paths []string, token string) ([]File, error) {
	if err := ValidateRepo(repo); err != nil {
		return nil, err
	}
	if rev == "" {
		rev = "main"
	}
	if !revRe.MatchString(rev) || strings.Contains(rev, "..") {
		return nil, fmt.Errorf("invalid revision %q", rev)
	}
	byDir := map[string][]treeEntry{}
	var out []File
	for _, raw := range paths {
		p, err := cleanPath(raw)
		if err != nil {
			return nil, err
		}
		dir := path.Dir(p)
		if dir == "." {
			dir = ""
		}
		entries, ok := byDir[dir]
		if !ok {
			entries, err = listTree(ctx, client, repo, rev, dir, token)
			if err != nil {
				return nil, err
			}
			byDir[dir] = entries
		}
		f := File{Repo: repo, Rev: rev, Path: p, Size: -1,
			URL: fmt.Sprintf("%s/%s/resolve/%s/%s", BaseURL, repo, url.PathEscape(rev), escapePath(p))}
		found := false
		for _, e := range entries {
			if e.Path == p && e.Type == "file" {
				found = true
				f.Size = e.Size
				if e.LFS != nil {
					f.Size = e.LFS.Size
					if len(e.LFS.Oid) == 64 {
						f.SHA256 = strings.ToLower(e.LFS.Oid)
					}
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("%s not found in %s@%s", p, repo, rev)
		}
		out = append(out, f)
	}
	return out, nil
}

func listTree(ctx context.Context, client *http.Client, repo, rev, dir, token string) ([]treeEntry, error) {
	u := fmt.Sprintf("%s/api/models/%s/tree/%s", BaseURL, repo, url.PathEscape(rev))
	if dir != "" {
		u += "/" + escapePath(dir)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("Hugging Face API: %d (gated or private repo? set a token)", resp.StatusCode)
		}
		return nil, fmt.Errorf("Hugging Face API: %s", resp.Status)
	}
	var entries []treeEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&entries); err != nil {
		return nil, fmt.Errorf("Hugging Face API: %w", err)
	}
	return entries, nil
}

// IsHFHost reports whether u points at huggingface.co (where a token may
// be sent).
func IsHFHost(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	base, _ := url.Parse(BaseURL)
	return h == strings.ToLower(base.Hostname())
}
