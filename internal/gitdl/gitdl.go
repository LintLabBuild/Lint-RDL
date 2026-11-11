// Package gitdl downloads Git repositories by running the user's own Git,
// if it is installed. It is not built in: without Git, repository links
// get a clear message instead.
//
// Safety: only repository links on allowlisted public hosts (git_hosts)
// are cloned, over HTTPS only, without redirects, hooks, symlinks,
// submodules, credential prompts or other protocols. rdl never runs
// anything from the cloned repository.
package gitdl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is a parsed repository link.
type Repo struct {
	Host     string `json:"host"`
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	Ref      string `json:"ref,omitempty"` // branch or tag from /tree/<ref>
	CloneURL string `json:"clone_url"`
}

var segRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,100}$`)

// pagePaths on GitHub-like hosts that are not repositories.
var notOwners = map[string]bool{
	"settings": true, "orgs": true, "marketplace": true, "explore": true, "topics": true,
	"login": true, "join": true, "sponsors": true, "features": true, "about": true,
	"users": true, "search": true, "notifications": true, "new": true, "apps": true,
	"collections": true, "trending": true, "pricing": true, "enterprise": true, "help": true,
}

func hostAllowed(host string, hosts []string) bool {
	h := strings.ToLower(host)
	for _, a := range hosts {
		if h == strings.ToLower(strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

// RewriteBlob turns a "view file" link into the raw file link, so it is
// downloaded as a plain file:
//
//	github.com/o/r/blob/<ref>/<path>  -> raw.githubusercontent.com/o/r/<ref>/<path>
//	gitlab.com/o/r/-/blob/<ref>/<path> -> gitlab.com/o/r/-/raw/<ref>/<path>
//	codeberg.org/o/r/src/branch/<b>/<path> -> codeberg.org/o/r/raw/branch/<b>/<path>
func RewriteBlob(u *url.URL) (*url.URL, bool) {
	h := strings.ToLower(u.Hostname())
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	switch {
	case h == "github.com" && len(parts) >= 5 && parts[2] == "blob":
		nu := *u
		nu.Host = "raw.githubusercontent.com"
		nu.Path = "/" + strings.Join(append(parts[:2], parts[3:]...), "/")
		nu.RawPath, nu.RawQuery, nu.Fragment = "", "", ""
		return &nu, true
	case h == "gitlab.com" && strings.Contains(u.Path, "/-/blob/"):
		nu := *u
		nu.Path = strings.Replace(u.Path, "/-/blob/", "/-/raw/", 1)
		nu.RawPath, nu.Fragment = "", ""
		return &nu, true
	case (h == "codeberg.org" || h == "gitea.com") && len(parts) >= 5 && parts[2] == "src":
		nu := *u
		parts[2] = "raw"
		nu.Path = "/" + strings.Join(parts, "/")
		nu.RawPath, nu.Fragment = "", ""
		return &nu, true
	}
	return nil, false
}

// Detect reports whether u is a repository link on an allowed host:
//
//	https://host/owner/repo[.git][/]
//	https://host/owner/repo/tree/<ref>      (GitHub, Gitea, Codeberg)
//	https://host/owner/repo/-/tree/<ref>    (GitLab)
//
// Release downloads, archives, raw files and other pages are not
// repositories and are downloaded as files.
func Detect(u *url.URL, hosts []string) (*Repo, bool) {
	if u.Scheme != "https" || u.User != nil || u.RawQuery != "" && !strings.HasSuffix(u.Path, ".git") {
		return nil, false
	}
	host := strings.ToLower(u.Hostname())
	if !hostAllowed(host, hosts) || u.Port() != "" {
		return nil, false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return nil, false
	}
	owner, name := parts[0], strings.TrimSuffix(parts[1], ".git")
	if host == "git.sr.ht" && !strings.HasPrefix(owner, "~") {
		return nil, false
	}
	o := strings.TrimPrefix(owner, "~")
	if !segRe.MatchString(o) || !segRe.MatchString(name) || notOwners[strings.ToLower(owner)] || name == "." || name == ".." {
		return nil, false
	}
	r := &Repo{Host: host, Owner: owner, Name: name}
	rest := parts[2:]
	switch {
	case len(rest) == 0:
	case len(rest) >= 2 && rest[0] == "tree":
		r.Ref = strings.Join(rest[1:], "/")
	case len(rest) >= 3 && rest[0] == "-" && rest[1] == "tree":
		r.Ref = strings.Join(rest[2:], "/")
	default:
		return nil, false
	}
	if r.Ref != "" && !validRef(r.Ref) {
		return nil, false
	}
	r.CloneURL = fmt.Sprintf("https://%s/%s/%s.git", host, owner, name)
	if host == "git.sr.ht" {
		r.CloneURL = fmt.Sprintf("https://%s/%s/%s", host, owner, name)
	}
	return r, true
}

var refRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)

func validRef(ref string) bool {
	return refRe.MatchString(ref) && !strings.HasPrefix(ref, "-") && !strings.Contains(ref, "..") && !strings.HasSuffix(ref, "/")
}

// LookPath finds the git executable; "" if Git is not installed.
func LookPath() string {
	p, err := exec.LookPath("git")
	if err != nil {
		return ""
	}
	return p
}

// ErrNoGit explains how to get repository support.
var ErrNoGit = errors.New("this is a Git repository link. Install Git (https://git-scm.com) to download repositories, or paste a release or file link instead")

// ---- probe ----

// Info is what rdl can say about a repository before cloning.
type Info struct {
	Description   string `json:"description,omitempty"`
	DefaultBranch string `json:"default_branch,omitempty"`
	SizeKB        int64  `json:"size_kb"` // -1 unknown (GitHub API reports the packed size)
	Archived      bool   `json:"archived,omitempty"`
	License       string `json:"license,omitempty"`
	Files         []File `json:"files,omitempty"`
	FileCount     int    `json:"file_count"`
	FolderCount   int    `json:"folder_count"`
	FilesSize     int64  `json:"files_size"`
	Truncated     bool   `json:"truncated,omitempty"`
}

// File is one file in the repository tree.
type File struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Dir  bool   `json:"dir,omitempty"`
}

// GitHubAPI is the API base (overridable for tests).
var GitHubAPI = "https://api.github.com"

// ProbeGitHub reads repository metadata and the file tree from the GitHub
// API. Other hosts return only what `git ls-remote` can tell.
func ProbeGitHub(ctx context.Context, client *http.Client, r *Repo) (*Info, error) {
	if r.Host != "github.com" {
		return nil, errors.New("file list is only available for GitHub repositories")
	}
	var meta struct {
		Description   string `json:"description"`
		DefaultBranch string `json:"default_branch"`
		Size          int64  `json:"size"`
		Archived      bool   `json:"archived"`
		License       *struct {
			SPDX string `json:"spdx_id"`
		} `json:"license"`
	}
	if err := getJSON(ctx, client, fmt.Sprintf("%s/repos/%s/%s", GitHubAPI, url.PathEscape(r.Owner), url.PathEscape(r.Name)), &meta); err != nil {
		return nil, err
	}
	info := &Info{Description: meta.Description, DefaultBranch: meta.DefaultBranch, SizeKB: meta.Size, Archived: meta.Archived}
	if meta.License != nil {
		info.License = meta.License.SPDX
	}
	ref := r.Ref
	if ref == "" {
		ref = meta.DefaultBranch
	}
	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
			Size int64  `json:"size"`
		} `json:"tree"`
		Truncated bool `json:"truncated"`
	}
	if err := getJSON(ctx, client, fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", GitHubAPI, url.PathEscape(r.Owner), url.PathEscape(r.Name), url.PathEscape(ref)), &tree); err != nil {
		return info, nil // metadata is still useful
	}
	info.Truncated = tree.Truncated
	for _, e := range tree.Tree {
		switch e.Type {
		case "blob":
			info.FileCount++
			info.FilesSize += e.Size
			if len(info.Files) < 500 {
				info.Files = append(info.Files, File{Path: e.Path, Size: e.Size})
			} else {
				info.Truncated = true
			}
		case "tree":
			info.FolderCount++
		}
	}
	return info, nil
}

func getJSON(ctx context.Context, client *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "rdl")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return errors.New("repository not found (or private)")
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("GitHub API: %s", resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

// ---- clone ----

// CloneOptions configures Clone.
type CloneOptions struct {
	Git         string // path to git
	URL         string // https clone URL (already validated by Detect)
	Ref         string
	FullHistory bool
	Dest        string // must not exist yet
	EmptyDir    string // an empty folder used as hooks path and template
	// Progress receives the percentage (0-100) and bytes received so far.
	Progress func(percent int, bytes int64)
}

// safetyConfig is passed with -c on every git command.
func safetyConfig(emptyDir string) []string {
	cfg := []string{
		"protocol.allow=never",
		"protocol.https.allow=always",
		"http.followRedirects=false",
		"core.hooksPath=" + emptyDir,
		"core.symlinks=false",
		"core.fsmonitor=false",
		"core.sshCommand=false",
		"credential.helper=",
		"submodule.recurse=false",
		"transfer.fsckObjects=true",
		"init.templateDir=" + emptyDir,
		"advice.detachedHead=false",
	}
	if runtime.GOOS == "windows" {
		cfg = append(cfg, "core.longpaths=true", "core.protectNTFS=true")
	}
	if testAllowFileProtocol {
		cfg = append(cfg, "protocol.file.allow=always")
	}
	var args []string
	for _, c := range cfg {
		args = append(args, "-c", c)
	}
	return args
}

// testAllowFileProtocol lets tests clone a local repository.
var testAllowFileProtocol bool

// Env returns a minimal environment for git: no prompts, no askpass.
func gitEnv() []string {
	env := os.Environ()
	return append(env,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
		"SSH_ASKPASS=",
		"GCM_INTERACTIVE=never",
		"GIT_PROTOCOL_FROM_USER=0",
		"GIT_CONFIG_PARAMETERS=",
	)
}

// ErrPermanent wraps git failures that retrying won't fix.
var ErrPermanent = errors.New("git")

var (
	pctRe   = regexp.MustCompile(`(Receiving objects|Resolving deltas|Updating files|Counting objects|Compressing objects):\s+(\d+)%`)
	bytesRe = regexp.MustCompile(`([\d.]+) (KiB|MiB|GiB|bytes)`)
)

// Clone runs git clone. A failed or cancelled clone removes Dest.
func Clone(ctx context.Context, o CloneOptions) (commit string, err error) {
	if o.Git == "" {
		return "", ErrNoGit
	}
	args := safetyConfig(o.EmptyDir)
	args = append(args, "clone", "--progress", "--no-recurse-submodules", "--template="+o.EmptyDir)
	if !o.FullHistory {
		args = append(args, "--depth=1")
	}
	if o.Ref != "" {
		args = append(args, "--branch="+o.Ref)
	}
	args = append(args, "--", o.URL, o.Dest)
	cmd := exec.CommandContext(ctx, o.Git, args...)
	cmd.Env = gitEnv()
	cmd.Dir = o.EmptyDir
	cmd.WaitDelay = 5 * time.Second
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	var tail []string
	sc := bufio.NewScanner(stderr)
	sc.Split(splitCRLF)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) != "" {
			tail = append(tail, line)
			if len(tail) > 8 {
				tail = tail[1:]
			}
		}
		if o.Progress != nil {
			if m := pctRe.FindStringSubmatch(line); m != nil && m[1] == "Receiving objects" {
				p, _ := strconv.Atoi(m[2])
				var b int64
				if bm := bytesRe.FindStringSubmatch(line); bm != nil {
					f, _ := strconv.ParseFloat(bm[1], 64)
					switch bm[2] {
					case "KiB":
						f *= 1 << 10
					case "MiB":
						f *= 1 << 20
					case "GiB":
						f *= 1 << 30
					}
					b = int64(f)
				}
				o.Progress(p, b)
			}
		}
	}
	werr := cmd.Wait()
	if werr != nil {
		os.RemoveAll(o.Dest)
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		msg := strings.Join(tail, " | ")
		low := strings.ToLower(msg)
		if strings.Contains(low, "not found") || strings.Contains(low, "could not read username") ||
			strings.Contains(low, "authentication") || strings.Contains(low, "remote branch") ||
			strings.Contains(low, "redirect") || strings.Contains(low, "not allowed") {
			return "", fmt.Errorf("%w: %s", ErrPermanent, msg)
		}
		return "", fmt.Errorf("git clone failed: %s", msg)
	}
	out, err := exec.CommandContext(ctx, o.Git, append(safetyConfig(o.EmptyDir), "-C", o.Dest, "rev-parse", "HEAD")...).Output()
	if err == nil {
		commit = strings.TrimSpace(string(out))
	}
	return commit, nil
}

func splitCRLF(data []byte, atEOF bool) (int, []byte, error) {
	for i, c := range data {
		if c == '\r' || c == '\n' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// CountFiles counts files below dir, skipping .git.
func CountFiles(dir string) (files int, size int64) {
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if d.Type().IsRegular() {
			files++
			if fi, err := d.Info(); err == nil {
				size += fi.Size()
			}
		}
		return nil
	})
	return
}
