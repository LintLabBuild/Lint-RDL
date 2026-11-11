package gitdl

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var hosts = []string{"github.com", "gitlab.com", "codeberg.org", "git.sr.ht"}

func TestDetect(t *testing.T) {
	yes := map[string]string{
		"https://github.com/comfyanonymous/ComfyUI":     "https://github.com/comfyanonymous/ComfyUI.git",
		"https://github.com/comfyanonymous/ComfyUI.git": "https://github.com/comfyanonymous/ComfyUI.git",
		"https://github.com/comfyanonymous/ComfyUI/":    "https://github.com/comfyanonymous/ComfyUI.git",
		"https://github.com/owner/repo/tree/v1.2.3":     "https://github.com/owner/repo.git",
		"https://gitlab.com/group/proj/-/tree/main":     "https://gitlab.com/group/proj.git",
		"https://codeberg.org/forgejo/forgejo":          "https://codeberg.org/forgejo/forgejo.git",
		"https://git.sr.ht/~sircmpwn/scdoc":             "https://git.sr.ht/~sircmpwn/scdoc",
		"https://GitHub.com/Owner/Repo":                 "https://github.com/Owner/Repo.git",
	}
	for in, want := range yes {
		u, _ := url.Parse(in)
		r, ok := Detect(u, hosts)
		if !ok || r.CloneURL != want {
			t.Errorf("%s: %v %+v", in, ok, r)
		}
	}
	u, _ := url.Parse("https://github.com/owner/repo/tree/feature/x")
	if r, _ := Detect(u, hosts); r.Ref != "feature/x" {
		t.Fatalf("ref %q", r.Ref)
	}
	no := []string{
		"https://github.com/owner/repo/releases/download/v1/x.zip",
		"https://github.com/owner/repo/archive/refs/heads/main.zip",
		"https://github.com/owner/repo/blob/main/README.md",
		"https://github.com/owner/repo/issues/1",
		"https://github.com/owner",
		"https://github.com/settings/profile",
		"http://github.com/owner/repo",
		"https://evil.com/owner/repo.git",
		"https://github.com:8443/owner/repo",
		"https://user@github.com/owner/repo",
		"https://github.com/owner/repo/tree/--upload-pack=x",
		"https://github.com/owner/repo/tree/a..b",
		"https://github.com/owner/..",
		"https://git.sr.ht/user/repo",
	}
	for _, in := range no {
		u, _ := url.Parse(in)
		if r, ok := Detect(u, hosts); ok {
			t.Errorf("%s detected as repo: %+v", in, r)
		}
	}
}

func TestRewriteBlob(t *testing.T) {
	cases := map[string]string{
		"https://github.com/o/r/blob/main/models/a.safetensors": "https://raw.githubusercontent.com/o/r/main/models/a.safetensors",
		"https://gitlab.com/g/p/-/blob/main/x.json":             "https://gitlab.com/g/p/-/raw/main/x.json",
		"https://codeberg.org/o/r/src/branch/main/README.md":    "https://codeberg.org/o/r/raw/branch/main/README.md",
	}
	for in, want := range cases {
		u, _ := url.Parse(in)
		nu, ok := RewriteBlob(u)
		if !ok || nu.String() != want {
			t.Errorf("%s -> %v", in, nu)
		}
	}
	u, _ := url.Parse("https://github.com/o/r")
	if _, ok := RewriteBlob(u); ok {
		t.Fatal("repo page rewritten")
	}
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestCloneSafety(t *testing.T) {
	git := LookPath()
	if git == "" {
		t.Skip("git not installed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("needs symlinks and a file:// path; Windows behaviour is covered by core.symlinks=false and core.protectNTFS")
	}
	src := t.TempDir()
	run(t, src, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(src, "README.md"), []byte("hi"), 0o644)
	os.Symlink("/etc/passwd", filepath.Join(src, "link"))
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "sub", "a.txt"), []byte("a"), 0o644)
	run(t, src, "add", "-A")
	run(t, src, "commit", "-q", "-m", "init")

	testAllowFileProtocol = true
	defer func() { testAllowFileProtocol = false }()
	empty := t.TempDir()
	dest := filepath.Join(t.TempDir(), "clone")
	var lastPct int
	commit, err := Clone(context.Background(), CloneOptions{Git: git, URL: "file://" + src, Dest: dest, EmptyDir: empty,
		Progress: func(p int, _ int64) { lastPct = p }})
	if err != nil {
		t.Fatal(err)
	}
	_ = lastPct
	if len(commit) != 40 {
		t.Fatalf("commit %q", commit)
	}
	if fi, err := os.Lstat(filepath.Join(dest, "link")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("symlink must be checked out as a plain file")
	}
	hooks, _ := os.ReadDir(filepath.Join(dest, ".git", "hooks"))
	if len(hooks) != 0 {
		t.Fatal("sample hooks were installed")
	}
	if n, _ := CountFiles(dest); n != 3 {
		t.Fatalf("files %d", n)
	}
	// ext:: and other protocols are refused.
	_, err = Clone(context.Background(), CloneOptions{Git: git, URL: "ext::sh -c touch% /tmp/pwned", Dest: filepath.Join(t.TempDir(), "x"), EmptyDir: empty})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "not allowed") {
		t.Fatalf("ext protocol: %v", err)
	}
}
