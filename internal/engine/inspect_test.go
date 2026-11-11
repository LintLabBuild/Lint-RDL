package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/gitdl"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
)

func serveFiles(t *testing.T, files map[string][]byte, types map[string]string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ct := types[r.URL.Path]; ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProbeContents(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	for _, n := range []string{"ComfyUI/main.py", "ComfyUI/models/", "ComfyUI/run_nvidia_gpu.bat"} {
		w, _ := zw.Create(n)
		w.Write(bytes.Repeat([]byte("x"), 1000))
	}
	zw.Close()
	index := []byte(`<html><head><title>Index of /pub/</title></head><body><a href="../">..</a><a href="a.bin">a.bin</a><a href="b.zip">b.zip</a><a href="sub/">sub/</a></body></html>`)
	srv := serveFiles(t, map[string][]byte{
		"/portable.zip":    zb.Bytes(),
		"/pub/":            index,
		"/cat.jpg":         append([]byte("MZ\x90\x00"), make([]byte, 100)...),
		"/live/index.m3u8": []byte("#EXTM3U\n"),
		"/page.bin":        []byte("<!DOCTYPE html><html><body>login</body></html>"),
	}, map[string]string{
		"/pub/":            "text/html",
		"/live/index.m3u8": "application/vnd.apple.mpegurl",
		"/page.bin":        "text/html",
	})
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	ctx := context.Background()

	r, err := m.Probe(ctx, srv.URL+"/portable.zip")
	if err != nil {
		t.Fatal(err)
	}
	if r.Type.Kind != "archive" || r.Contents == nil || r.Contents.Files != 2 || !strings.Contains(r.Contents.Summary, "program") {
		t.Fatalf("zip: %+v %+v", r.Type, r.Contents)
	}

	r, err = m.Probe(ctx, srv.URL+"/pub/")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "folder" || r.Contents.Files != 2 || r.Contents.Folders != 1 || !strings.Contains(r.Verdict, "--all") {
		t.Fatalf("folder: %+v", r)
	}

	r, err = m.Probe(ctx, srv.URL+"/cat.jpg")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Type.Executable || len(r.Warnings) == 0 || !strings.Contains(r.Warnings[0], "disguised") {
		t.Fatalf("disguised exe: %+v", r)
	}

	if _, err := m.Probe(ctx, srv.URL+"/live/index.m3u8"); !errors.Is(err, policy.ErrBlocked) {
		t.Fatalf("m3u8: %v", err)
	}
	r, _ = m.Probe(ctx, srv.URL+"/page.bin")
	if !strings.Contains(r.Verdict, "web page") {
		t.Fatalf("html page: %s", r.Verdict)
	}
}

func TestStreamPlaylistDownloadRefused(t *testing.T) {
	srv := serveFiles(t, map[string][]byte{"/v": []byte("#EXTM3U\n")}, map[string]string{"/v": "application/x-mpegURL"})
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, err := m.Add(AddRequest{URL: srv.URL + "/v"})
	if err != nil {
		t.Fatal(err)
	}
	v := waitDone(t, m, job.ID, 10*time.Second)
	if v.State != "failed" || !strings.Contains(v.Error, "streaming playlist") {
		t.Fatalf("%s %s", v.State, v.Error)
	}
}

func TestGitLinks(t *testing.T) {
	e := newEnv(t)
	e.opts.GitHosts = []string{"github.com"}
	m := e.manager(t)
	defer m.Close()
	if _, err := m.Add(AddRequest{URL: "https://github.com/comfyanonymous/ComfyUI"}); !errors.Is(err, gitdl.ErrNoGit) {
		t.Fatalf("without git: %v", err)
	}
	r, err := m.Probe(context.Background(), "https://github.com/comfyanonymous/ComfyUI")
	if err != nil || r.Kind != "git" || r.Git.GitInstalled || !strings.Contains(r.Verdict, "Install Git") {
		t.Fatalf("%v %+v", err, r)
	}
	e.opts.GitPath = "/usr/bin/git"
	m2 := e.manager(t)
	defer m2.Close()
	job, err := m2.Add(AddRequest{URL: "https://github.com/comfyanonymous/ComfyUI/tree/v0.3.0"})
	if err != nil || job.Kind != "git" || job.Name != "ComfyUI" || job.GitRef != "v0.3.0" || job.GitURL != "https://github.com/comfyanonymous/ComfyUI.git" {
		t.Fatalf("%v %+v", err, job)
	}
	// blob links become raw file downloads, not clones
	job, err = m2.Add(AddRequest{URL: "https://github.com/o/r/blob/main/models/x.safetensors"})
	if err != nil || job.Kind != "" || !strings.HasPrefix(job.URL, "https://raw.githubusercontent.com/o/r/main/") || job.Name != "x.safetensors" {
		t.Fatalf("%v %+v", err, job)
	}
}
