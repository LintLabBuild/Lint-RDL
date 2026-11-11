package hf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/models/Comfy-Org/Wan/tree/main/split_files/vae" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`[{"type":"file","path":"split_files/vae/wan2.2_vae.safetensors","size":135,
		 "lfs":{"oid":"` + strings.Repeat("a", 64) + `","size":1409400000}},
		 {"type":"file","path":"split_files/vae/README.md","size":42}]`))
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()

	files, err := Lookup(context.Background(), srv.Client(), "Comfy-Org/Wan", "", []string{"split_files/vae/wan2.2_vae.safetensors", "split_files/vae/README.md"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if files[0].Size != 1409400000 || files[0].SHA256 != strings.Repeat("a", 64) {
		t.Fatalf("%+v", files[0])
	}
	if !strings.HasSuffix(files[0].URL, "/Comfy-Org/Wan/resolve/main/split_files/vae/wan2.2_vae.safetensors") {
		t.Fatal(files[0].URL)
	}
	if files[1].SHA256 != "" || files[1].Size != 42 {
		t.Fatalf("%+v", files[1])
	}
	if _, err := Lookup(context.Background(), srv.Client(), "Comfy-Org/Wan", "", []string{"split_files/vae/missing"}, ""); err == nil {
		t.Fatal("missing file should fail")
	}
}

func TestValidation(t *testing.T) {
	for _, r := range []string{"a", "a/b/c", "../x", "a/..", "a b/c", ""} {
		if ValidateRepo(r) == nil {
			t.Errorf("repo %q accepted", r)
		}
	}
	for _, p := range []string{"../x", "a/../../b", "/"} {
		if _, err := cleanPath(p); err == nil {
			t.Errorf("path %q accepted", p)
		}
	}
	if _, err := Lookup(context.Background(), http.DefaultClient, "a/b", "../main", []string{"x"}, ""); err == nil {
		t.Error("bad rev accepted")
	}
}
