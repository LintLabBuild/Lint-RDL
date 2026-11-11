package favorites

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxBookmarks(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".config", "gtk-3.0"), 0o755)
	os.MkdirAll(filepath.Join(home, ".local", "share"), 0o755)
	os.WriteFile(filepath.Join(home, ".config", "gtk-3.0", "bookmarks"), []byte(
		"file:///home/me/AI%20Models Models\nfile:///home/me/Projects\nsftp://server/x\nsmb://nas/share Share\n"), 0o644)
	os.WriteFile(filepath.Join(home, ".local", "share", "user-places.xbel"), []byte(`<?xml version="1.0"?>
<xbel><bookmark href="file:///home/me/Projects"><title>Projects</title></bookmark>
<bookmark href="file:///data/ComfyUI"><title>Comfy</title></bookmark>
<bookmark href="remote:/"><title>Network</title></bookmark></xbel>`), 0o644)
	got := dedupe(linuxBookmarks(home, "", ""))
	want := []string{"/home/me/AI Models", "/home/me/Projects", "/data/ComfyUI"}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i, w := range want {
		if got[i].Path != filepath.FromSlash(w) {
			t.Errorf("%d: %s want %s", i, got[i].Path, w)
		}
	}
	if got[0].Label != "Models" || got[2].Label != "Comfy" {
		t.Fatalf("%+v", got)
	}
}
