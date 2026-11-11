package policy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/lintlabbuild/lint-rdl/internal/favorites"
)

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"model.safetensors":     "model.safetensors",
		"../../etc/passwd":      "passwd",
		`..\..\Windows\win.ini`: "win.ini",
		`C:\Users\x\evil.exe`:   "evil.exe",
		`\\?\C:\x\y.txt`:        "y.txt",
		"file.txt:hidden":       "file.txt_hidden",
		"a<b>c\"d|e?f*g":        "a_b_c_d_e_f_g",
		"CON":                   "_CON",
		"con.txt":               "_con.txt",
		"LPT9.tar.gz":           "_LPT9.tar.gz",
		"COM1 .txt":             "_COM1 .txt",
		"nul":                   "_nul",
		"name.   ":              "name",
		"trailing...":           "trailing",
		"photo\u202egpj.exe":    "photogpj.exe",
		"zero\u200bwidth.txt":   "zerowidth.txt",
		"\u2066iso\u2069.bin":   "iso.bin",
		"tab\there":             "tab here",
		"ctrl\x01\x1fchar":      "ctrlchar",
		"..":                    "fallback",
		"   ":                   "fallback",
		"":                      "fallback",
		"/":                     "fallback",
		".hidden":               "hidden",
		"bad\xffutf8.bin":       "bad_utf8.bin",
		"résumé.pdf":            "résumé.pdf",
		"normal name (1).zip":   "normal name (1).zip",
	}
	for in, want := range cases {
		if got := SanitizeFilename(in, "fallback"); got != want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", in, got, want)
		}
	}
	long := strings.Repeat("é", 300) + ".safetensors"
	got := SanitizeFilename(long, "x")
	if len(got) > MaxFilenameBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, ".safetensors") {
		t.Errorf("long name not capped correctly: %d bytes", len(got))
	}
}

func FuzzSanitizeFilename(f *testing.F) {
	for _, s := range []string{"a.txt", "../x", "CON", "a:b", "x\u202e.exe", "..\\..\\", strings.Repeat("a", 500)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := SanitizeFilename(s, "fb")
		if out == "" {
			t.Fatal("empty result")
		}
		if strings.ContainsAny(out, `/\:<>"|?*`) {
			t.Fatalf("unsafe char in %q", out)
		}
		if out == "." || out == ".." || strings.HasSuffix(out, ".") || strings.HasSuffix(out, " ") || strings.HasPrefix(out, " ") {
			t.Fatalf("bad edges in %q", out)
		}
		if IsReservedName(out) {
			t.Fatalf("reserved name %q", out)
		}
		if len(out) > MaxFilenameBytes || !utf8.ValidString(out) {
			t.Fatalf("bad length/utf8 %q", out)
		}
		for _, r := range out {
			if r < 0x20 || isInvisibleFormat(r) {
				t.Fatalf("invisible char in %q", out)
			}
		}
	})
}

func setupRoots(t *testing.T) (*PathPolicy, string) {
	t.Helper()
	root, _ := RealPath(t.TempDir())
	os.MkdirAll(filepath.Join(root, "models", "vae"), 0o755)
	os.MkdirAll(filepath.Join(root, "secrets"), 0o755)
	os.MkdirAll(filepath.Join(root, "Startup"), 0o755)
	return &PathPolicy{
		Roots:     []string{root},
		Deny:      []string{filepath.Join(root, "secrets")},
		Forbidden: []string{filepath.Join(root, "Startup")},
	}, root
}

func TestResolveDir(t *testing.T) {
	p, root := setupRoots(t)
	if d, err := p.ResolveDir(""); err != nil || d != root {
		t.Fatalf("default: %v %v", d, err)
	}
	if d, err := p.ResolveDir("models/vae"); err != nil || d != filepath.Join(root, "models", "vae") {
		t.Fatalf("relative: %v %v", d, err)
	}
	if _, err := p.ResolveDir("../"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("../ escaped: %v", err)
	}
	if _, err := p.ResolveDir("models/../../"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("nested ../ escaped: %v", err)
	}
	if _, err := p.ResolveDir(os.TempDir()); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("absolute outside root: %v", err)
	}
	if _, err := p.ResolveDir("secrets"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("deny list: %v", err)
	}
	if _, err := p.ResolveDir("Startup"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("forbidden list: %v", err)
	}
	if _, err := p.ResolveDir("models:stream"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("ADS colon: %v", err)
	}
	if _, err := p.ResolveDir("missing"); err == nil {
		t.Fatal("missing folder must not be created")
	}
	os.Mkdir(filepath.Join(root, PartDirName), 0o700)
	if _, err := p.ResolveDir(PartDirName); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf(".rdl as destination: %v", err)
	}
}

func TestSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows; junction test runs in CI on Windows separately")
	}
	p, root := setupRoots(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.ResolveDir("link"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("symlink escape: %v", err)
	}
	// Link inside root pointing to a denied folder.
	os.Symlink(filepath.Join(root, "secrets"), filepath.Join(root, "s2"))
	if _, err := p.ResolveDir("s2"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("link to denied: %v", err)
	}
	// Listing hides the escaping link.
	ents, _ := p.List("", false)
	for _, e := range ents {
		if e.Name == "link" || e.Name == "s2" || e.Name == "secrets" {
			t.Fatalf("listing shows %s", e.Name)
		}
	}
}

func TestSwapFolderRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs symlink privileges")
	}
	p, root := setupRoots(t)
	dir, err := p.ResolveDir("models")
	if err != nil {
		t.Fatal(err)
	}
	// Folder replaced by a link to outside after the first check.
	outside := t.TempDir()
	os.RemoveAll(dir)
	os.Symlink(outside, dir)
	if err := p.CheckFinalPath(filepath.Join(dir, "file.bin")); err == nil {
		t.Fatal("swapped folder must be refused at final check")
	}
	_ = root
}

func TestCheckFinalPathName(t *testing.T) {
	p, root := setupRoots(t)
	if err := p.CheckFinalPath(filepath.Join(root, "ok.bin")); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckFinalPath(filepath.Join(root, "CON")); err == nil {
		t.Fatal("reserved name passed")
	}
}

func TestMkdirAndList(t *testing.T) {
	p, root := setupRoots(t)
	d, err := p.Mkdir("models", "loras")
	if err != nil || d != filepath.Join(root, "models", "loras") {
		t.Fatalf("%v %v", d, err)
	}
	for _, bad := range []string{"..", "a/b", `a\b`, "CON", "x:y", "", PartDirName} {
		if _, err := p.Mkdir("", bad); err == nil {
			t.Errorf("mkdir %q should fail", bad)
		}
	}
	p.MaxDepth = 2
	if _, err := p.Mkdir("models/loras", "deep"); err == nil {
		t.Fatal("depth limit not enforced")
	}
	os.WriteFile(filepath.Join(root, "models", "a.bin"), []byte("x"), 0o644)
	ents, err := p.List("models", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !e.IsDir {
			t.Fatal("files shown while browse_show_files is off")
		}
	}
	ents, _ = p.List("models", true)
	found := false
	for _, e := range ents {
		found = found || e.Name == "a.bin"
	}
	if !found {
		t.Fatal("files hidden while browse_show_files is on")
	}
	if up, _ := p.Parent(""); up != root {
		t.Fatalf("cd .. above root: %s", up)
	}
	if up, _ := p.Parent("models"); up != root {
		t.Fatalf("parent: %s", up)
	}
}

func TestReserveUniqueName(t *testing.T) {
	dir := t.TempDir()
	a, _ := ReserveUniqueName(dir, "x.bin")
	b, _ := ReserveUniqueName(dir, "x.bin")
	c, _ := ReserveUniqueName(dir, "x.bin")
	if filepath.Base(a) != "x.bin" || filepath.Base(b) != "x (1).bin" || filepath.Base(c) != "x (2).bin" {
		t.Fatal(a, b, c)
	}
}

func TestBlockedExtension(t *testing.T) {
	if !HasBlockedExtension("Setup.EXE", DefaultBlockedExtensions) || HasBlockedExtension("model.safetensors", DefaultBlockedExtensions) {
		t.Fatal("extension check")
	}
}

func TestDiskGuard(t *testing.T) {
	g := &DiskGuard{MinFree: 10, Stat: func(string) (DiskInfo, error) { return DiskInfo{Free: 100, FSType: "FAT32"}, nil }}
	if err := g.Check("x", 50, 50); err != nil {
		t.Fatal(err)
	}
	if err := g.Check("x", 95, 95); !errors.Is(err, ErrDiskSpace) {
		t.Fatal(err)
	}
	if err := g.Check("x", 5<<30, 0); err == nil || !strings.Contains(err.Error(), "FAT32") {
		t.Fatal(err)
	}
	if _, err := StatDisk(t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestFavorites(t *testing.T) {
	p, _ := setupRoots(t)
	home, _ := RealPath(t.TempDir())
	fav := filepath.Join(home, "AI Models")
	os.MkdirAll(filepath.Join(fav, "vae"), 0o755)
	hidden := filepath.Join(home, ".secret")
	os.MkdirAll(hidden, 0o755)
	forbidden := filepath.Join(home, "Startup")
	os.MkdirAll(forbidden, 0o755)
	p.Forbidden = append(p.Forbidden, forbidden)
	p.Home = home
	calls := 0
	p.Favorites = func() []favorites.Folder {
		calls++
		return []favorites.Folder{
			{Path: fav, Label: "Models", Source: "gtk"},
			{Path: home, Label: "Home"},                       // home itself: rejected
			{Path: filepath.Dir(home), Label: "Parent"},       // parent of home: rejected
			{Path: string(filepath.Separator), Label: "Root"}, // volume root: rejected
			{Path: hidden, Label: "Hidden"},                   // hidden: rejected
			{Path: forbidden, Label: "Startup"},               // forbidden: rejected
			{Path: filepath.Join(home, "missing"), Label: "Gone"},
			{Path: "relative/path", Label: "Rel"},
		}
	}
	sf := p.SaveFolders()
	if len(sf) != 2 || sf[1].Path != fav || sf[1].Label != "Models" {
		t.Fatalf("%+v", sf)
	}
	if d, err := p.ResolveDir(filepath.Join(fav, "vae")); err != nil || d != filepath.Join(fav, "vae") {
		t.Fatalf("favorite not usable: %v", err)
	}
	if d, err := p.ResolveDir("@Models/vae"); err != nil || d != filepath.Join(fav, "vae") {
		t.Fatalf("@label: %v %v", d, err)
	}
	if _, err := p.ResolveDir("@Nope"); err == nil {
		t.Fatal("unknown label accepted")
	}
	if _, err := p.ResolveDir(home); err == nil {
		t.Fatal("home accepted as destination")
	}
	if _, err := p.ResolveDir(hidden); err == nil {
		t.Fatal("hidden favorite accepted")
	}
	p.SaveFolders()
	if calls != 1 {
		t.Fatalf("favorites read %d times", calls)
	}
}

func TestHiddenFolderInsideRoot(t *testing.T) {
	p, root := setupRoots(t)
	os.MkdirAll(filepath.Join(root, ".git", "hooks"), 0o755)
	if _, err := p.ResolveDir(".git/hooks"); !errors.Is(err, ErrPathBlocked) {
		t.Fatalf("hidden folder accepted: %v", err)
	}
}
