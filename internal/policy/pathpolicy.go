package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lintlabbuild/lint-rdl/internal/favorites"
)

// ErrPathBlocked is wrapped by every path policy rejection.
var ErrPathBlocked = errors.New("blocked by path policy")

func pathBlocked(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPathBlocked, fmt.Sprintf(format, a...))
}

// PartDirName is the hidden folder inside a save folder that holds
// in-progress .part files. It is never a valid destination itself.
const PartDirName = ".rdl"

// PathPolicy decides where rdl may write.
type PathPolicy struct {
	// Roots are the save folders the owner listed at the PC. The first one
	// is the default save folder.
	Roots []string
	// Deny lists folders that are forbidden even inside a root.
	Deny []string
	// Forbidden are built-in always-forbidden folders (rdl's own folders,
	// Startup folders, the OS and program folders). See DefaultForbidden.
	Forbidden []string
	// MaxDepth limits how deep below a root mkdir may create folders.
	// Zero means 8.
	MaxDepth int
	// Favorites, if set, returns folders pinned in the file manager
	// (Explorer Quick access, GTK/KDE bookmarks). Valid ones become extra
	// save folders. It is called at most once per PathPolicy.
	Favorites func() []favorites.Folder
	// Home is the user's home folder (default os.UserHomeDir). Favorites
	// may not be the home folder or one of its parents.
	Home string

	favOnce sync.Once
	favs    []SaveFolder
}

// SaveFolder is one place a download may be saved: a configured root or a
// pinned favorite that passed the safety checks.
type SaveFolder struct {
	Path   string `json:"path"`
	Label  string `json:"label"`
	Source string `json:"source"` // root | explorer | gtk | kde
}

// isVolumeRoot reports C:\, D:\, / and \\server\share.
func isVolumeRoot(p string) bool {
	return filepath.Dir(p) == p || filepath.VolumeName(p)+string(filepath.Separator) == p
}

// hasHiddenComponent reports a path component starting with '.'.
func hasHiddenComponent(rel string) bool {
	for _, c := range strings.Split(rel, string(filepath.Separator)) {
		if strings.HasPrefix(c, ".") && c != "." && c != ".." {
			return true
		}
	}
	return false
}

// validFavorites returns the pinned folders that may be used as save
// folders. A favorite is rejected if it is a drive root, the home folder or
// a parent of it, hidden, or inside a forbidden or denied folder.
func (p *PathPolicy) validFavorites() []SaveFolder {
	p.favOnce.Do(func() {
		if p.Favorites == nil {
			return
		}
		home := p.Home
		if home == "" {
			home, _ = os.UserHomeDir()
		}
		if home != "" {
			if h, err := RealPath(home); err == nil {
				home = h
			}
		}
		for _, f := range p.Favorites() {
			if !filepath.IsAbs(f.Path) {
				continue
			}
			real, err := RealPath(f.Path)
			if err != nil {
				continue
			}
			if st, err := os.Stat(real); err != nil || !st.IsDir() {
				continue
			}
			if isVolumeRoot(real) || (home != "" && IsWithin(real, home)) || hasHiddenComponent(real) {
				continue
			}
			if p.inForbidden(real) {
				continue
			}
			p.favs = append(p.favs, SaveFolder{Path: real, Label: f.Label, Source: f.Source})
		}
	})
	return p.favs
}

// SaveFolders lists configured roots first, then valid favorites that are
// not already inside a root.
func (p *PathPolicy) SaveFolders() []SaveFolder {
	var out []SaveFolder
	for _, r := range p.Roots {
		if rr, err := RealPath(r); err == nil {
			out = append(out, SaveFolder{Path: rr, Label: filepath.Base(rr), Source: "root"})
		}
	}
	for _, f := range p.validFavorites() {
		dup := false
		for _, o := range out {
			if IsWithin(o.Path, f.Path) {
				dup = true
			}
		}
		if !dup {
			out = append(out, f)
		}
	}
	return out
}

func (p *PathPolicy) inForbidden(real string) bool {
	for _, list := range [][]string{p.Forbidden, p.Deny} {
		for _, d := range list {
			if d != "" && IsWithin(realOrClean(d), real) {
				return true
			}
		}
	}
	return false
}

// DefaultRoot returns the first configured root, or "".
func (p *PathPolicy) DefaultRoot() string {
	if len(p.Roots) == 0 {
		return ""
	}
	return p.Roots[0]
}

func (p *PathPolicy) maxDepth() int {
	if p.MaxDepth <= 0 {
		return 8
	}
	return p.MaxDepth
}

// samePathFold reports whether paths compare equal under the platform's
// case rules.
func samePathFold(a, b string) bool {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// IsWithin reports whether target is base or below it. Both must be clean
// absolute paths.
func IsWithin(base, target string) bool {
	base = filepath.Clean(base)
	target = filepath.Clean(target)
	if samePathFold(base, target) {
		return true
	}
	sep := string(filepath.Separator)
	prefix := base
	if !strings.HasSuffix(prefix, sep) {
		prefix += sep
	}
	if len(target) <= len(prefix) {
		return false
	}
	return samePathFold(target[:len(prefix)], prefix)
}

// realOrClean resolves p if it exists; otherwise resolves the deepest
// existing ancestor and appends the rest. Used for deny lists whose folders
// may not exist yet.
func realOrClean(p string) string {
	p = filepath.Clean(p)
	rest := []string{}
	cur := p
	for {
		if r, err := RealPath(cur); err == nil {
			for i := len(rest) - 1; i >= 0; i-- {
				r = filepath.Join(r, rest[i])
			}
			return r
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = append(rest, filepath.Base(cur))
		cur = parent
	}
}

// resolvedRoots returns the real paths of all roots that currently exist,
// plus valid pinned favorites.
func (p *PathPolicy) resolvedRoots() []string {
	out := make([]string, 0, len(p.Roots))
	for _, r := range p.Roots {
		if rr, err := RealPath(r); err == nil {
			out = append(out, rr)
		}
	}
	for _, f := range p.validFavorites() {
		out = append(out, f.Path)
	}
	return out
}

// checkReal validates an already-resolved real path: inside a root, not in
// a forbidden or denied folder, not inside a hidden or .rdl folder.
func (p *PathPolicy) checkReal(real string) (root string, err error) {
	for _, r := range p.resolvedRoots() {
		if IsWithin(r, real) && len(r) > len(root) {
			root = r
		}
	}
	if root == "" {
		return "", pathBlocked("%s is not inside an allowed save folder", real)
	}
	if p.inForbidden(real) {
		return "", pathBlocked("%s is inside a forbidden folder", real)
	}
	rel, _ := filepath.Rel(root, real)
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if samePathFold(part, PartDirName) {
			return "", pathBlocked("rdl's working folder cannot be used as a destination")
		}
	}
	if hasHiddenComponent(rel) {
		return "", pathBlocked("hidden folders cannot be used as a destination")
	}
	return root, nil
}

// ResolveDir turns a user-supplied folder (absolute, or relative to the
// default root; empty means the default root) into a real, checked path.
// The folder must already exist: rdl never creates folders silently.
func (p *PathPolicy) ResolveDir(dir string) (string, error) {
	if len(p.Roots) == 0 {
		return "", pathBlocked("no save folders configured (run: rdl roots add <folder>)")
	}
	dir = strings.TrimSpace(dir)
	if strings.ContainsRune(dir, 0) {
		return "", pathBlocked("path contains NUL")
	}
	if strings.HasPrefix(dir, "@") {
		label, rest, _ := strings.Cut(strings.TrimPrefix(dir, "@"), "/")
		if l2, r2, ok := strings.Cut(label, `\`); ok {
			label, rest = l2, r2
		}
		var base string
		for _, f := range p.SaveFolders() {
			if strings.EqualFold(f.Label, label) || strings.EqualFold(filepath.Base(f.Path), label) {
				base = f.Path
				break
			}
		}
		if base == "" {
			return "", fmt.Errorf("no save folder or favorite named %q (see: rdl folders)", label)
		}
		dir = filepath.Join(base, filepath.FromSlash(rest))
	}
	if dir == "" {
		dir = p.DefaultRoot()
	} else if !filepath.IsAbs(dir) {
		if runtime.GOOS == "windows" && (strings.HasPrefix(dir, `\`) || filepath.VolumeName(dir) != "") {
			return "", pathBlocked("drive-relative paths are not allowed")
		}
		dir = filepath.Join(p.DefaultRoot(), dir)
	}
	if hasStreamColon(dir) {
		return "", pathBlocked("':' is not allowed in folder names")
	}
	real, err := RealPath(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("folder does not exist: %s", dir)
		}
		return "", err
	}
	st, err := os.Stat(real)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("not a folder: %s", dir)
	}
	if _, err := p.checkReal(real); err != nil {
		return "", err
	}
	return real, nil
}

// hasStreamColon reports a ':' outside the drive letter (NTFS ADS).
func hasStreamColon(p string) bool {
	vol := filepath.VolumeName(p)
	return strings.ContainsRune(p[len(vol):], ':')
}

// CheckFinalPath re-validates the folder of an about-to-be-written file,
// right before writing or renaming. It defeats swap-the-folder races where
// the folder was replaced by a link after the first check.
func (p *PathPolicy) CheckFinalPath(file string) error {
	dir := filepath.Dir(file)
	real, err := RealPath(dir)
	if err != nil {
		return err
	}
	if !samePathFold(real, filepath.Clean(dir)) {
		return pathBlocked("folder %s changed (now resolves to %s)", dir, real)
	}
	if _, err := p.checkReal(real); err != nil {
		return err
	}
	base := filepath.Base(file)
	if base != SanitizeFilename(base, "") {
		return pathBlocked("unsafe file name %q", base)
	}
	if fi, err := os.Lstat(file); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return pathBlocked("%s is a link", file)
	}
	return nil
}

// PartDir returns (and creates) the hidden .rdl folder inside dir.
func (p *PathPolicy) PartDir(dir string) (string, error) {
	pd := filepath.Join(dir, PartDirName)
	if fi, err := os.Lstat(pd); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return "", pathBlocked("%s is not a plain folder", pd)
		}
		return pd, nil
	}
	if err := os.Mkdir(pd, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return "", err
	}
	hideFile(pd)
	return pd, nil
}

// Mkdir creates a folder named name inside parent (resolved like
// ResolveDir) and returns its real path.
func (p *PathPolicy) Mkdir(parent, name string) (string, error) {
	pr, err := p.ResolveDir(parent)
	if err != nil {
		return "", err
	}
	clean := SanitizeFilename(name, "")
	if clean == "" || clean != strings.TrimSpace(name) {
		return "", pathBlocked("invalid folder name %q", name)
	}
	if samePathFold(clean, PartDirName) {
		return "", pathBlocked("reserved folder name")
	}
	root, _ := p.checkReal(pr)
	rel, _ := filepath.Rel(root, pr)
	depth := 0
	if rel != "." {
		depth = len(strings.Split(rel, string(filepath.Separator)))
	}
	if depth+1 > p.maxDepth() {
		return "", pathBlocked("folders may only be %d levels deep", p.maxDepth())
	}
	target := filepath.Join(pr, clean)
	if err := os.Mkdir(target, 0o755); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return p.ResolveDir(target)
		}
		return "", err
	}
	return p.ResolveDir(target)
}

// Entry is one item shown when browsing. No content, only name and kind.
type Entry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"dir"`
	Size  int64  `json:"size,omitempty"`
}

// List shows the folders (and, if showFiles, the files) in dir. Hidden
// entries, rdl's working folder and links leading outside the roots are
// left out.
func (p *PathPolicy) List(dir string, showFiles bool) ([]Entry, error) {
	real, err := p.ResolveDir(dir)
	if err != nil {
		return nil, err
	}
	des, err := os.ReadDir(real)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, de := range des {
		name := de.Name()
		if strings.HasPrefix(name, ".") || samePathFold(name, PartDirName) {
			continue
		}
		full := filepath.Join(real, name)
		info, err := os.Stat(full)
		if err != nil {
			continue
		}
		if info.IsDir() {
			if _, err := p.ResolveDir(full); err != nil {
				continue
			}
			out = append(out, Entry{Name: name, IsDir: true})
		} else if showFiles && info.Mode().IsRegular() {
			out = append(out, Entry{Name: name, Size: info.Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// Parent returns the parent of dir, but never goes above its root
// ("cd .." stops at the root).
func (p *PathPolicy) Parent(dir string) (string, error) {
	real, err := p.ResolveDir(dir)
	if err != nil {
		return "", err
	}
	root, err := p.checkReal(real)
	if err != nil {
		return "", err
	}
	if samePathFold(root, real) {
		return real, nil
	}
	return filepath.Dir(real), nil
}

// ReserveUniqueName atomically creates an empty placeholder for name in
// dir, adding " (1)", " (2)"... if the name is taken. The caller then
// renames the finished file over the placeholder. Never overwrites.
func ReserveUniqueName(dir, name string) (string, error) {
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	if stem == "" {
		stem, ext = name, ""
	}
	for i := 0; i < 10000; i++ {
		cand := name
		if i > 0 {
			cand = capLength(stem+" ("+strconv.Itoa(i)+")"+ext, MaxFilenameBytes+8)
		}
		full := filepath.Join(dir, cand)
		f, err := os.OpenFile(full, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			f.Close()
			return full, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free file name for %s", name)
}
