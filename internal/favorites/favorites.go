// Package favorites reads the folders the user pinned in their file
// manager (Windows File Explorer "Quick access", GNOME/GTK and KDE
// bookmarks on Linux) so rdl can offer them as save folders.
//
// The list is only a suggestion source: the path policy still rejects
// system folders, drive roots, the home folder itself, hidden folders and
// anything on the forbidden or deny lists.
package favorites

import (
	"bufio"
	"encoding/xml"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Folder is one pinned folder.
type Folder struct {
	Path   string `json:"path"`
	Label  string `json:"label,omitempty"`
	Source string `json:"source"` // explorer | gtk | kde
}

// List returns the pinned folders of the current user. Errors are
// swallowed: no favorites is a normal state.
func List() []Folder {
	return dedupe(list())
}

func dedupe(in []Folder) []Folder {
	seen := map[string]bool{}
	var out []Folder
	for _, f := range in {
		if f.Path == "" {
			continue
		}
		k := strings.ToLower(filepath.Clean(f.Path))
		if seen[k] {
			continue
		}
		seen[k] = true
		f.Path = filepath.Clean(f.Path)
		if f.Label == "" {
			f.Label = filepath.Base(f.Path)
		}
		out = append(out, f)
	}
	return out
}

// fileURLPath turns file:///home/x/My%20Dir into /home/x/My Dir.
func fileURLPath(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "file" || (u.Host != "" && u.Host != "localhost") {
		return "", false
	}
	return filepath.FromSlash(u.Path), u.Path != ""
}

// parseGTKBookmarks reads lines "file:///path Optional Label".
func parseGTKBookmarks(path string) []Folder {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Folder
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		uri, label, _ := strings.Cut(line, " ")
		if p, ok := fileURLPath(uri); ok {
			out = append(out, Folder{Path: p, Label: strings.TrimSpace(label), Source: "gtk"})
		}
	}
	return out
}

// parseXBEL reads KDE's user-places.xbel.
func parseXBEL(path string) []Folder {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc struct {
		Bookmarks []struct {
			Href  string `xml:"href,attr"`
			Title string `xml:"title"`
			Info  struct {
				Metadata []struct {
					IsSystemItem string `xml:"isSystemItem"`
				} `xml:"metadata"`
			} `xml:"info"`
		} `xml:"bookmark"`
	}
	if xml.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []Folder
	for _, b := range doc.Bookmarks {
		if p, ok := fileURLPath(b.Href); ok {
			out = append(out, Folder{Path: p, Label: b.Title, Source: "kde"})
		}
	}
	return out
}

// linuxBookmarks reads GTK 3/4 and KDE bookmark files under home.
func linuxBookmarks(home, configHome, dataHome string) []Folder {
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	if dataHome == "" {
		dataHome = filepath.Join(home, ".local", "share")
	}
	var out []Folder
	out = append(out, parseGTKBookmarks(filepath.Join(configHome, "gtk-3.0", "bookmarks"))...)
	out = append(out, parseGTKBookmarks(filepath.Join(configHome, "gtk-4.0", "bookmarks"))...)
	out = append(out, parseGTKBookmarks(filepath.Join(home, ".gtk-bookmarks"))...)
	out = append(out, parseXBEL(filepath.Join(dataHome, "user-places.xbel"))...)
	return out
}
