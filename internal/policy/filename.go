package policy

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxFilenameBytes caps cleaned filenames (NTFS allows 255 UTF-16 units;
// we stay well under so "name (123).ext" and long-path prefixes still fit).
const MaxFilenameBytes = 200

// reservedNames are Windows device names; forbidden with any extension.
var reservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"CONIN$": true, "CONOUT$": true, "CLOCK$": true,
}

func init() {
	for _, p := range []string{"COM", "LPT"} {
		for _, d := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
			reservedNames[p+d] = true
		}
	}
}

// IsReservedName reports whether name (with any extension) is a Windows
// reserved device name.
func IsReservedName(name string) bool {
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	base = strings.TrimRight(base, " ")
	return reservedNames[strings.ToUpper(base)]
}

// isInvisibleFormat reports characters that can disguise a name: bidi
// overrides and isolates, zero-width characters, BOM, and other Cf.
func isInvisibleFormat(r rune) bool {
	switch r {
	case '\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069',
		'\u061c', '\ufeff', '\u00ad', '\u180e':
		return true
	}
	return unicode.Is(unicode.Cf, r)
}

// SanitizeFilename turns an attacker-controlled name (from a URL or a
// Content-Disposition header) into a safe single path component. If nothing
// usable remains it returns fallback.
//
// Rules (spec section 7.6): strip directories, remove ':' (blocks NTFS alternate
// data streams), <>"|?* and control characters, remove bidi and other
// invisible format characters, reject reserved device names, strip leading
// and trailing dots and spaces, and cap the length.
func SanitizeFilename(name, fallback string) string {
	name = strings.ToValidUTF8(name, "_")
	// Strip any directory part, whichever separator was used.
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			continue
		case strings.ContainsRune(`<>:"|?*`, r):
			b.WriteRune('_')
		case isInvisibleFormat(r):
			continue
		case unicode.IsSpace(r):
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	name = b.String()
	// Collapse runs of whitespace.
	name = strings.Join(strings.Fields(name), " ")
	name = strings.Trim(name, ". ")
	if name == "" {
		return fallback
	}
	if IsReservedName(name) {
		name = "_" + name
	}
	name = capLength(name, MaxFilenameBytes)
	name = strings.TrimRight(name, ". ")
	if name == "" {
		return fallback
	}
	return name
}

// capLength shortens name to at most max bytes, keeping a short extension
// and never splitting a UTF-8 sequence.
func capLength(name string, max int) string {
	if len(name) <= max {
		return name
	}
	ext := ""
	if i := strings.LastIndexByte(name, '.'); i > 0 && len(name)-i <= 16 {
		ext = name[i:]
		name = name[:i]
	}
	limit := max - len(ext)
	for limit > 0 && !utf8.RuneStart(name[limit]) {
		limit--
	}
	return name[:limit] + ext
}

// FilenameFromURLPath picks the last path segment of an (already unescaped)
// URL path.
func FilenameFromURLPath(p string) string {
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		p = p[i+1:]
	}
	return p
}

// DefaultBlockedExtensions are executable or script types that rdl warns
// about (or refuses) depending on block_extensions.
var DefaultBlockedExtensions = []string{
	".exe", ".msi", ".msix", ".appx", ".bat", ".cmd", ".com", ".ps1", ".psm1",
	".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".scr",
	".pif", ".cpl", ".jar", ".reg", ".dll", ".sys", ".url", ".application",
	".sh", ".desktop",
}

// HasBlockedExtension reports whether name ends in one of exts
// (case-insensitive).
func HasBlockedExtension(name string, exts []string) bool {
	ln := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(ln, strings.ToLower(e)) {
			return true
		}
	}
	return false
}
