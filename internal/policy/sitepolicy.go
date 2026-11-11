package policy

import (
	"mime"
	"strings"
)

// StreamingSites are video and music streaming services. Their content
// is offered for playback in their own player, not as a file a browser can
// save, so rdl (which is not built for stream ripping) refuses them. The
// list is built in and can't be removed from config; owners can add more
// with blocked_sites.
//
// The rule is: if the server hands over a file that a browser would save,
// rdl may download it. Social sites are not listed: their pages are HTML
// (which rdl refuses as "a web page, not a file"), while direct file links
// on their CDNs are ordinary files.
var StreamingSites = []string{
	"youtube.com", "youtu.be", "youtube-nocookie.com", "googlevideo.com", "youtubekids.com",
	"netflix.com", "nflxvideo.net", "primevideo.com", "amazonvideo.com", "disneyplus.com",
	"hotstar.com", "jiohotstar.com", "jiocinema.com", "hulu.com", "max.com", "hbomax.com",
	"peacocktv.com", "paramountplus.com", "sonyliv.com", "zee5.com", "crunchyroll.com", "mxplayer.in",
	"twitch.tv", "ttvnw.net", "vimeo.com", "vimeocdn.com", "dailymotion.com", "dai.ly",
	"spotify.com", "scdn.co", "soundcloud.com", "sndcdn.com", "music.apple.com", "tidal.com",
	"deezer.com", "gaana.com", "jiosaavn.com", "wynk.in", "audible.com",
}

// UnsupportedSites serve files that are encrypted on the server and only
// decrypted by the site's own JavaScript in the browser. A plain HTTP
// download can't get the real file, so rdl explains that instead of
// saving an HTML page or encrypted data. This is a technical limit, not
// a policy one.
var UnsupportedSites = map[string]string{
	"mega.nz":    "MEGA",
	"mega.io":    "MEGA",
	"mega.co.nz": "MEGA",
}

// StreamManifestTypes are playlist formats that hide a video as many
// fragments (HLS, DASH, Smooth Streaming). rdl doesn't stitch streams.
var StreamManifestTypes = []string{
	"application/vnd.apple.mpegurl", "application/x-mpegurl", "audio/mpegurl", "audio/x-mpegurl",
	"application/dash+xml", "application/vnd.ms-sstr+xml",
}

// StreamManifestExts are the matching file extensions.
var StreamManifestExts = []string{".m3u8", ".m3u", ".mpd", ".ism", ".f4m"}

func hostMatches(host string, domains []string) (string, bool) {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "."))
		if d != "" && (h == d || strings.HasSuffix(h, "."+d)) {
			return d, true
		}
	}
	return "", false
}

// CheckSite refuses streaming services and explains unsupported sites.
func (p *URLPolicy) CheckSite(host string) error {
	if d, ok := hostMatches(host, StreamingSites); ok {
		return blocked("%s is a streaming service: its videos/music are offered for playback, not as files, and rdl is not built for stream ripping", d)
	}
	for d, name := range UnsupportedSites {
		if _, ok := hostMatches(host, []string{d}); ok {
			return blocked("%s links are not supported yet: %s encrypts files on its server and only your browser can decrypt them, so a plain download would give you an unusable file. Use %s's own app or the browser for now", name, name, name)
		}
	}
	if d, ok := hostMatches(host, p.BlockedSites); ok {
		return blocked("%s is blocked by config (blocked_sites)", d)
	}
	return nil
}

// IsStreamManifest reports an HLS/DASH playlist by content type or name.
func IsStreamManifest(contentType, name string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	for _, t := range StreamManifestTypes {
		if mt == t {
			return true
		}
	}
	return HasBlockedExtension(name, StreamManifestExts)
}

// ErrStreamManifest explains why a playlist is refused.
const ErrStreamManifest = "this link is a streaming playlist (HLS/DASH) that a player stitches together, not a file; rdl doesn't download streams"
