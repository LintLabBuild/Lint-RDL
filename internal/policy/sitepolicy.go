package policy

import (
	"mime"
	"strings"
)

// StreamingSites are sites whose content is only meant to be streamed or
// is deliberately hidden behind players, DRM or client-side encryption.
// rdl refuses them on purpose (no piracy, no stream ripping). They are
// built in and can't be removed from config; owners can add more with
// blocked_sites.
var StreamingSites = []string{
	// video / music streaming
	"youtube.com", "youtu.be", "youtube-nocookie.com", "googlevideo.com", "youtubekids.com",
	"vimeo.com", "vimeocdn.com", "dailymotion.com", "dai.ly", "twitch.tv", "ttvnw.net",
	"tiktok.com", "tiktokcdn.com", "instagram.com", "cdninstagram.com", "facebook.com", "fb.watch",
	"x.com", "twitter.com", "twimg.com", "reddit.com", "v.redd.it", "bilibili.com",
	"netflix.com", "nflxvideo.net", "primevideo.com", "amazonvideo.com", "disneyplus.com",
	"hotstar.com", "hulu.com", "max.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
	"jiocinema.com", "jiohotstar.com", "sonyliv.com", "zee5.com", "crunchyroll.com", "mxplayer.in",
	"spotify.com", "scdn.co", "soundcloud.com", "sndcdn.com", "music.apple.com", "tidal.com",
	"deezer.com", "gaana.com", "jiosaavn.com", "wynk.in", "audible.com",
	// content hidden behind client-side encryption
	"mega.nz", "mega.io", "mega.co.nz",
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

// CheckSite refuses streaming and content-hiding sites.
func (p *URLPolicy) CheckSite(host string) error {
	if d, ok := hostMatches(host, StreamingSites); ok {
		return blocked("%s is a streaming site; rdl only downloads files that are offered for download (no stream ripping)", d)
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
const ErrStreamManifest = "this link is a streaming playlist (HLS/DASH), not a file; rdl doesn't download or stitch streams"
