package policy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCheckIPBlocked(t *testing.T) {
	p := &URLPolicy{}
	blockedIPs := []string{
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.100.100.100", "127.0.0.1", "127.255.255.254",
		"169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.168.1.50",
		"198.18.0.1", "198.19.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fc00::1", "fd12:3456::1", "fe80::1", "ff02::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"::127.0.0.1", "::10.1.2.3", // IPv4-compatible
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:132", // NAT64 with private IPv4
		"2002:7f00:1::1", // 6to4 of 127.0.0.1
		"fe80::1%eth0",
	}
	for _, s := range blockedIPs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if err := p.CheckIP(a); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "64:ff9b::808:808", "::ffff:8.8.8.8", "172.32.0.1", "100.128.0.1"}
	for _, s := range allowed {
		if err := p.CheckIP(netip.MustParseAddr(s)); err != nil {
			t.Errorf("%s should be allowed: %v", s, err)
		}
	}
}

func TestAllowPrivate(t *testing.T) {
	pr, err := ParseAllowPrivate("192.168.1.50")
	if err != nil {
		t.Fatal(err)
	}
	p := &URLPolicy{AllowPrivate: []netip.Prefix{pr}}
	if err := p.CheckIP(netip.MustParseAddr("192.168.1.50")); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckIP(netip.MustParseAddr("::ffff:192.168.1.50")); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckIP(netip.MustParseAddr("192.168.1.51")); err == nil {
		t.Fatal("neighbour must stay blocked")
	}
}

func TestOddIPSpellings(t *testing.T) {
	cases := map[string]string{
		"2130706433":          "127.0.0.1",
		"0x7f000001":          "127.0.0.1",
		"0X7F000001":          "127.0.0.1",
		"0177.0.0.1":          "127.0.0.1",
		"0177.0.0.01":         "127.0.0.1",
		"127.1":               "127.0.0.1",
		"127.0.1":             "127.0.0.1",
		"0x7f.1":              "127.0.0.1",
		"017700000001":        "127.0.0.1",
		"10.1":                "10.0.0.1",
		"3232235777":          "192.168.1.1",
		"0xa9.0xfe.0xa9.0xfe": "169.254.169.254",
		"0":                   "0.0.0.0",
		"127.0.0.1.":          "127.0.0.1",
	}
	for in, want := range cases {
		got, ok := ParseHostIP(in)
		if !ok || got.String() != want {
			t.Errorf("ParseHostIP(%q) = %v,%v want %s", in, got, ok, want)
		}
	}
	for _, name := range []string{"example.com", "1.2.3.4.5", "0x", "256.1.1.1.1", "huggingface.co"} {
		if a, ok := ParseHostIP(name); ok && name != "0x" {
			t.Errorf("ParseHostIP(%q) unexpectedly parsed as %v", name, a)
		}
	}
}

func TestCheckRawURL(t *testing.T) {
	p := &URLPolicy{}
	bad := []string{
		"file:///etc/passwd", "file://C:/Windows/win.ini", "ftp://example.com/x", "smb://server/share",
		"data:text/plain,hi", "javascript:alert(1)", `\\server\share\file`, "//example.com/x",
		"https://user:pass@example.com/x", "https://user@example.com/x",
		"http://127.0.0.1/", "http://localhost:8080/", "http://foo.localhost/", "http://[::1]/",
		"http://[::ffff:127.0.0.1]/", "http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/",
		"http://127.1/", "http://169.254.169.254/latest/meta-data/", "http://[fe80::1%25eth0]/",
		"http://10.0.0.1:65536/", "http:///nohost", "gopher://x", "https://example.com/\nx",
		"http://100.100.100.100/", "HTTP://192.168.0.1/",
	}
	for _, u := range bad {
		if _, err := p.CheckRawURL(u); !errors.Is(err, ErrBlocked) {
			t.Errorf("%q should be blocked, got %v", u, err)
		}
	}
	good := []string{"https://huggingface.co/x", "http://example.com:8080/a?b=c", "HTTPS://GitHub.com/"}
	for _, u := range good {
		if _, err := p.CheckRawURL(u); err != nil {
			t.Errorf("%q should be allowed: %v", u, err)
		}
	}
}

func TestDomainAllowlist(t *testing.T) {
	p := &URLPolicy{DomainAllowlist: []string{"huggingface.co", ".github.com"}}
	for _, u := range []string{"https://huggingface.co/x", "https://cdn-lfs.huggingface.co/x", "https://github.com/a", "https://objects.github.com/"} {
		if _, err := p.CheckRawURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"https://evilhuggingface.co/x", "https://huggingface.co.evil.com/", "https://example.com/"} {
		if _, err := p.CheckRawURL(u); err == nil {
			t.Errorf("%s should be blocked", u)
		}
	}
}

// fakeResolver answers each lookup from a list (to simulate DNS rebinding).
type rebindDialer struct {
	answers []string
	n       atomic.Int32
}

// TestDialControlBlocksRebinding: the name resolves to a public IP when
// checked, then a private IP when used. The socket-level Control hook sees
// the real address and refuses.
func TestDialControlBlocksRebinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret")) }))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	p := &URLPolicy{}
	c := p.NewClient(ClientOptions{})
	tr := c.Transport.(*checkingTransport).rt.(*http.Transport)
	// Replace DNS: "rebind.test" -> 127.0.0.1 at connect time. The dialer
	// Control hook is the only thing standing in the way.
	base := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return base(ctx, network, "127.0.0.1:"+port)
	}
	_, err := c.Get("http://rebind.test:" + port + "/")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected block at dial time, got %v", err)
	}
}

func TestRedirectToPrivateBlocked(t *testing.T) {
	// The first hop is allowed (via AllowPrivate for 127.0.0.1 only), the
	// redirect goes to 169.254.169.254 which must be refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	pr, _ := ParseAllowPrivate("127.0.0.1")
	p := &URLPolicy{AllowPrivate: []netip.Prefix{pr}}
	c := p.NewClient(ClientOptions{})
	_, err := c.Get(srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected redirect block, got %v", err)
	}
	// Redirect to a non-http scheme.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer srv2.Close()
	if _, err := c.Get(srv2.URL); err == nil {
		t.Fatal("redirect to file: must fail")
	}
}

func TestRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+r.URL.Path+"x", http.StatusFound)
	}))
	defer srv.Close()
	pr, _ := ParseAllowPrivate("127.0.0.1")
	p := &URLPolicy{AllowPrivate: []netip.Prefix{pr}}
	_, err := p.NewClient(ClientOptions{}).Get(srv.URL + "/")
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Fatalf("expected redirect limit error, got %v", err)
	}
}

func TestSystemProxyIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	p := &URLPolicy{}
	tr := p.NewClient(ClientOptions{}).Transport.(*checkingTransport).rt.(*http.Transport)
	if tr.Proxy != nil {
		t.Fatal("system proxy must be ignored")
	}
}

type staticResolver map[string][]netip.Addr

func (r staticResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	return r[host], nil
}

func TestProxyPrecheck(t *testing.T) {
	proxy, _ := url.Parse("http://127.0.0.1:3128")
	p := &URLPolicy{Proxy: proxy, Resolver: staticResolver{"internal.example": {netip.MustParseAddr("10.0.0.5")}}}
	c := p.NewClient(ClientOptions{})
	if _, err := c.Get("http://internal.example/"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected block, got %v", err)
	}
}

func FuzzCheckRawURL(f *testing.F) {
	for _, s := range []string{"https://example.com/a", "http://127.0.0.1/", "http://0x7f.1/", "file:///x", "http://[::ffff:7f00:1]/"} {
		f.Add(s)
	}
	p := &URLPolicy{}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := p.CheckRawURL(s)
		if err != nil {
			return
		}
		// Anything accepted must be http(s), have a host, no userinfo, and
		// not be a private IP literal in any spelling.
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "HTTP" && u.Scheme != "HTTPS" {
			if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
				t.Fatalf("accepted scheme %q", u.Scheme)
			}
		}
		if u.User != nil || u.Hostname() == "" {
			t.Fatalf("accepted %q", s)
		}
		if ip, ok := ParseHostIP(u.Hostname()); ok {
			if p.CheckIP(ip) != nil {
				t.Fatalf("accepted private %q", s)
			}
		}
	})
}

func TestStreamingSitesBlocked(t *testing.T) {
	p := &URLPolicy{BlockedSites: []string{"example-tube.com"}}
	for _, u := range []string{
		"https://www.youtube.com/watch?v=abc", "https://youtu.be/abc", "https://rr3---sn-abc.googlevideo.com/videoplayback",
		"https://m.youtube.com/shorts/x", "https://music.youtube.com/watch?v=1", "https://open.spotify.com/track/1",
		"https://www.netflix.com/title/1", "https://vimeo.com/123",
		"https://cdn.example.com/video/master.m3u8", "https://cdn.example.com/stream.MPD?x=1",
		"https://sub.example-tube.com/x.mp4",
	} {
		if _, err := p.CheckRawURL(u); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s should be blocked, got %v", u, err)
		}
	}
	// MEGA is not a policy block but a technical one, with its own message.
	if _, err := p.CheckRawURL("https://mega.nz/file/abc#key"); err == nil || !strings.Contains(err.Error(), "not supported yet") {
		t.Errorf("mega: %v", err)
	}
	// Direct file links on social/CDN hosts are ordinary files.
	for _, u := range []string{"https://notyoutube.com/x.zip", "https://github.com/a/b/releases/download/v1/x.zip", "https://example.com/video.mp4",
		"https://pbs.twimg.com/media/abc.jpg", "https://i.redd.it/x.png", "https://www.dropbox.com/s/abc/file.zip?dl=1"} {
		if _, err := p.CheckRawURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if !IsStreamManifest("application/vnd.apple.mpegurl; charset=utf-8", "x") || IsStreamManifest("video/mp4", "a.mp4") {
		t.Fatal("manifest detection")
	}
}
