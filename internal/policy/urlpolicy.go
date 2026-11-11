// Package policy holds every security rule rdl applies before touching the
// network or the disk. All adapters go through these checks, so a fix here
// protects every interface at once.
package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ErrBlocked is wrapped by every URL policy rejection.
var ErrBlocked = errors.New("blocked by URL policy")

func blocked(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrBlocked, fmt.Sprintf(format, a...))
}

// blockedPrefixes are the default non-public ranges (spec §6 rule 4).
var blockedPrefixes = mustPrefixes(
	// IPv4
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10", // CGNAT, Tailscale
	"127.0.0.0/8",
	"169.254.0.0/16", // link-local, cloud metadata
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24", // TEST-NET-1
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",
	"240.0.0.0/4", // includes 255.255.255.255
	// IPv6
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"fec0::/10", // deprecated site-local
	"ff00::/8",
	"100::/64",      // discard-only
	"2001:db8::/32", // documentation
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

var (
	nat64Prefix      = netip.MustParsePrefix("64:ff9b::/96")
	nat64LocalPrefix = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFourPrefix  = netip.MustParsePrefix("2002::/16")
	teredoPrefix     = netip.MustParsePrefix("2001::/32")
)

// URLPolicy decides which URLs and IP addresses rdl may download from.
type URLPolicy struct {
	// AllowPrivate lists private addresses or ranges the owner explicitly
	// allowed at the PC (rdl allow-private add ...).
	AllowPrivate []netip.Prefix
	// DomainAllowlist, if non-empty, restricts downloads to these domains
	// and their subdomains.
	DomainAllowlist []string
	// BlockedSites are extra domains the owner refuses (on top of the
	// built-in StreamingSites).
	BlockedSites []string
	// Proxy, if set, is used for all requests. When a proxy is used the
	// socket-level IP check sees the proxy, so rdl additionally resolves and
	// checks the target host itself before every request.
	Proxy *url.URL
	// Resolver is used for the pre-check when a proxy is configured, and by
	// tests. Nil means net.DefaultResolver.
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
}

// ParseAllowPrivate turns "192.168.1.50" or "192.168.1.0/24" into a prefix.
func ParseAllowPrivate(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// CheckIP reports whether a connection to ip is allowed.
func (p *URLPolicy) CheckIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return blocked("invalid IP address")
	}
	ip = ip.WithZone("")
	for _, cand := range embeddedAddrs(ip) {
		if p.privateAllowed(cand) {
			continue
		}
		for _, pr := range blockedPrefixes {
			if pr.Contains(cand) {
				if cand != ip {
					return blocked("%s embeds non-public address %s (%s)", ip, cand, pr)
				}
				return blocked("%s is not a public address (%s)", ip, pr)
			}
		}
	}
	return nil
}

func (p *URLPolicy) privateAllowed(ip netip.Addr) bool {
	for _, a := range p.AllowPrivate {
		if a.Contains(ip) {
			return true
		}
	}
	return false
}

// embeddedAddrs returns ip plus any IPv4 address hidden inside it
// (IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo).
func embeddedAddrs(ip netip.Addr) []netip.Addr {
	out := []netip.Addr{ip}
	if ip.Is4In6() {
		out = append(out, ip.Unmap())
		return out
	}
	if !ip.Is6() {
		return out
	}
	b := ip.As16()
	v4 := func(off int) netip.Addr {
		return netip.AddrFrom4([4]byte{b[off], b[off+1], b[off+2], b[off+3]})
	}
	// IPv4-compatible ::a.b.c.d (deprecated, first 96 bits zero).
	allZero := true
	for i := 0; i < 12; i++ {
		if b[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero && ip != netip.IPv6Unspecified() && ip != netip.IPv6Loopback() {
		out = append(out, v4(12))
	}
	if nat64Prefix.Contains(ip) || nat64LocalPrefix.Contains(ip) {
		out = append(out, v4(12))
	}
	if sixToFourPrefix.Contains(ip) {
		out = append(out, v4(2))
	}
	if teredoPrefix.Contains(ip) {
		// Teredo client address is the last 32 bits, bit-inverted.
		out = append(out, netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}))
	}
	return out
}

// ParseHostIP interprets host the way permissive IP parsers (inet_aton) do,
// so odd spellings like 2130706433, 0x7f000001, 0177.0.0.1 and 127.1 are
// recognised as IP literals. ok is false if host is a name.
func ParseHostIP(host string) (netip.Addr, bool) {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if a, err := netip.ParseAddr(h); err == nil {
		return a, true
	}
	h = strings.TrimSuffix(h, ".")
	parts := strings.Split(h, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		v, err := parseCNumber(p)
		if err != nil {
			return netip.Addr{}, false
		}
		vals[i] = v
	}
	var n uint64
	switch len(vals) {
	case 1:
		if vals[0] > 0xffffffff {
			return netip.Addr{}, false
		}
		n = vals[0]
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return netip.Addr{}, false
		}
		n = vals[0]<<24 | vals[1]
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return netip.Addr{}, false
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]
	case 4:
		for _, v := range vals {
			if v > 0xff {
				return netip.Addr{}, false
			}
		}
		n = vals[0]<<24 | vals[1]<<16 | vals[2]<<8 | vals[3]
	}
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true
}

func parseCNumber(s string) (uint64, error) {
	ls := strings.ToLower(s)
	switch {
	case strings.HasPrefix(ls, "0x"):
		if len(ls) == 2 {
			return 0, nil
		}
		return strconv.ParseUint(ls[2:], 16, 64)
	case len(ls) > 1 && ls[0] == '0':
		return strconv.ParseUint(ls[1:], 8, 64)
	default:
		return strconv.ParseUint(ls, 10, 64)
	}
}

// CheckURL applies the scheme, credential, literal-IP and domain rules.
// It does not resolve names; the dialer hook checks the real socket address.
func (p *URLPolicy) CheckURL(u *url.URL) error {
	if u == nil {
		return blocked("empty URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return blocked("scheme %q not allowed (only http and https)", u.Scheme)
	}
	if u.User != nil {
		return blocked("credentials in URLs are not allowed")
	}
	if u.Opaque != "" {
		return blocked("malformed URL")
	}
	host := u.Hostname()
	if host == "" {
		return blocked("URL has no host")
	}
	if strings.ContainsAny(host, "\\%") {
		return blocked("host contains invalid characters")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
			return blocked("invalid port %q", port)
		}
	}
	if ip, ok := ParseHostIP(host); ok {
		if err := p.CheckIP(ip); err != nil {
			return err
		}
	} else {
		lh := strings.ToLower(strings.TrimSuffix(host, "."))
		if lh == "localhost" || strings.HasSuffix(lh, ".localhost") {
			if err := p.CheckIP(netip.MustParseAddr("127.0.0.1")); err != nil {
				return err
			}
		}
	}
	if err := p.CheckSite(host); err != nil {
		return err
	}
	if HasBlockedExtension(u.Path, StreamManifestExts) {
		return blocked(ErrStreamManifest)
	}
	if len(p.DomainAllowlist) > 0 && !p.domainAllowed(host) {
		return blocked("domain %q is not in the allowlist", host)
	}
	return nil
}

func (p *URLPolicy) domainAllowed(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range p.DomainAllowlist {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "."))
		if d == "" {
			continue
		}
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// CheckRawURL parses and checks a URL string, also rejecting UNC and
// Windows-path lookalikes before parsing.
func (p *URLPolicy) CheckRawURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, `\\`) || strings.HasPrefix(raw, "//") {
		return nil, blocked("UNC and scheme-relative paths are not allowed")
	}
	if strings.ContainsAny(raw, "\x00\r\n\t") {
		return nil, blocked("URL contains control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, blocked("cannot parse URL: %v", err)
	}
	if err := p.CheckURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

// Control is a net.Dialer Control hook. It runs on the exact address the
// socket is about to connect to, which defeats DNS rebinding.
func (p *URLPolicy) Control(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return blocked("bad dial address %q", address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return blocked("dial to non-IP address %q", address)
	}
	return p.CheckIP(ip)
}

func (p *URLPolicy) resolver() interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
} {
	if p.Resolver != nil {
		return p.Resolver
	}
	return net.DefaultResolver
}

// precheckHost resolves host and checks every address. Used only when a
// proxy hides the real destination from the dialer hook.
func (p *URLPolicy) precheckHost(ctx context.Context, host string) error {
	if _, ok := ParseHostIP(host); ok {
		return nil // already checked in CheckURL
	}
	addrs, err := p.resolver().LookupNetIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	for _, a := range addrs {
		if err := p.CheckIP(a); err != nil {
			return err
		}
	}
	return nil
}

// MaxRedirects is the redirect hop limit (spec §5.4).
const MaxRedirects = 10

// ClientOptions tunes NewClient.
type ClientOptions struct {
	// ConnectTimeout bounds TCP+TLS setup. Default 30s.
	ConnectTimeout time.Duration
	// ResponseHeaderTimeout bounds waiting for response headers. Default 60s.
	ResponseHeaderTimeout time.Duration
	// OnRedirect is called for every redirect hop that passed policy.
	OnRedirect func(req *http.Request, via []*http.Request)
}

// NewClient returns an http.Client that enforces the policy on every hop
// and on the actual socket address, and ignores system proxy settings.
func (p *URLPolicy) NewClient(o ClientOptions) *http.Client {
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = 30 * time.Second
	}
	if o.ResponseHeaderTimeout == 0 {
		o.ResponseHeaderTimeout = 60 * time.Second
	}
	dialer := &net.Dialer{
		Timeout:   o.ConnectTimeout,
		KeepAlive: 30 * time.Second,
		Control:   p.Control,
	}
	tr := &http.Transport{
		Proxy:                 nil, // never the system proxy (spec §6 rule 7)
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   o.ConnectTimeout,
		ResponseHeaderTimeout: o.ResponseHeaderTimeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true, // we ask for identity and handle encoding ourselves
	}
	if p.Proxy != nil {
		proxyURL := p.Proxy
		tr.Proxy = func(*http.Request) (*url.URL, error) { return proxyURL, nil }
		// The dial hook would see the proxy address; allow the proxy itself.
		if ip, ok := ParseHostIP(proxyURL.Hostname()); ok {
			pp := *p
			pp.AllowPrivate = append(append([]netip.Prefix{}, p.AllowPrivate...), netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
			dialer.Control = pp.Control
		} else {
			dialer.Control = nil
		}
	}
	return &http.Client{
		Transport: &checkingTransport{p: p, rt: tr},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", MaxRedirects)
			}
			if err := p.CheckURL(req.URL); err != nil {
				return err
			}
			if o.OnRedirect != nil {
				o.OnRedirect(req, via)
			}
			return nil
		},
	}
}

// checkingTransport re-checks every request URL (including the first one)
// before it leaves, so a caller can't bypass CheckURL by accident.
type checkingTransport struct {
	p  *URLPolicy
	rt http.RoundTripper
}

func (t *checkingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.p.CheckURL(req.URL); err != nil {
		return nil, err
	}
	if t.p.Proxy != nil {
		if err := t.p.precheckHost(req.Context(), req.URL.Hostname()); err != nil {
			return nil, err
		}
	}
	return t.rt.RoundTrip(req)
}

// CloseIdle closes idle connections of a client built by NewClient.
func CloseIdle(c *http.Client) {
	if ct, ok := c.Transport.(*checkingTransport); ok {
		if tr, ok := ct.rt.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
}
