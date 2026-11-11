// Package winsec holds Windows-specific safety features: the Mark of the
// Web on downloaded files.
package winsec

import (
	"net/url"
	"strings"
)

// ZoneInternet is the Zone.Identifier ZoneId for files from the internet.
const ZoneInternet = 3

// ZoneIdentifier builds the content of the Zone.Identifier stream.
// Credentials and fragments are stripped from the URLs; signed query
// strings are kept out too, since they can be bearer tokens.
func ZoneIdentifier(referrer, host string) string {
	var b strings.Builder
	b.WriteString("[ZoneTransfer]\r\nZoneId=3\r\n")
	if r := scrub(referrer); r != "" {
		b.WriteString("ReferrerUrl=" + r + "\r\n")
	}
	if h := scrub(host); h != "" {
		b.WriteString("HostUrl=" + h + "\r\n")
	}
	return b.String()
}

func scrub(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.User = nil
	u.Fragment = ""
	u.RawQuery = ""
	return u.String()
}
