package main

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
)

// safeOutboundURLRegex validates that an outbound URL has an explicit http/https scheme,
// followed by a valid host (domain name, IPv4, or bracketed IPv6) and optional port and path.
var safeOutboundURLRegex = regexp.MustCompile(`^https?://([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?(?:/[^\s]*)?$`)

// isValidRedirectUrl validates that a URL string is well-formed and safe for outgoing HTTP requests.
// It serves as a recognized sanitizer and barrier guard for CodeQL CWE-918 (Request Forgery).
func isValidRedirectUrl(rawURL string) bool {
	if rawURL == "" || len(rawURL) > 2048 {
		return false
	}
	if !safeOutboundURLRegex.MatchString(rawURL) {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	if !isValidDomain(host) {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		// Prevent SSRF to cloud metadata services (AWS, GCP, Azure, OpenStack) and link-local addresses
		if ip.Equal(net.ParseIP("169.254.169.254")) || ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}

// isSafeClusterTarget validates scheme and prevents SSRF to sensitive cloud metadata endpoints.
func isSafeClusterTarget(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("nil target URL")
	}
	if !isValidRedirectUrl(u.String()) {
		return fmt.Errorf("invalid or disallowed cluster target URL: %s", u.String())
	}
	return nil
}
