package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// openLocalOfficialFile attempts to open a bundled official blocklist/allowlist from local filesystem paths.
func openLocalOfficialFile(relPath string) (*os.File, error) {
	if strings.Contains(relPath, "..") || strings.Contains(relPath, "\\") {
		return nil, os.ErrNotExist
	}
	var safeRel string
	switch relPath {
	case "allowlists/default.txt":
		safeRel = "allowlists/default.txt"
	case "blocklists/default.txt":
		safeRel = "blocklists/default.txt"
	case "blocklists/search-ads-hybrid.txt":
		safeRel = "blocklists/search-ads-hybrid.txt"
	default:
		return nil, os.ErrNotExist
	}
	for _, base := range []string{"official", "/official", "/app/official"} {
		if f, err := os.Open(filepath.Join(base, safeRel)); err == nil {
			return f, nil
		}
	}
	return nil, os.ErrNotExist
}

// createSafeBlocklistClient returns an HTTP client with custom dialer that verifies
// target IP addresses to prevent Server-Side Request Forgery (SSRF) and DNS rebinding attacks.
func createSafeBlocklistClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if testMode {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if ip := net.ParseIP(host); ip != nil {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
					go SendSecurityWebhook("dns_rebinding", "DNS-Rebinding / SSRF Angriff abgewehrt", map[string]interface{}{
						"target":     addr,
						"blocked_ip": ip.String(),
						"type":       "direct_private_ip",
					})
					return nil, fmt.Errorf("connection to private/local IP blocked: %s", ip.String())
				}
			} else {
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, fmt.Errorf("dns resolution failed: %w", err)
				}
				for _, ip := range ips {
					if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
						go SendSecurityWebhook("dns_rebinding", "DNS-Rebinding / SSRF Angriff abgewehrt", map[string]interface{}{
							"target":     addr,
							"blocked_ip": ip.String(),
							"type":       "resolved_private_ip",
						})
						return nil, fmt.Errorf("connection to private/local IP blocked: %s", ip.String())
					}
				}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func isTransientBlocklistFetchError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "Timeout exceeded") ||
		strings.Contains(msg, "awaiting headers") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "connection reset")
}

// fetchBlocklistURL performs a safe HTTP GET for a blocklist URL with retry on timeout.
// It enforces HTTPS, validates that the destination is not private/loopback,
// and uses an SSRF-safe dialer.
func fetchBlocklistURL(rawURL, userAgent string, extraHeaders map[string]string, timeoutSec int) (*http.Response, error) {
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	resp, err := doFetchBlocklistURL(rawURL, userAgent, extraHeaders, timeoutSec)
	if isTransientBlocklistFetchError(err) || (resp != nil && (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500)) {
		if resp != nil {
			resp.Body.Close()
		}
		// Retry once on transient network timeout or server 5xx/429 with increased timeout
		time.Sleep(1 * time.Second)
		return doFetchBlocklistURL(rawURL, userAgent, extraHeaders, timeoutSec+30)
	}
	return resp, err
}

func doFetchBlocklistURL(rawURL, userAgent string, extraHeaders map[string]string, timeoutSec int) (*http.Response, error) {
	if !isValidRedirectUrl(rawURL) || !safeOutboundURLRegex.MatchString(rawURL) {
		return nil, fmt.Errorf("invalid or forbidden blocklist URL: %s", rawURL)
	}
	if !isValidListURL(rawURL) && !testMode {
		return nil, fmt.Errorf("invalid or forbidden blocklist URL: %s", rawURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url parse: %w", err)
	}

	scheme := parsed.Scheme
	if scheme != "https" && !testMode {
		return nil, fmt.Errorf("blocklist URL must use HTTPS (got %q) – skipping for security", scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	if !testMode {
		if ip := net.ParseIP(hostname); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return nil, fmt.Errorf("forbidden private IP for blocklist: %s", hostname)
			}
		} else {
			hostLower := strings.ToLower(hostname)
			if hostLower == "localhost" || strings.HasSuffix(hostLower, ".local") || strings.HasSuffix(hostLower, ".internal") || strings.HasSuffix(hostLower, ".lan") {
				return nil, fmt.Errorf("forbidden private hostname for blocklist: %s", hostname)
			}
		}
	}

	host := hostname
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(hostname, port)
	}

	cleanURL := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     parsed.EscapedPath(),
		RawQuery: parsed.RawQuery,
	}
	targetURL := cleanURL.String()
	if !isValidRedirectUrl(targetURL) || !safeOutboundURLRegex.MatchString(targetURL) {
		return nil, fmt.Errorf("invalid or forbidden blocklist target URL: %s", targetURL)
	}

	timeout := time.Duration(timeoutSec) * time.Second
	client := createSafeBlocklistClient(timeout)
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return client.Do(req) //nolint:wrapcheck
}

// fetchBlocklistURLWithContext is like fetchBlocklistURL but accepts an existing context.
func fetchBlocklistURLWithContext(ctx context.Context, rawURL, userAgent string, extraHeaders map[string]string) (*http.Response, error) {
	if !isValidRedirectUrl(rawURL) || !safeOutboundURLRegex.MatchString(rawURL) {
		return nil, fmt.Errorf("invalid or forbidden blocklist URL: %s", rawURL)
	}
	if !isValidListURL(rawURL) && !testMode {
		return nil, fmt.Errorf("invalid or forbidden blocklist URL: %s", rawURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url parse: %w", err)
	}

	scheme := parsed.Scheme
	if scheme != "https" && !testMode {
		return nil, fmt.Errorf("blocklist URL must use HTTPS (got %q) – skipping for security", scheme)
	}

	hostname := parsed.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("empty hostname")
	}

	if !testMode {
		if ip := net.ParseIP(hostname); ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return nil, fmt.Errorf("forbidden private IP for blocklist: %s", hostname)
			}
		} else {
			hostLower := strings.ToLower(hostname)
			if hostLower == "localhost" || strings.HasSuffix(hostLower, ".local") || strings.HasSuffix(hostLower, ".internal") || strings.HasSuffix(hostLower, ".lan") {
				return nil, fmt.Errorf("forbidden private hostname for blocklist: %s", hostname)
			}
		}
	}

	host := hostname
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(hostname, port)
	}

	cleanURL := &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     parsed.EscapedPath(),
		RawQuery: parsed.RawQuery,
	}
	targetURL := cleanURL.String()
	if !isValidRedirectUrl(targetURL) || !safeOutboundURLRegex.MatchString(targetURL) {
		return nil, fmt.Errorf("invalid or forbidden blocklist target URL: %s", targetURL)
	}

	client := createSafeBlocklistClient(60 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	return client.Do(req) //nolint:wrapcheck
}
