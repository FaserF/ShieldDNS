package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

var geoCache sync.Map    // Cache for GeoIP results (IP -> IPInfo snippet)
var geoInFlight sync.Map // Track active lookups to prevent duplicates

// domainRegex allows standard domains, wildcards (*.domain.com), underscores, and single-label local hostnames.
var domainRegex = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9_]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9_])?\.)*[a-zA-Z0-9_]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9_])?$`)

// isValidDomain checks if a string is a valid domain name or IP address.
func isValidDomain(s string) bool {
	if s == "" {
		return false
	}
	// Allow valid IP addresses
	if net.ParseIP(s) != nil {
		return true
	}
	// Check against domain regex
	if len(s) > 253 {
		return false
	}
	// Strict check: no spaces, no newlines, no brackets
	if strings.ContainsAny(s, " \n\r\t{}()<>\\\"'`|") {
		return false
	}

	// Fast path for common domains
	if domainRegex.MatchString(s) {
		return true
	}

	return false
}

// sendJSONError sends a machine-readable error response.
func sendJSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// isValidUpstream checks if a string is a valid DNS upstream (IP or Hostname).
func isValidUpstream(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Strip protocol if present for validation
	clean := s
	if idx := strings.Index(s, "://"); idx != -1 {
		clean = s[idx+3:]
	}

	host := clean
	if strings.Contains(clean, ":") {
		var err error
		host, _, err = net.SplitHostPort(clean)
		if err != nil {
			return false // Malformed addr:port
		}
	}

	return isValidDomain(host)
}

// escapeXML prepares a string for safe insertion into an XML attribute or element.
func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// NormalizeDomain strips protocols, paths, fragments, and trailing dots to return a clean domain in lowercase.
func NormalizeDomain(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}

	// Heuristic: If it contains a slash but no protocol delimiter, it's a path traversal or absolute path
	// e.g. "../../../etc/passwd" or "/etc/passwd"
	// but "http://google.com" is fine.
	firstSlash := strings.Index(s, "/")
	protocolIdx := strings.Index(s, "://")
	if firstSlash != -1 && (protocolIdx == -1 || firstSlash < protocolIdx) {
		return ""
	}

	// Strip protocols
	if protocolIdx != -1 {
		s = s[protocolIdx+3:]
	}
	// Strip paths and query strings
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	// Strip trailing dot
	s = strings.TrimSuffix(s, ".")

	// Final safety: Detect any characters that don't belong in a domain.
	// If any invalid character is found, the entire domain is rejected.
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' || r == '*') {
			return "" // Reject invalid domains completely
		}
	}
	return s
}

// AdblockRule contains parsed components of an Adblock/AdGuard syntax rule
type AdblockRule struct {
	Domain      string   // Normalized domain or regex pattern
	IsAllowlist bool     // True if @@ rule
	IsImportant bool     // True if $important modifier present
	IsDNSRule   bool     // True if $dnsrewrite or standard domain rule
	IsRegex     bool     // True if /regex/
	ClientIP    string   // Client IP or subnet from $client modifier
	Modifiers   []string // List of modifiers like important, all, cname, etc.
}

// ParseAdblockRule parses AdGuard / AdBlock Plus DNS filter rules:
// - @@||example.com^ (exception/allowlist)
// - ||example.com^ (block domain and all subdomains)
// - ||example.com^$important,badfilter,dnstype=...
// - ||example.com^$client='192.168.1.108'
// - |http://example.com| or |https://example.com/
// - standard domains, hosts lines, dnsmasq lines
func ParseAdblockRule(raw string) *AdblockRule {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return nil
	}

	// Skip HTML/CSS cosmetic rules from browser adblockers (##, #?#, #$#)
	if strings.Contains(line, "##") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
		return nil
	}

	rule := &AdblockRule{}

	// 1. Exception rule check (@@)
	if strings.HasPrefix(line, "@@") {
		rule.IsAllowlist = true
		line = strings.TrimPrefix(line, "@@")
	}

	// 2. Extract modifiers after '$'
	if idx := strings.Index(line, "$"); idx != -1 {
		modifiersStr := line[idx+1:]
		line = line[:idx]
		for _, mod := range strings.Split(modifiersStr, ",") {
			mod = strings.TrimSpace(mod)
			if mod == "" {
				continue
			}
			rule.Modifiers = append(rule.Modifiers, strings.ToLower(mod))
			if strings.EqualFold(mod, "important") {
				rule.IsImportant = true
			}
			// Parse $client='192.168.1.108' or $client=192.168.1.108
			lowMod := strings.ToLower(mod)
			if strings.HasPrefix(lowMod, "client=") {
				clientVal := strings.TrimPrefix(mod, "client=")
				if strings.HasPrefix(lowMod, "client=") {
					clientVal = mod[len("client="):]
				}
				clientVal = strings.Trim(clientVal, "'\" ")
				rule.ClientIP = clientVal
			}
		}
	}

	// 3. Handle regexp /pattern/
	if len(line) > 2 && strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") && line[1] != '/' && line[1] != '\\' {
		rule.IsRegex = true
		rule.Domain = line[1 : len(line)-1]
		return rule
	}

	// 4. Handle ||domain^ or ||domain
	if strings.HasPrefix(line, "||") {
		content := strings.TrimPrefix(line, "||")
		if idx := strings.Index(content, "^"); idx != -1 {
			content = content[:idx]
		}
		rule.Domain = NormalizeDomain(content)
		if rule.Domain != "" {
			rule.IsDNSRule = true
			return rule
		}
		return nil
	}

	// 5. Handle |http:// or |https:// prefixes
	if strings.HasPrefix(line, "|") {
		content := strings.Trim(line, "|")
		rule.Domain = NormalizeDomain(content)
		if rule.Domain != "" {
			rule.IsDNSRule = true
			return rule
		}
		return nil
	}

	// 6. Handle ^ separator at end
	if strings.HasSuffix(line, "^") {
		content := strings.TrimSuffix(line, "^")
		rule.Domain = NormalizeDomain(content)
		if rule.Domain != "" {
			rule.IsDNSRule = true
			return rule
		}
		return nil
	}

	// 7. Standard normalize fallback
	d := NormalizeDomain(line)
	if d != "" {
		rule.Domain = d
		rule.IsDNSRule = true
		return rule
	}

	return nil
}

// isValidListURL checks if a URL is safe to fetch blocklists from.
// Only HTTPS and file:// are permitted. Plain HTTP is rejected to prevent
// man-in-the-middle attacks on blocklist downloads.
func isValidListURL(rawURL string) bool {
	if testMode {
		return true
	}
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return false
	}

	// file:// URLs are handled separately with path-restriction checks in processList
	if strings.HasPrefix(rawURL, "file://") {
		return true
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// Only HTTPS is allowed – plain HTTP is insecure for blocklist downloads
	if parsed.Scheme != "https" {
		return false
	}

	host := parsed.Hostname()
	if host == "" {
		return false
	}

	// Block loopback / private ranges by IP
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
	} else {
		// Block well-known internal hostnames
		hostLower := strings.ToLower(host)
		if hostLower == "localhost" || strings.HasSuffix(hostLower, ".local") || strings.HasSuffix(hostLower, ".internal") || strings.HasSuffix(hostLower, ".lan") {
			return false
		}

		// Resolve the hostname to check resolved IP addresses (prevents SSRF via DNS rebinding)
		ips, err := net.LookupIP(host)
		if err != nil {
			return false // Block if host cannot be resolved
		}
		for _, ip := range ips {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				return false
			}
		}
	}

	return true
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
					return nil, fmt.Errorf("connection to private/local IP blocked: %s", ip.String())
				}
			} else {
				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, fmt.Errorf("dns resolution failed: %w", err)
				}
				for _, ip := range ips {
					if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
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

// fetchBlocklistURL performs a safe HTTP GET for a blocklist URL.
// It enforces HTTPS, validates that the destination is not private/loopback,
// and uses an SSRF-safe dialer.
func fetchBlocklistURL(rawURL, userAgent string, extraHeaders map[string]string, timeoutSec int) (*http.Response, error) {
	if !isValidListURL(rawURL) && !testMode {
		return nil, fmt.Errorf("invalid or forbidden blocklist URL: %s", rawURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url parse: %w", err)
	}

	// Only HTTPS is allowed for blocklist downloads (bypassed in testMode for local test servers)
	scheme := parsed.Scheme
	if scheme != "https" && !testMode {
		return nil, fmt.Errorf("blocklist URL must use HTTPS (got %q) – skipping for security", scheme)
	}

	// Re-validate host
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

	timeout := time.Duration(timeoutSec) * time.Second
	client := createSafeBlocklistClient(timeout)
	req, err := http.NewRequest(http.MethodGet, cleanURL.String(), nil)
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
	if !isValidListURL(rawURL) && !testMode {
		return nil, fmt.Errorf("invalid or forbidden blocklist URL: %s", rawURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("url parse: %w", err)
	}

	// Only HTTPS is allowed for blocklist downloads (bypassed in testMode for local test servers)
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

	client := createSafeBlocklistClient(30 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cleanURL.String(), nil)
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

// IsCriticalIP checks if an IP belongs to core infrastructure that should never be blocked.
func IsCriticalIP(ip string, blockPageIP string, whitelist []string) bool {
	if ip == "DoH Proxy" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	if ip != "" && ip == blockPageIP {
		return true
	}

	for _, w := range whitelist {
		if w == ip {
			return true
		}
	}

	return false
}

// extractIPFromLog attempts to parse an IP address from common Go HTTP server error messages.
func extractIPFromLog(msg string) string {
	// Look for "from <ip>:<port>" or "from client <ip>:<port>"
	// Examples:
	// "http: TLS handshake error from 1.2.3.4:123"
	// "http2: server: error reading preface from client 1.2.3.4:123"

	idx := strings.Index(msg, "from ")
	if idx == -1 {
		return ""
	}

	part := msg[idx+5:]
	if strings.HasPrefix(part, "client ") {
		part = part[7:]
	}

	// Find the last colon (it separates IP and Port)
	lastColon := strings.LastIndex(part, ":")
	if lastColon == -1 {
		return ""
	}

	// The IP is between the start and the last colon
	ip := part[:lastColon]

	// Basic validation
	if net.ParseIP(ip) != nil {
		return ip
	}

	return ""
}

func CalculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]float64)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	total := float64(len(s))
	for _, count := range counts {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func extractQuotes(s string) []string {
	var quotes []string
	start := -1
	for i, char := range s {
		if char == '"' {
			if start == -1 {
				start = i
			} else {
				quotes = append(quotes, s[start+1:i])
				start = -1
			}
		}
	}
	return quotes
}

// AnonymizeIP masks client IP addresses for privacy compliance (GDPR/DSGVO).
// IPv4: masks the last octet (/24 subnet masking).
// IPv6: masks the lower 64 bits (/64 subnet masking).
func AnonymizeIP(ipStr string) string {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" || ipStr == "DoH Proxy" || ipStr == "localhost" {
		return ipStr
	}

	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return ipStr
	}

	if ipv4 := parsed.To4(); ipv4 != nil {
		// IPv4: Zero the last octet (e.g., 192.168.1.42 -> 192.168.1.0)
		return fmt.Sprintf("%d.%d.%d.0", ipv4[0], ipv4[1], ipv4[2])
	}

	// IPv6: Retain first 64 bits (4 groups of 16-bit hextets), zero out the host identifier
	ipv6 := parsed.To16()
	if ipv6 != nil {
		mask := net.CIDRMask(64, 128)
		masked := ipv6.Mask(mask)
		return masked.String()
	}

	return ipStr
}
