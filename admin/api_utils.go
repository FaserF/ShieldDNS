package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
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

// isValidListURL checks if a URL is safe to fetch blocklists from.
// It only permits http/https schemes and blocks requests to private/loopback networks
// to prevent SSRF attacks (CWE-918 / CodeQL go/request-forgery).
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

	// Only allow http and https
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
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
	}

	return true
}

// IsCriticalIP checks if an IP belongs to core infrastructure that should never be blocked.
func IsCriticalIP(ip string, blockPageIP string) bool {
	if ip == "DoH Proxy" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return true
	}

	if ip != "" && ip == blockPageIP {
		return true
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

// GetCountryCodeCached returns the country code for an IP from cache, or "-" if not yet known.
// It triggers an async lookup if the IP is not in cache to avoid blocking the DNS worker.
func GetCountryCodeCached(ip string) string {
	if ip == "" || ip == "DoH Proxy" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return "geo" // Local/Internal
	}

	// Check if IP is private
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil && (parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()) {
		return "geo"
	}

	// Check main IP info cache
	if val, ok := ipInfoCache.Load(ip); ok {
		info := val.(IPInfo)
		if info.CountryCode != "" {
			return info.CountryCode
		}
	}

	// Check GeoIP snippet cache
	if cached, ok := geoCache.Load(ip); ok {
		if c, ok := cached.(IPInfo); ok && c.CountryCode != "" {
			return c.CountryCode
		}
	}

	// Check if a lookup is already in progress for this IP
	if _, loaded := geoInFlight.LoadOrStore(ip, true); loaded {
		return "-"
	}
	
	// Not in cache, trigger an async lookup for future queries
	go func(targetIP string) {
		defer geoInFlight.Delete(targetIP)
		
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		fetchGeoIP(ctx, targetIP)
	}(ip)

	return "-"
}

// fetchGeoIP is a simplified version of the lookup logic in handleIPInfo
func fetchGeoIP(ctx context.Context, ip string) {
	var geoData struct {
		CountryCode string `json:"countryCode"`
		Status      string `json:"status"`
	}

	// Try the most reliable fast provider
	url := "https://ip-api.com/json/" + ip + "?fields=status,countryCode"
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "ShieldDNS-Admin/v1.14")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	
	if json.NewDecoder(resp.Body).Decode(&geoData) == nil && geoData.Status == "success" {
		// Update geoCache
		geoCache.Store(ip, IPInfo{CountryCode: geoData.CountryCode})
	}
}

func handleIPInfo(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	if val, ok := ipInfoCache.Load(ip); ok {
		info := val.(IPInfo)
		if time.Now().Before(info.ExpiresAt) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info)
			return
		}
	}

	isPrivate := false
	parsedIP := net.ParseIP(ip)
	if parsedIP != nil {
		if parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast() {
			isPrivate = true
		}
	} else if ip == "DoH Proxy" || ip == "localhost" {
		isPrivate = true
	}

	configLock.RLock()
	alias := config.ClientAliases[ip]
	configLock.RUnlock()

	info := IPInfo{
		IP:        ip,
		Alias:     alias,
		IsPrivate: isPrivate,
	}

	// Use context with timeout for all network-dependent lookups
	LookupCtx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	// Reverse DNS with Resolver to support timeouts
	if info.Hostname == "" {
		resolver := &net.Resolver{}
		names, err := resolver.LookupAddr(LookupCtx, ip)
		if err == nil && len(names) > 0 {
			info.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}
	if ip == "DoH Proxy" {
		info.Hostname = "ShieldDNS Internal Proxy"
		info.ISP = "Local Forwarder"
		info.Country = "Local"
		info.CountryCode = "geo" // Standardized local indicator
		info.City = "Server Environment"
		info.Manufacturer = "ShieldDNS System"
		info.OS = "ShieldDNS Native"
	} else if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		info.Hostname = "Localhost (Loopback)"
		info.ISP = "Internal Interface"
		info.Country = "Server Environment"
		info.CountryCode = "geo"
		info.City = "ShieldDNS Core"
		info.Manufacturer = "ShieldDNS Console"
		info.OS = "ShieldDNS Native"
	}

	// GeoIP for public IPs
	if !isPrivate {
		// Check cache first
		if cached, ok := geoCache.Load(ip); ok {
			c := cached.(IPInfo)
			info.Country = c.Country
			info.CountryCode = c.CountryCode
			info.City = c.City
			info.ISP = c.ISP
			info.Org = c.Org
			info.AS = c.AS
		} else {
			geoCtx, geoCancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer geoCancel()

			var geoData struct {
				Country     string `json:"country"`
				CountryCode string `json:"countryCode"`
				City        string `json:"city"`
				ISP         string `json:"isp"`
				Org         string `json:"org"`
				AS          string `json:"as"`
				Status      string `json:"status"`
				Message     string `json:"message"`
			}

			// Multiple providers for client IP resolution
			providers := []struct {
				url    string
				parser func([]byte) error
			}{
				{
					url: "https://ip-api.com/json/" + ip,
					parser: func(b []byte) error {
						return json.Unmarshal(b, &geoData)
					},
				},
				{
					url: "http://ip-api.com/json/" + ip,
					parser: func(b []byte) error {
						return json.Unmarshal(b, &geoData)
					},
				},
				{
					url: "https://ipwho.is/" + ip,
					parser: func(b []byte) error {
						var raw struct {
							Country     string `json:"country"`
							CountryCode string `json:"country_code"`
							City        string `json:"city"`
							Connection  struct {
								ISP string `json:"isp"`
								Org string `json:"org"`
								ASN int    `json:"asn"`
							} `json:"connection"`
							Success bool `json:"success"`
						}
						if err := json.Unmarshal(b, &raw); err != nil || !raw.Success {
							return fmt.Errorf("ipwho.is failed or returned success=false")
						}
						geoData.Status = "success"
						geoData.Country = raw.Country
						geoData.CountryCode = raw.CountryCode
						geoData.City = raw.City
						geoData.ISP = raw.Connection.ISP
						geoData.Org = raw.Connection.Org
						geoData.AS = fmt.Sprintf("AS%d", raw.Connection.ASN)
						return nil
					},
				},
			}

			for _, p := range providers {
				req, _ := http.NewRequestWithContext(geoCtx, "GET", p.url, nil)
				req.Header.Set("User-Agent", "ShieldDNS-Admin/v1.14")

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				if err := p.parser(body); err == nil && geoData.Status == "success" {
					info.Country = geoData.Country
					info.CountryCode = geoData.CountryCode
					info.City = geoData.City
					info.ISP = geoData.ISP
					info.Org = geoData.Org
					info.AS = geoData.AS

					// Store in cache
					geoCache.Store(ip, info)
					break
				}
			}
		}
	}

	// MAC and Manufacturer for local IPs
	if isPrivate {
		mac := getMACByIP(ip)
		if mac != "" {
			info.MAC = mac
			info.Manufacturer = getManufacturerByMAC(mac)
		}
	}

	// Add User-Agent and OS info if available
	ua := ""
	if uaVal, ok := ipToUA.Load(ip); ok {
		ua = uaVal.(string)
	} else {
		// Fallback to database for persistence across restarts
		ua = getClientUA(ip)
		if ua != "" {
			ipToUA.Store(ip, ua) // Refresh memory cache
		}
	}

	if ua != "" && ua != "-" && ua != "none" {
		info.UserAgent = ua
		if detectedOS := detectOS(ua); detectedOS != "" {
			info.OS = detectedOS
		}

		// If it's a mobile/smart device, improve the manufacturer field
		if info.Manufacturer == "" || info.Manufacturer == "Unknown" || info.Manufacturer == "-" {
			if dev := detectDevice(ua); dev != "" {
				info.Manufacturer = dev
			}
		}
	}

	// Inference from Hostname (last resort, only if info is still unknown)
	if info.Hostname != "" {
		hostOS, hostMan := inferFromHostname(info.Hostname)
		if info.OS == "" || info.OS == "Unknown OS" {
			info.OS = hostOS
		}
		if info.Manufacturer == "" || info.Manufacturer == "Unknown" || info.Manufacturer == "-" {
			info.Manufacturer = hostMan
		}
	}

	// Set expiration
	if isPrivate {
		info.ExpiresAt = time.Now().Add(1 * time.Hour)
	} else {
		info.ExpiresAt = time.Now().Add(24 * time.Hour)
	}

	// Final Fallbacks to avoid "-" in UI
	if info.Country == "" {
		info.Country = "-"
	}
	if info.City == "" {
		info.City = "-"
	}
	if info.ISP == "" {
		info.ISP = "-"
	}
	if info.OS == "" {
		info.OS = "Unknown OS"
	}

	ipInfoCache.Store(ip, info)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func detectOS(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod"):
		return "iOS"
	case strings.Contains(ua, "android"):
		if strings.Contains(ua, "tv") || strings.Contains(ua, "fire") {
			return "Android TV"
		}
		return "Android"
	case strings.Contains(ua, "windows nt"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		return "macOS"
	case strings.Contains(ua, "linux") && !strings.Contains(ua, "android"):
		if strings.Contains(ua, "hass.io") || strings.Contains(ua, "home assistant") {
			return "Home Assistant OS"
		}
		return "Linux"
	case strings.Contains(ua, "crkey") || strings.Contains(ua, "chromecast"):
		return "Chromecast"
	case strings.Contains(ua, "tizen"):
		return "Tizen (Samsung TV)"
	case strings.Contains(ua, "playstation"):
		return "PlayStation"
	case strings.Contains(ua, "nintendo switch"):
		return "Nintendo Switch"
	case strings.Contains(ua, "dnssettings"):
		return "Apple Managed DNS"
	case strings.Contains(ua, "shelly"):
		return "Shelly IoT"
	case strings.Contains(ua, "esphome") || strings.Contains(ua, "tasmota") || strings.Contains(ua, "esp8266") || strings.Contains(ua, "esp32"):
		return "ESP-based IoT"
	case strings.Contains(ua, "sonos"):
		return "Sonos"
	case strings.Contains(ua, "rokios"):
		return "Roku OS"
	case strings.Contains(ua, "appletv") || strings.Contains(ua, "apple tv"):
		return "tvOS"
	case strings.Contains(ua, "aetv") || strings.Contains(ua, "firetv"):
		return "Fire OS"
	case strings.Contains(ua, "hdm") || strings.Contains(ua, "hue"):
		return "Philips Hue"
	}
	return ""
}

func detectDevice(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone"):
		return "iPhone"
	case strings.Contains(ua, "ipad"):
		return "iPad"
	case strings.Contains(ua, "atv") || strings.Contains(ua, "appletv") || strings.Contains(ua, "apple tv"):
		return "Apple TV"
	case strings.Contains(ua, "aft") || strings.Contains(ua, "firetv"):
		return "Amazon Fire TV"
	case strings.Contains(ua, "nexus") || strings.Contains(ua, "pixel"):
		return "Google Pixel"
	case strings.Contains(ua, "sonos"):
		return "Sonos Speaker"
	case strings.Contains(ua, "shelly"):
		return "Shelly Device"
	case strings.Contains(ua, "lg") && strings.Contains(ua, "webos"):
		return "LG Smart TV"
	case strings.Contains(ua, "bravia") || (strings.Contains(ua, "sony") && strings.Contains(ua, "tv")):
		return "Sony Smart TV"
	case strings.Contains(ua, "esphome"):
		return "ESPHome Device"
	case strings.Contains(ua, "unifi"):
		return "Ubiquiti Unifi"
	case strings.Contains(ua, "samsung") || strings.Contains(ua, "sm-"):
		return "Samsung Device"
	case strings.Contains(ua, "oneplus"):
		return "OnePlus Phone"
	case strings.Contains(ua, "huawei") || strings.Contains(ua, "honor"):
		return "Huawei/Honor Device"
	}
	return ""
}

func inferFromHostname(h string) (os, manufacturer string) {
	h = strings.ToLower(h)
	switch {
	case strings.Contains(h, "iphone"):
		return "iOS", "Apple (iPhone)"
	case strings.Contains(h, "ipad"):
		return "iOS", "Apple (iPad)"
	case strings.Contains(h, "macbook") || strings.Contains(h, "mac-") || strings.Contains(h, "imac"):
		return "macOS", "Apple (Mac)"
	case strings.Contains(h, "apple-watch") || strings.Contains(h, "watchos"):
		return "watchOS", "Apple Watch"
	case strings.Contains(h, "android"):
		return "Android", "Android Device"
	case strings.Contains(h, "pixel"):
		return "Android", "Google Pixel"
	case strings.Contains(h, "galaxy") || strings.Contains(h, "samsung"):
		return "Android", "Samsung Device"
	case strings.Contains(h, "windows"):
		return "Windows", "PC/Laptop"
	case strings.Contains(h, "nintendo"):
		return "Nintendo OS", "Nintendo Console"
	case strings.Contains(h, "playstation") || strings.Contains(h, "ps4") || strings.Contains(h, "ps5"):
		return "PlayStation OS", "Sony PlayStation"
	case strings.Contains(h, "xbox"):
		return "Xbox OS", "Microsoft Xbox"
	case strings.Contains(h, "sonos"):
		return "Sonos OS", "Sonos Speaker"
	case strings.Contains(h, "shelly"):
		return "Shelly Native", "Shelly IoT"
	case strings.Contains(h, "esphome") || strings.Contains(h, "tasmota") || strings.Contains(h, "esp32"):
		return "ESP-based", "IoT Device"
	case strings.Contains(h, "raspberry") || strings.Contains(h, "raspi"):
		return "Linux", "Raspberry Pi"
	case strings.Contains(h, "synology") || strings.Contains(h, "diskstation"):
		return "DSM", "Synology NAS"
	case strings.Contains(h, "unifi"):
		return "Unifi OS", "Ubiquiti Device"
	case strings.Contains(h, "fritz.box") || strings.Contains(h, "fritz.nas") || strings.Contains(h, "fritz-box"):
		return "FRITZ!OS", "AVM"
	case strings.Contains(h, "hp-printer") || strings.Contains(h, "hp_printer") || strings.Contains(h, "hpsmart"):
		return "Embedded", "HP Printer"
	case strings.Contains(h, "bridge") || strings.Contains(h, "gateway"):
		return "Embedded", "Network Bridge"
	case strings.Contains(h, "camera") || strings.Contains(h, "cam-"):
		return "Embedded", "Security Camera"
	case strings.Contains(h, "echo") || strings.Contains(h, "alexa") || strings.Contains(h, "amazon"):
		return "Fire OS", "Amazon Echo"
	}
	return "", ""
}

func getMACByIP(ip string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ip {
			return fields[3]
		}
	}
	return ""
}

func getManufacturerByMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))

	// Expanded OUI database
	ouis := map[string]string{
		"B4FB12": "Apple", "0017F2": "Apple", "D0034B": "Apple", "F01898": "Apple",
		"04D6B8": "Apple", "1499E2": "Apple", "341298": "Apple", "404D7F": "Apple",
		"600308": "Apple", "703560": "Apple", "8C8590": "Apple", "DC2BD4": "Apple",
		"00166B": "Samsung", "E470B8": "Samsung", "286B35": "Samsung", "382D23": "Samsung",
		"484377": "Samsung", "8C71F8": "Samsung", "90B686": "Samsung", "B40B44": "Samsung",
		"702C1F": "Google", "D824BD": "Google", "1CC035": "Google", "BCD074": "Google",
		"28D244": "Xiaomi", "649E33": "Xiaomi", "8CBEBE": "Xiaomi", "ACF7F3": "Xiaomi",
		"00000C": "Cisco", "000142": "Cisco", "000143": "Cisco",
		"0010FA": "Sony", "280D1C": "Sony", "3C0771": "Sony", "709E29": "Sony",
		"001422": "Dell", "000874": "Dell", "000AF7": "Dell",
		"001143": "HP", "000E7F": "HP", "001185": "HP",
		"001132": "Synology", "9009DF": "Synology", "0024A5": "Synology",
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
		"000C29": "VMware", "080027": "VirtualBox",
		"000420": "Slim Devices (Logitech)",
		"00096B": "IBM",
		"001F3B": "Nintendo", "98415C": "Nintendo", "E0E751": "Nintendo",
		"C0EEFB": "OnePlus",
		"000FB5": "Netgear", "288088": "Netgear", "BCF685": "Netgear",
		"0014BF": "Linksys",
		"0018E7": "TP-Link", "F4F26D": "TP-Link", "002719": "TP-Link", "50D4F7": "TP-Link", "D807B6": "TP-Link",
		"24A160": "Espressif (IoT)", "30AEA4": "Espressif (IoT)", "A4CF12": "Espressif (IoT)", "84F3EB": "Espressif (IoT)",
		"BCDD26": "Shelly/Allterco", "C049EF": "Shelly/Allterco", "40F520": "Shelly/Allterco",
		"00032F": "Sonos", "B8E937": "Sonos", "5C56D0": "Sonos", "949F3E": "Sonos",
		"00156D": "Ubiquiti", "0418D6": "Ubiquiti", "B4FBE4": "Ubiquiti", "7483C2": "Ubiquiti", "68D79A": "Ubiquiti",
		"0004F2": "Polycom", "64167F": "Polycom",
		"00E062": "Brother", "3C2AF4": "Brother", "E4A7A0": "Brother",
		"001788": "Philips Hue", "ECB5FA": "Philips Hue",
		"603197": "Netatmo",
		"002686": "AVM (FritzBox)", "0896D7": "AVM (FritzBox)", "3431C4": "AVM (FritzBox)", "3810D5": "AVM (FritzBox)",
		"444E6D": "AVM (FritzBox)", "7CC709": "AVM (FritzBox)", "9C28BF": "AVM (FritzBox)", "BC0543": "AVM (FritzBox)",
		"E0286D": "AVM (FritzBox)", "FCFBFB": "AVM (FritzBox)",
		"D4AD70": "Tesla", "44FB42": "Tesla",
		"0024E4": "Withings",
	}

	if m, ok := ouis[prefix]; ok {
		return m
	}
	return "-"
}

func handleQR(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "data parameter required", http.StatusBadRequest)
		return
	}
	if len(data) > 500 {
		http.Error(w, "data too long", http.StatusBadRequest)
		return
	}

	png, err := qrcode.Encode(data, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(png)
}

func handleMobileConfig(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	adminDomain := config.AdminDomain
	blockPageIP := config.BlockPageIP
	signEnabled := config.SignMobileConfig
	configLock.RUnlock()

	host := adminDomain
	if host == "" {
		host = r.Host
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
	}

	// Build ServerAddresses XML block (Bootstrap IPs)
	// We should use the actual server IP that the client can reach.
	bootstrapIP := blockPageIP
	if bootstrapIP == "" || bootstrapIP == "127.0.0.1" || bootstrapIP == "0.0.0.0" {
		// Fallback: Try to get the IP from the host header if it's an IP
		h := r.Host
		if strings.Contains(h, ":") {
			h, _, _ = net.SplitHostPort(h)
		}
		if net.ParseIP(h) != nil {
			bootstrapIP = h
		} else {
			bootstrapIP = "" // No bootstrap IP available
		}
	}

	serverAddrsXML := ""
	if bootstrapIP != "" && bootstrapIP != "127.0.0.1" {
		serverAddrsXML = fmt.Sprintf(`
			<key>ServerAddresses</key>
			<array>
				<string>%s</string>
			</array>`, bootstrapIP)
	}

	// Certificate handling - check if self-signed
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}

	isSelfSigned := false
	var certBase64 string
	certData, err := os.ReadFile(certFile)
	if err != nil {
		certData, _ = os.ReadFile("/etc/shielddns/ssl/selfsigned.crt")
	}

	if certData != nil {
		block, _ := pem.Decode(certData)
		if block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if cert.Issuer.String() == cert.Subject.String() {
					isSelfSigned = true
					certBase64 = base64.StdEncoding.EncodeToString(block.Bytes)
				}
			}
		}
	} else {
		// Try fallback from DataDir
		fallbackPath := filepath.Join(DataDir, "ssl", "selfsigned.crt")
		if certData, err = os.ReadFile(fallbackPath); err == nil {
			block, _ := pem.Decode(certData)
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if cert.Issuer.String() == cert.Subject.String() {
						isSelfSigned = true
						certBase64 = base64.StdEncoding.EncodeToString(block.Bytes)
					}
				}
			}
		}
	}

	// Generate unique UUIDs
	genUUID := func(offset int64) string {
		now := time.Now().UnixNano() + offset
		return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
			now&0xFFFFFFFF, now>>32&0xFFFF,
			0x4000|(now>>48&0x0FFF), 0x8000|(now>>60&0x3FFF),
			now&0xFFFFFFFFFFFF)
	}

	dohUUID := genUUID(0)
	profileUUID := genUUID(1)
	certPayloadUUID := genUUID(2)

	certPayloadXML := ""
	certReferenceXML := ""
	if isSelfSigned && certBase64 != "" {
		certPayloadXML = fmt.Sprintf(`
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ShieldDNS.crt</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>Trusts the ShieldDNS self-signed root certificate.</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS Root Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.rootcert</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>`, certBase64, certPayloadUUID)

		certReferenceXML = fmt.Sprintf("\n\t\t\t<key>PayloadCertificateUUID</key>\n\t\t\t<string>%s</string>", certPayloadUUID)
	}

	// NOTE: iOS Configuration Profiles only support DNSProtocol values "TLS" and "HTTPS".
	// QUIC is NOT part of Apple's MDM specification and causes "internal error" on install.
	// DoQ is supported natively via third-party apps (DNSecure, AdGuard) but not via profiles.

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=shielddns_%s.mobileconfig", escapeXML(host)))

	mobileConfig := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://%[1]s/dns-query</string>%[2]s
			</dict>
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
				</dict>
			</array>
			<key>PayloadDescription</key>
			<string>Encrypted DNS-over-HTTPS (DoH) for ShieldDNS (%[1]s).</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS DoH (%[1]s)</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.doh.%[1]s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%[3]s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>%[5]s
		</dict>%[4]s
	</array>
	<key>PayloadDescription</key>
	<string>ShieldDNS Encryption Profile (%[1]s). Enables system-wide DNS encryption for improved privacy.</string>
	<key>PayloadDisplayName</key>
	<string>ShieldDNS Protection (%[1]s)</string>
	<key>PayloadIdentifier</key>
	<string>com.shielddns.profile.%[1]s</string>
	<key>PayloadOrganization</key>
	<string>ShieldDNS Project</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%[6]s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>SECURITY &amp; PRIVACY NOTICE:
This profile configures your device to use ShieldDNS (%[1]s) as its encrypted DNS provider.

WHAT THIS MEANS:
ShieldDNS will encrypt all DNS queries from this device, preventing ISPs and third parties from monitoring your web activity. It also leverages advanced blocklists to protect you from advertisements, trackers, and malicious content in real-time.

TECHNICAL DETAILS:
- Target Server: %[1]s
- Supported Protocol: DNS-over-HTTPS (DoH)
- Documentation: https://github.com/FaserF/ShieldDNS

By proceeding, you consent to all DNS traffic being routed through this server. No personal web traffic (HTTP/HTTPS content) is decrypted; only the destination addresses are processed for filtering. You can remove this profile at any time in Settings &gt; General &gt; VPN &amp; Device Management.</string>
	</dict>
</dict>
</plist>`, escapeXML(host), serverAddrsXML, dohUUID, certPayloadXML, certReferenceXML, profileUUID)

	finalContent := []byte(mobileConfig)
	if signEnabled {
		// Get cert and key files
		certFile := os.Getenv("CERT_FILE")
		if certFile == "" {
			certFile = "/ssl/fullchain.pem"
		}
		keyFile := os.Getenv("KEY_FILE")
		if keyFile == "" {
			keyFile = "/ssl/privkey.pem"
		}

		if _, err := os.Stat(certFile); err == nil {
			signed, signErr := signProfile(finalContent, certFile, keyFile)
			if signErr == nil {
				finalContent = signed
			} else {
				slog.Error("Failed to sign mobileconfig profile", "error", signErr)
				// Fallback to unsigned content (which we already have in finalContent)
			}
		}
	}

	w.Write(finalContent)
}

func signProfile(content []byte, certFile, keyFile string) ([]byte, error) {
	// openssl smime -sign -signer cert.pem -inkey key.pem -certfile chain.pem -nodetach -outform der
	// Note: certFile (fullchain.pem) usually contains both the entity cert and the chain.
	cmd := exec.Command("openssl", "smime", "-sign",
		"-signer", certFile,
		"-inkey", keyFile,
		"-certfile", certFile,
		"-nodetach",
		"-outform", "der")

	cmd.Stdin = bytes.NewReader(content)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl error: %v, stderr: %s", err, stderr.String())
	}

	return out.Bytes(), nil
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

var detectedServerCountry string

func detectServerCountry() {
	// Periodic check to handle network readiness and dynamic IPs
	for {
		// Try multiple services for reliability
		endpoints := []string{
			"https://ip-api.com/json/",
			"http://ip-api.com/json/",
			"https://ipwho.is/",
			"https://freeipapi.com/api/json",
		}

		success := false
		for _, url := range endpoints {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
			req.Header.Set("User-Agent", "ShieldDNS-Admin/v1.14")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				cancel()
				continue
			}

			if strings.Contains(url, "ip-api.com") {
				var data struct {
					CountryCode string `json:"countryCode"`
					Status      string `json:"status"`
					Message     string `json:"message"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
					if data.Status == "success" {
						detectedServerCountry = data.CountryCode
						success = true
					} else {
						slog.Debug("ip-api.com failed", "msg", data.Message)
					}
				}
			} else if strings.Contains(url, "ipwho.is") {
				var data struct {
					CountryCode string `json:"country_code"`
					Success     bool   `json:"success"`
					Message     string `json:"message"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
					if data.Success {
						detectedServerCountry = data.CountryCode
						success = true
					} else {
						slog.Debug("ipwho.is failed", "msg", data.Message)
					}
				}
			} else if strings.Contains(url, "freeipapi.com") {
				var data struct {
					CountryCode string `json:"countryCode"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.CountryCode != "" {
					detectedServerCountry = data.CountryCode
					success = true
				}
			} else if strings.Contains(url, "freeipapi.com") {
				var data struct {
					CountryCode string `json:"countryCode"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.CountryCode != "" {
					detectedServerCountry = data.CountryCode
					success = true
				}
			}
			resp.Body.Close()
			cancel()

			if success {
				slog.Info("Server country detected", "country", detectedServerCountry, "source", url)
				break
			}
		}

		if success {
			// Refresh every 6 hours if successful
			time.Sleep(6 * time.Hour)
		} else {
			slog.Debug("Failed to detect server country. Retrying in 1 minute...")
			time.Sleep(1 * time.Minute)
		}
	}
}

func handleHighRiskCountries(w http.ResponseWriter, r *http.Request) {
	// Curated list based on 2026 threat intelligence (high volume of botnets, malware distribution, and state-sponsored activity)
	highRisk := []string{"CN", "RU", "IR", "KP", "VN", "BR", "BY"}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(highRisk)
}

func handleServerCountry(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	manual := config.ServerCountry
	configLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"detected": detectedServerCountry,
		"manual":   manual,
	})
}
