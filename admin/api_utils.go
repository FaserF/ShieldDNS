package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$`)

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
	return domainRegex.MatchString(s)
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

// NormalizeDomain strips protocols, paths, fragments, and trailing dots to return a clean domain.
func NormalizeDomain(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	// Strip paths, queries, fragments
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(s, sep); idx != -1 {
			s = s[:idx]
		}
	}
	return strings.TrimSuffix(s, ".")
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
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") || ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "fd") || ip == "DoH Proxy" || ip == "localhost" {
		isPrivate = true
	}

	info := IPInfo{
		IP:        ip,
		IsPrivate: isPrivate,
	}

	// Handle special internal clients with hardcoded metadata
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

	// Reverse DNS (only if not already handled by special cases)
	if info.Hostname == "" {
		names, _ := net.LookupAddr(ip)
		if len(names) > 0 {
			info.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	// GeoIP for public IPs
	if !isPrivate {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		
		req, _ := http.NewRequestWithContext(ctx, "GET", "https://ip-api.com/json/"+ip, nil)
		client := &http.Client{}
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			var geoData struct {
				Country     string `json:"country"`
				CountryCode string `json:"countryCode"`
				City        string `json:"city"`
				ISP         string `json:"isp"`
				Org         string `json:"org"`
				AS          string `json:"as"`
				Status      string `json:"status"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&geoData); err == nil && geoData.Status == "success" {
				info.Country = geoData.Country
				info.CountryCode = geoData.CountryCode
				info.City = geoData.City
				info.ISP = geoData.ISP
				info.Org = geoData.Org
				info.AS = geoData.AS
			}
		} else {
			slog.Warn("GeoIP lookup failed", "ip", ip, "error", err)
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
		info.OS = detectOS(ua)

		// If it's a mobile/smart device, improve the manufacturer field
		if info.Manufacturer == "" || info.Manufacturer == "Unknown" {
			dev := detectDevice(ua)
			if dev != "" {
				info.Manufacturer = dev
			}
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
	}
	return ""
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
		"001F3B": "Nintendo",
		"C0EEFB": "OnePlus",
		"000FB5": "Netgear",
		"0014BF": "Linksys",
		"0018E7": "TP-Link", "F4F26D": "TP-Link",
		"24A160": "Espressif (IoT)", "30AEA4": "Espressif (IoT)", "A4CF12": "Espressif (IoT)",
		"BCDD26": "Shelly/Allterco", "C049EF": "Shelly/Allterco",
		"00032F": "Sonos", "B8E937": "Sonos",
		"00156D": "Ubiquiti", "0418D6": "Ubiquiti", "B4FBE4": "Ubiquiti", "7483C2": "Ubiquiti",
		"0004F2": "Polycom",
		"00E062": "Brother",
		"001788": "Philips Hue",
		"603197": "Netatmo",
	}

	if m, ok := ouis[prefix]; ok {
		return m
	}
	return "Unknown"
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

	// Build ServerAddresses XML block
	serverAddrsXML := ""
	if blockPageIP != "" && blockPageIP != "127.0.0.1" {
		serverAddrsXML = fmt.Sprintf(`
			<key>ServerAddresses</key>
			<array>
				<string>%s</string>
			</array>`, blockPageIP)
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
