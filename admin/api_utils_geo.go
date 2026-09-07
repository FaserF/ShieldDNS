package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)




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

var geoIPResolver = resolveGeoIP

// fetchGeoIP fetches full GeoIP data for an IP and stores it in geoCache and ipInfoCache.
// It is the single source of truth for all GeoIP lookups.
// After a successful lookup it also upgrades BlockedClientsInfo so all UI views are consistent.
func fetchGeoIP(ctx context.Context, ip string) {
	resolved, err := geoIPResolver(ctx, ip)
	if err != nil {
		return
	}

	// Update geoCache (used by GetCountryCodeCached and handleIPInfo)
	geoCache.Store(ip, resolved)

	// Also update ipInfoCache so the IP detail view is immediately correct
	if existing, ok := ipInfoCache.Load(ip); ok {
		prev := existing.(IPInfo)
		// Merge: only overwrite geo fields, keep hostname/alias/mac etc.
		if prev.Country == "" || prev.Country == "-" {
			prev.Country = resolved.Country
		}
		if prev.CountryCode == "" || prev.CountryCode == "-" {
			prev.CountryCode = resolved.CountryCode
		}
		if prev.City == "" || prev.City == "-" {
			prev.City = resolved.City
		}
		if prev.ISP == "" || prev.ISP == "-" {
			prev.ISP = resolved.ISP
		}
		prev.Org = resolved.Org
		prev.AS = resolved.AS
		prev.ExpiresAt = resolved.ExpiresAt
		ipInfoCache.Store(ip, prev)
	} else {
		ipInfoCache.Store(ip, resolved)
	}

	// Upgrade BlockedClientsInfo so all views (Currently Blocked Clients) see the country
	configLock.Lock()
	if config.BlockedClientsInfo != nil {
		if entry, ok := config.BlockedClientsInfo[ip]; ok && (entry.CountryCode == "" || entry.CountryCode == "-") {
			entry.CountryCode = resolved.CountryCode
			config.BlockedClientsInfo[ip] = entry
			if err := saveConfigNoLock(); err != nil {
				slog.Error("Failed to save config in fetchGeoIP (upgrade)", "error", err)
			}
		}
	}
	configLock.Unlock()
}

// resolveGeoIP is the internal robust lookup engine using multiple providers.
func resolveGeoIP(ctx context.Context, ip string) (IPInfo, error) {
	var geoData struct {
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
		Org         string `json:"org"`
		AS          string `json:"as"`
		Status      string `json:"status"`
	}

	providers := []struct {
		url    string
		parser func([]byte) error
	}{
		{
			url: "https://ip-api.com/json/" + ip + "?fields=status,country,countryCode,city,isp,org,as",
			parser: func(b []byte) error {
				return json.Unmarshal(b, &geoData)
			},
		},
		{
			url: "http://ip-api.com/json/" + ip + "?fields=status,country,countryCode,city,isp,org,as",
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
					return fmt.Errorf("ipwho.is failed")
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
		req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "ShieldDNS-Admin/v1.14")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err := p.parser(body); err == nil && geoData.Status == "success" && geoData.CountryCode != "" {
			return IPInfo{
				IP:          ip,
				Country:     geoData.Country,
				CountryCode: geoData.CountryCode,
				City:        geoData.City,
				ISP:         geoData.ISP,
				Org:         geoData.Org,
				AS:          geoData.AS,
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			}, nil
		}
	}

	return IPInfo{}, fmt.Errorf("all GeoIP providers failed for %s", ip)
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
		configLock.RLock()
		localPTRs := append([]string{}, config.LocalPTRUpstreams...)
		configLock.RUnlock()

		var names []string
		var err error

		if isPrivate && len(localPTRs) > 0 {
			// Query configured local PTR upstream (e.g. router 192.168.178.1)
			for _, ptrServer := range localPTRs {
				target := ptrServer
				if !strings.Contains(target, ":") {
					target = net.JoinHostPort(target, "53")
				}
				customResolver := &net.Resolver{
					PreferGo: true,
					Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
						d := net.Dialer{Timeout: 1500 * time.Millisecond}
						return d.DialContext(ctx, "udp", target)
					},
				}
				names, err = customResolver.LookupAddr(LookupCtx, ip)
				if err == nil && len(names) > 0 {
					break
				}
			}
		}

		if len(names) == 0 {
			resolver := &net.Resolver{}
			names, err = resolver.LookupAddr(LookupCtx, ip)
		}

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

			resolved, err := resolveGeoIP(geoCtx, ip)
			if err == nil {
				info.Country = resolved.Country
				info.CountryCode = resolved.CountryCode
				info.City = resolved.City
				info.ISP = resolved.ISP
				info.Org = resolved.Org
				info.AS = resolved.AS

				// Store in cache
				geoCache.Store(ip, info)

				// Also upgrade BlockedClientsInfo if this client is blocked
				configLock.Lock()
				if config.BlockedClientsInfo != nil {
					if entry, ok := config.BlockedClientsInfo[ip]; ok && (entry.CountryCode == "" || entry.CountryCode == "-") {
						entry.CountryCode = resolved.CountryCode
						config.BlockedClientsInfo[ip] = entry
						go func() {
							configLock.Lock()
							if err := saveConfigNoLock(); err != nil {
								slog.Error("Failed to save config in handleGeoBlock (add/remove)", "error", err)
							}
							configLock.Unlock()
						}()
					}
				}
				configLock.Unlock()
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
var detectedServerCountry string
var detectedServerIP string

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
					Query       string `json:"query"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
					if data.Status == "success" {
						detectedServerCountry = data.CountryCode
						detectedServerIP = data.Query
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
					IP          string `json:"ip"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
					if data.Success {
						detectedServerCountry = data.CountryCode
						detectedServerIP = data.IP
						success = true
					} else {
						slog.Debug("ipwho.is failed", "msg", data.Message)
					}
				}
			} else if strings.Contains(url, "freeipapi.com") {
				var data struct {
					CountryCode string `json:"countryCode"`
					IP          string `json:"ipAddress"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.CountryCode != "" {
					detectedServerCountry = data.CountryCode
					detectedServerIP = data.IP
					success = true
				}
			}

			resp.Body.Close()
			cancel()

			if success {
				slog.Info("Server info detected", "country", detectedServerCountry, "ip", detectedServerIP, "source", url)
				ensureServerIPWhitelisted(detectedServerIP)
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

func ensureServerIPWhitelisted(ip string) {
	if ip == "" {
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	found := false
	for _, w := range config.AutoblockWhitelist {
		if w == ip {
			found = true
			break
		}
	}

	if !found {
		slog.Info("Automatically adding server public IP to autoblock whitelist", "ip", ip)
		config.AutoblockWhitelist = append(config.AutoblockWhitelist, ip)
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in ensureServerIPWhitelisted", "error", err)
		}
	}
}
