package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ServicePreset represents a toggleable blocked service bundle (social, gaming, video, messaging, etc.).
type ServicePreset struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Icon     string   `json:"icon"`
	Domains  []string `json:"domains"`
}

// SafeSearchEngine defines a search/video engine with SafeSearch VIP enforcement.
type SafeSearchEngine struct {
	ID         string
	Name       string
	TargetHost string
	FallbackIP string
	Domains    []string
}

var DefaultServicePresets = []ServicePreset{
	// Social
	{ID: "tiktok", Name: "TikTok", Category: "social", Icon: "fab fa-tiktok", Domains: []string{"tiktok.com", "tiktokv.com", "tiktokv.us", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokw.us", "ttwstatic.com", "musical.ly", "byteoversea.com", "ibytedtos.com", "ibyteimg.com"}},
	{ID: "facebook", Name: "Facebook", Category: "social", Icon: "fab fa-facebook", Domains: []string{"facebook.com", "facebook.net", "fb.com", "fb.me", "fbcdn.net", "fbsbx.com", "messenger.com"}},
	{ID: "instagram", Name: "Instagram", Category: "social", Icon: "fab fa-instagram", Domains: []string{"instagram.com", "cdninstagram.com", "ig.me", "instagr.am"}},
	{ID: "snapchat", Name: "Snapchat", Category: "social", Icon: "fab fa-snapchat", Domains: []string{"snapchat.com", "snap.com", "snapkit.com", "snapads.com", "sc-cdn.net", "sc-static.net"}},
	{ID: "twitter", Name: "X (Twitter)", Category: "social", Icon: "fab fa-x-twitter", Domains: []string{"twitter.com", "x.com", "twimg.com", "t.co", "twttr.com"}},
	{ID: "reddit", Name: "Reddit", Category: "social", Icon: "fab fa-reddit", Domains: []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"}},
	{ID: "pinterest", Name: "Pinterest", Category: "social", Icon: "fab fa-pinterest", Domains: []string{"pinterest.com", "pinimg.com", "pin.it"}},
	{ID: "linkedin", Name: "LinkedIn", Category: "social", Icon: "fab fa-linkedin", Domains: []string{"linkedin.com", "licdn.com", "lnkd.in"}},
	{ID: "tumblr", Name: "Tumblr", Category: "social", Icon: "fab fa-tumblr", Domains: []string{"tumblr.com"}},
	{ID: "tinder", Name: "Tinder", Category: "dating", Icon: "fas fa-fire", Domains: []string{"tinder.com", "gotinder.com"}},

	// Gaming
	{ID: "roblox", Name: "Roblox", Category: "gaming", Icon: "fas fa-cubes", Domains: []string{"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"}},
	{ID: "fortnite", Name: "Fortnite & Epic Games", Category: "gaming", Icon: "fas fa-gamepad", Domains: []string{"fortnite.com", "epicgames.com", "epicgames.dev", "unrealengine.com"}},
	{ID: "minecraft", Name: "Minecraft", Category: "gaming", Icon: "fas fa-cube", Domains: []string{"minecraft.net", "mojang.com", "minecraftservices.com"}},
	{ID: "steam", Name: "Steam", Category: "gaming", Icon: "fab fa-steam", Domains: []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com", "valvesoftware.com"}},
	{ID: "xbox", Name: "Xbox Live", Category: "gaming", Icon: "fab fa-xbox", Domains: []string{"xboxlive.com", "xbox.com", "xboxab.com", "xboxservices.com"}},
	{ID: "playstation", Name: "PlayStation Network", Category: "gaming", Icon: "fab fa-playstation", Domains: []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com"}},
	{ID: "discord", Name: "Discord", Category: "gaming", Icon: "fab fa-discord", Domains: []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"}},

	// Video & Music
	{ID: "youtube", Name: "YouTube", Category: "video", Icon: "fab fa-youtube", Domains: []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtube-nocookie.com", "youtubei.googleapis.com", "youtubekids.com"}},
	{ID: "netflix", Name: "Netflix", Category: "video", Icon: "fas fa-film", Domains: []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net"}},
	{ID: "twitch", Name: "Twitch", Category: "video", Icon: "fab fa-twitch", Domains: []string{"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "ext-twitch.tv"}},
	{ID: "disneyplus", Name: "Disney+", Category: "video", Icon: "fas fa-tv", Domains: []string{"disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com", "disneystreaming.com"}},
	{ID: "primevideo", Name: "Prime Video", Category: "video", Icon: "fab fa-amazon", Domains: []string{"primevideo.com", "aiv-cdn.net", "aiv-delivery.net", "amazonvideo.com"}},
	{ID: "hulu", Name: "Hulu", Category: "video", Icon: "fas fa-play-circle", Domains: []string{"hulu.com", "hulustream.com", "huluim.com"}},
	{ID: "spotify", Name: "Spotify", Category: "music", Icon: "fab fa-spotify", Domains: []string{"spotify.com", "scdn.co", "spotifycdn.com", "spoti.fi"}},

	// Messaging & AI
	{ID: "whatsapp", Name: "WhatsApp", Category: "messaging", Icon: "fab fa-whatsapp", Domains: []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{ID: "telegram", Name: "Telegram", Category: "messaging", Icon: "fab fa-telegram", Domains: []string{"telegram.org", "telegram.me", "t.me", "telesco.pe"}},
	{ID: "signal", Name: "Signal", Category: "messaging", Icon: "fas fa-comment-dots", Domains: []string{"signal.org", "whispersystems.org"}},
	{ID: "chatgpt", Name: "ChatGPT / OpenAI", Category: "ai", Icon: "fas fa-robot", Domains: []string{"chatgpt.com", "openai.com", "oaiusercontent.com", "oaistatic.com"}},
}

var safeSearchEngines = []SafeSearchEngine{
	{
		ID:         "google",
		Name:       "Google Search",
		TargetHost: "forcesafesearch.google.com",
		FallbackIP: "216.239.38.120",
		Domains: []string{
			"google.com", "www.google.com",
			"google.de", "www.google.de",
			"google.co.uk", "www.google.co.uk",
			"google.fr", "www.google.fr",
			"google.es", "www.google.es",
			"google.it", "www.google.it",
			"google.nl", "www.google.nl",
			"google.at", "www.google.at",
			"google.ch", "www.google.ch",
			"google.ca", "www.google.ca",
			"google.com.au", "www.google.com.au",
			"google.pl", "www.google.pl",
		},
	},
	{
		ID:         "bing",
		Name:       "Bing",
		TargetHost: "strict.bing.com",
		FallbackIP: "204.79.197.220",
		Domains:    []string{"bing.com", "www.bing.com"},
	},
	{
		ID:         "duckduckgo",
		Name:       "DuckDuckGo",
		TargetHost: "safe.duckduckgo.com",
		FallbackIP: "52.142.124.215",
		Domains:    []string{"duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com"},
	},
	{
		ID:         "yandex",
		Name:       "Yandex",
		TargetHost: "familysearch.yandex.ru",
		FallbackIP: "213.180.193.250",
		Domains:    []string{"yandex.ru", "www.yandex.ru", "yandex.com", "www.yandex.com"},
	},
	{
		ID:         "pixabay",
		Name:       "Pixabay",
		TargetHost: "safesearch.pixabay.com",
		FallbackIP: "104.18.40.123",
		Domains:    []string{"pixabay.com", "www.pixabay.com"},
	},
}

var youtubeSafeSearchDomains = []string{
	"www.youtube.com",
	"m.youtube.com",
	"youtubei.googleapis.com",
	"youtube.googleapis.com",
	"www.youtube-nocookie.com",
}

// GetServicePresetByID looks up a service preset case-insensitively.
func GetServicePresetByID(id string) (ServicePreset, bool) {
	norm := strings.ToLower(strings.TrimSpace(id))
	for _, svc := range DefaultServicePresets {
		if svc.ID == norm {
			return svc, true
		}
	}
	return ServicePreset{}, false
}

// GetBlockedServiceDomains returns a map of domain (and *.domain) -> attribution string
// for all enabled BlockedServices in cfg.
func GetBlockedServiceDomains(cfg *Config) map[string]string {
	out := make(map[string]string)
	if cfg == nil || len(cfg.BlockedServices) == 0 {
		return out
	}
	for _, id := range cfg.BlockedServices {
		svc, ok := GetServicePresetByID(id)
		if !ok {
			continue
		}
		attr := "Blocked Service: " + svc.Name
		for _, d := range svc.Domains {
			norm := NormalizeDomain(d)
			if norm == "" {
				continue
			}
			out[norm] = attr
			out["*."+norm] = attr
		}
	}
	return out
}

// GetSafeSearchMappings returns exact domain -> VIP IP mappings for CoreDNS hosts enforcement.
func GetSafeSearchMappings(cfg *Config) map[string]string {
	out := make(map[string]string)
	if cfg == nil {
		return out
	}
	if cfg.SafeSearchEnabled {
		for _, eng := range safeSearchEngines {
			for _, d := range eng.Domains {
				out[d] = eng.FallbackIP
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.YouTubeRestriction)) {
	case "strict":
		for _, d := range youtubeSafeSearchDomains {
			out[d] = "216.239.38.120"
		}
	case "moderate":
		for _, d := range youtubeSafeSearchDomains {
			out[d] = "216.239.38.119"
		}
	}
	return out
}

// GetSafeSearchMatch checks whether a domain is enforced by SafeSearch or YouTube Restricted Mode.
func GetSafeSearchMatch(domain string, cfg *Config) (targetHost string, vip string, engineName string, ok bool) {
	if cfg == nil {
		return "", "", "", false
	}
	norm := NormalizeDomain(domain)
	if norm == "" {
		return "", "", "", false
	}
	if cfg.SafeSearchEnabled {
		for _, eng := range safeSearchEngines {
			for _, d := range eng.Domains {
				if d == norm {
					return eng.TargetHost, eng.FallbackIP, eng.Name, true
				}
			}
		}
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.YouTubeRestriction))
	if mode == "strict" || mode == "moderate" {
		for _, d := range youtubeSafeSearchDomains {
			if d == norm {
				if mode == "strict" {
					return "restrict.youtube.com", "216.239.38.120", "YouTube (Strict)", true
				}
				return "restrictmoderate.youtube.com", "216.239.38.119", "YouTube (Moderate)", true
			}
		}
	}
	return "", "", "", false
}

// handleServicesCatalog returns the available service presets and active parental control settings.
func handleServicesCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	blocked := append([]string{}, config.BlockedServices...)
	safeSearch := config.SafeSearchEnabled
	ytMode := config.YouTubeRestriction
	configLock.RUnlock()

	if ytMode == "" {
		ytMode = "none"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"presets":             DefaultServicePresets,
		"blocked_services":    blocked,
		"safesearch_enabled":  safeSearch,
		"youtube_restriction": ytMode,
	})
}

// handleServicesUpdate updates BlockedServices, SafeSearchEnabled, and YouTubeRestriction.
func handleServicesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		BlockedServices    []string `json:"blocked_services"`
		SafeSearchEnabled  *bool    `json:"safesearch_enabled"`
		YouTubeRestriction *string  `json:"youtube_restriction"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	configLock.Lock()
	if config.ClusterRole == "replica" {
		configLock.Unlock()
		sendJSONError(w, "Services and SafeSearch are centrally managed by Cluster Primary.", http.StatusForbidden)
		return
	}

	if req.BlockedServices != nil {
		var valid []string
		seen := make(map[string]bool)
		for _, id := range req.BlockedServices {
			norm := strings.ToLower(strings.TrimSpace(id))
			if _, ok := GetServicePresetByID(norm); ok && !seen[norm] {
				valid = append(valid, norm)
				seen[norm] = true
			}
		}
		if valid == nil {
			valid = []string{}
		}
		config.BlockedServices = valid
	}
	if req.SafeSearchEnabled != nil {
		config.SafeSearchEnabled = *req.SafeSearchEnabled
	}
	if req.YouTubeRestriction != nil {
		mode := strings.ToLower(strings.TrimSpace(*req.YouTubeRestriction))
		switch mode {
		case "none", "moderate", "strict":
			config.YouTubeRestriction = mode
		default:
			configLock.Unlock()
			sendJSONError(w, "Invalid youtube_restriction: must be none, moderate, or strict", http.StatusBadRequest)
			return
		}
	}

	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	cfgClone := config.Clone()
	configLock.Unlock()

	reloadRulesFastNoLock(cfgClone)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":             true,
		"blocked_services":    cfgClone.BlockedServices,
		"safesearch_enabled":  cfgClone.SafeSearchEnabled,
		"youtube_restriction": cfgClone.YouTubeRestriction,
	})
}
