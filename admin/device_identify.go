package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// DeviceSignature defines deterministic fingerprinting signals for a hardware/software class.
type DeviceSignature struct {
	ID            string
	Product       string
	Class         string
	Icon          string
	NameKeywords  []string
	DomainWeights map[string]float64
	SuggestedGrp  string
}

// DeviceIdentity holds the inferred identity, confidence, and evidence for a client IP.
type DeviceIdentity struct {
	ClientIP       string   `json:"client_ip"`
	Alias          string   `json:"alias,omitempty"`
	Product        string   `json:"product"`
	Class          string   `json:"class"`
	Icon           string   `json:"icon"`
	Confidence     string   `json:"confidence"` // "certain", "likely", "possibly", "unknown"
	Score          float64  `json:"score"`
	Evidence       []string `json:"evidence"`
	SuggestedGroup string   `json:"suggested_group,omitempty"`
}

var BuiltInDeviceSignatures = []DeviceSignature{
	{
		ID: "apple-tv", Product: "Apple TV", Class: "streaming", Icon: "fas fa-tv", SuggestedGrp: "Streaming",
		NameKeywords:  []string{"appletv", "apple-tv", "apple tv"},
		DomainWeights: map[string]float64{"apple.com": 0.35, "icloud.com": 0.25, "mzstatic.com": 0.25, "itunes.apple.com": 0.15},
	},
	{
		ID: "apple-iphone", Product: "iPhone / iPad", Class: "phone", Icon: "fas fa-mobile-alt", SuggestedGrp: "Personal Devices",
		NameKeywords:  []string{"iphone", "ipad", "ios"},
		DomainWeights: map[string]float64{"apple.com": 0.35, "icloud.com": 0.35, "mzstatic.com": 0.2, "push.apple.com": 0.1},
	},
	{
		ID: "apple-mac", Product: "Mac", Class: "laptop", Icon: "fas fa-laptop", SuggestedGrp: "Workstations",
		NameKeywords:  []string{"macbook", "imac", "mac-mini", "macintosh", "macos"},
		DomainWeights: map[string]float64{"apple.com": 0.35, "icloud.com": 0.35, "swscan.apple.com": 0.3},
	},
	{
		ID: "google-chromecast", Product: "Chromecast / Google TV", Class: "streaming", Icon: "fas fa-tv", SuggestedGrp: "Streaming",
		NameKeywords:  []string{"chromecast", "google-tv", "crkey"},
		DomainWeights: map[string]float64{"googlevideo.com": 0.4, "gstatic.com": 0.3, "googleapis.com": 0.3},
	},
	{
		ID: "google-nest", Product: "Google Nest / Home", Class: "speaker", Icon: "fas fa-volume-up", SuggestedGrp: "Smart Home",
		NameKeywords:  []string{"nest-hub", "nest-mini", "google-home", "nest-audio"},
		DomainWeights: map[string]float64{"nest.com": 0.4, "gstatic.com": 0.3, "googleapis.com": 0.3},
	},
	{
		ID: "android-phone", Product: "Android Device", Class: "phone", Icon: "fas fa-mobile-alt", SuggestedGrp: "Personal Devices",
		NameKeywords:  []string{"android", "pixel", "galaxy", "oneplus", "sm-"},
		DomainWeights: map[string]float64{"android.com": 0.4, "gstatic.com": 0.2, "googleapis.com": 0.2, "3gppnetwork.org": 0.2},
	},
	{
		ID: "amazon-echo", Product: "Amazon Echo", Class: "speaker", Icon: "fas fa-volume-up", SuggestedGrp: "Smart Home",
		NameKeywords:  []string{"echo", "alexa", "amazon-"},
		DomainWeights: map[string]float64{"amazonalexa.com": 0.6, "amazon.com": 0.2, "a2z.com": 0.2},
	},
	{
		ID: "amazon-fire-tv", Product: "Amazon Fire TV", Class: "streaming", Icon: "fas fa-tv", SuggestedGrp: "Streaming",
		NameKeywords:  []string{"firetv", "fire-tv", "aft"},
		DomainWeights: map[string]float64{"primevideo.com": 0.4, "amazonvideo.com": 0.3, "amazon.com": 0.2, "media-amazon.com": 0.1},
	},
	{
		ID: "roku-player", Product: "Roku Player", Class: "streaming", Icon: "fas fa-tv", SuggestedGrp: "Streaming",
		NameKeywords:  []string{"roku", "rokios"},
		DomainWeights: map[string]float64{"roku.com": 0.55, "rokutime.com": 0.25, "ravm.tv": 0.2},
	},
	{
		ID: "samsung-tv", Product: "Samsung Smart TV", Class: "tv", Icon: "fas fa-tv", SuggestedGrp: "Smart TVs",
		NameKeywords:  []string{"tizen", "samsungtv", "samsung-tv"},
		DomainWeights: map[string]float64{"samsungcloudsolution.com": 0.45, "samsungotn.net": 0.35, "samsungcloud.tv": 0.2},
	},
	{
		ID: "lg-tv", Product: "LG webOS Smart TV", Class: "tv", Icon: "fas fa-tv", SuggestedGrp: "Smart TVs",
		NameKeywords:  []string{"webos", "lgwebostv", "lg-tv"},
		DomainWeights: map[string]float64{"lgtvsdp.com": 0.55, "lgsmartad.com": 0.25, "lge.com": 0.2},
	},
	{
		ID: "sony-playstation", Product: "Sony PlayStation", Class: "console", Icon: "fas fa-gamepad", SuggestedGrp: "Gaming",
		NameKeywords:  []string{"ps4", "ps5", "playstation"},
		DomainWeights: map[string]float64{"playstation.net": 0.55, "playstation.com": 0.25, "sonyentertainmentnetwork.com": 0.2},
	},
	{
		ID: "nintendo-switch", Product: "Nintendo Switch", Class: "console", Icon: "fas fa-gamepad", SuggestedGrp: "Gaming",
		NameKeywords:  []string{"nintendo", "switch"},
		DomainWeights: map[string]float64{"nintendo.net": 0.7, "nintendo.com": 0.3},
	},
	{
		ID: "microsoft-xbox", Product: "Microsoft Xbox", Class: "console", Icon: "fas fa-gamepad", SuggestedGrp: "Gaming",
		NameKeywords:  []string{"xbox"},
		DomainWeights: map[string]float64{"xboxlive.com": 0.65, "xbox.com": 0.25, "xboxservices.com": 0.1},
	},
	{
		ID: "sonos-speaker", Product: "Sonos Speaker", Class: "speaker", Icon: "fas fa-volume-up", SuggestedGrp: "Smart Home",
		NameKeywords:  []string{"sonos"},
		DomainWeights: map[string]float64{"sonos.com": 1.0},
	},
	{
		ID: "philips-hue", Product: "Philips Hue Bridge", Class: "hub", Icon: "fas fa-lightbulb", SuggestedGrp: "IoT",
		NameKeywords:  []string{"philips-hue", "hue-bridge", "hue"},
		DomainWeights: map[string]float64{"meethue.com": 1.0},
	},
	{
		ID: "shelly-iot", Product: "Shelly / ESPHome IoT", Class: "iot", Icon: "fas fa-microchip", SuggestedGrp: "IoT",
		NameKeywords:  []string{"shelly", "esphome", "tasmota"},
		DomainWeights: map[string]float64{"shelly.cloud": 0.7, "esphome.io": 0.3},
	},
	{
		ID: "home-assistant", Product: "Home Assistant", Class: "hub", Icon: "fas fa-home", SuggestedGrp: "Smart Home",
		NameKeywords:  []string{"homeassistant", "home-assistant", "hass"},
		DomainWeights: map[string]float64{"home-assistant.io": 0.7, "nabucasa.com": 0.3},
	},
	{
		ID: "windows-pc", Product: "Windows PC", Class: "desktop", Icon: "fas fa-desktop", SuggestedGrp: "Workstations",
		NameKeywords:  []string{"desktop-", "laptop-", "windows"},
		DomainWeights: map[string]float64{"msftconnecttest.com": 0.4, "windowsupdate.com": 0.35, "microsoft.com": 0.25},
	},
}

// IdentifyDevice deterministically fingerprints a client IP from its domain traffic,
// user-agent / hostname signals, and alias, with optional Omniroute AI fallback.
func IdentifyDevice(clientIP string, askAI bool) DeviceIdentity {
	clientIP = strings.TrimSpace(clientIP)
	configLock.RLock()
	alias := ""
	if config.ClientAliases != nil {
		alias = config.ClientAliases[clientIP]
	}
	aiEnabled := config.AIEnabled
	configLock.RUnlock()

	ua := ""
	if v, ok := ipToUA.Load(clientIP); ok {
		ua, _ = v.(string)
	}

	topDomains := fetchClientRecentDomains(clientIP, 30)

	// Normalize textual hint signals (alias + UA)
	hintLower := strings.ToLower(alias + " " + ua)

	var bestSig *DeviceSignature
	bestScore := 0.0
	var bestEvidence []string

	for i := range BuiltInDeviceSignatures {
		sig := &BuiltInDeviceSignatures[i]
		var totalDomWeight float64
		var matchedDomWeight float64
		var ev []string

		for suffix, w := range sig.DomainWeights {
			totalDomWeight += w
			for _, dom := range topDomains {
				if dom == suffix || strings.HasSuffix(dom, "."+suffix) {
					matchedDomWeight += w
					ev = append(ev, fmt.Sprintf("queried %s", dom))
					break
				}
			}
		}

		domScore := 0.0
		if totalDomWeight > 0 {
			domScore = matchedDomWeight / totalDomWeight
		}

		nameScore := 0.0
		for _, kw := range sig.NameKeywords {
			if kw != "" && strings.Contains(hintLower, kw) {
				nameScore = 1.0
				ev = append(ev, fmt.Sprintf("matched label %q", kw))
				break
			}
		}

		// Weighted combination: domain traffic 70%, name/UA signal 30%.
		// When no hostname/UA signal is present (common for UDP/TCP DNS), strong exclusive domain matches (>= 0.65) stand on their own.
		score := 0.70*domScore + 0.30*nameScore
		if nameScore == 0 && domScore >= 0.65 {
			score = domScore
		} else if nameScore == 1.0 && len(topDomains) == 0 {
			score = 0.65
		}

		if score > bestScore {
			bestScore = score
			bestSig = sig
			bestEvidence = ev
		}
	}

	res := DeviceIdentity{
		ClientIP:   clientIP,
		Alias:      alias,
		Product:    "Unknown Device",
		Class:      "other",
		Icon:       "fas fa-network-wired",
		Confidence: "unknown",
		Score:      bestScore,
		Evidence:   []string{},
	}

	if bestSig != nil && bestScore >= 0.35 {
		res.Product = bestSig.Product
		res.Class = bestSig.Class
		res.Icon = bestSig.Icon
		res.SuggestedGroup = bestSig.SuggestedGrp
		res.Evidence = bestEvidence
		if bestScore >= 0.60 {
			res.Confidence = "likely"
		} else {
			res.Confidence = "possibly"
		}
		return res
	}

	// Fallback to existing UA heuristic if any
	if ua != "" {
		if dev := detectDevice(ua); dev != "" {
			res.Product = dev
			res.Confidence = "possibly"
			res.Score = 0.45
			res.Evidence = append(res.Evidence, "User-Agent heuristic")
			return res
		}
	}

	// Optional Omniroute AI classification when deterministic fingerprinting is uncertain
	if askAI && aiEnabled && len(topDomains) > 0 {
		if aiIdent := classifyDeviceWithAI(clientIP, alias, topDomains); aiIdent != nil {
			return *aiIdent
		}
	}

	return res
}

func fetchClientRecentDomains(clientIP string, limit int) []string {
	if db == nil || clientIP == "" {
		return nil
	}
	rows, err := dbQuery(`
		SELECT domain, COUNT(*) as c
		FROM queries
		WHERE client_ip = ?
		GROUP BY domain
		ORDER BY c DESC
		LIMIT ?
	`, clientIP, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var d string
		var cnt int64
		if err := rows.Scan(&d, &cnt); err == nil {
			if nd := NormalizeDomain(d); nd != "" {
				domains = append(domains, nd)
			}
		}
	}
	return domains
}

func classifyDeviceWithAI(clientIP, alias string, domains []string) *DeviceIdentity {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if len(domains) > 20 {
		domains = domains[:20]
	}

	messages := []OpenAIChatMessage{
		{
			Role: "system",
			Content: `You are a network device fingerprinting engine. Given a client's DNS domains, output STRICTLY JSON:
{"product":"short device name","class":"phone|tablet|laptop|desktop|tv|streaming|speaker|console|camera|iot|other","confidence":"likely|possibly","reason":"short reason"}`,
		},
		{
			Role:    "user",
			Content: fmt.Sprintf("Client IP: %s, Alias: %s, Top Domains: %s", clientIP, alias, strings.Join(domains, ", ")),
		},
	}

	out, err := CallOpenAIChatCompletion(ctx, messages)
	if err != nil {
		return nil
	}
	cleaned := strings.TrimSpace(out)
	cleaned = strings.TrimPrefix(cleaned, "```json")
	cleaned = strings.TrimPrefix(cleaned, "```")
	cleaned = strings.TrimSuffix(cleaned, "```")
	cleaned = strings.TrimSpace(cleaned)

	var parsed struct {
		Product    string `json:"product"`
		Class      string `json:"class"`
		Confidence string `json:"confidence"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(cleaned), &parsed); err != nil || parsed.Product == "" {
		return nil
	}
	conf := parsed.Confidence
	if conf != "likely" && conf != "possibly" {
		conf = "possibly"
	}
	return &DeviceIdentity{
		ClientIP:   clientIP,
		Alias:      alias,
		Product:    parsed.Product,
		Class:      parsed.Class,
		Icon:       iconForDeviceClass(parsed.Class),
		Confidence: conf,
		Score:      0.55,
		Evidence:   []string{"Omniroute AI: " + parsed.Reason},
	}
}

func iconForDeviceClass(class string) string {
	switch strings.ToLower(class) {
	case "phone":
		return "fas fa-mobile-alt"
	case "tablet":
		return "fas fa-tablet-alt"
	case "laptop":
		return "fas fa-laptop"
	case "desktop":
		return "fas fa-desktop"
	case "tv", "streaming":
		return "fas fa-tv"
	case "speaker":
		return "fas fa-volume-up"
	case "console":
		return "fas fa-gamepad"
	case "camera":
		return "fas fa-video"
	case "hub":
		return "fas fa-home"
	case "iot":
		return "fas fa-microchip"
	default:
		return "fas fa-network-wired"
	}
}

// handleClientIdentity handles GET /api/client/identity?ip=...&ask_ai=...
func handleClientIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		sendJSONError(w, "ip query parameter is required", http.StatusBadRequest)
		return
	}
	askAI := strings.EqualFold(r.URL.Query().Get("ask_ai"), "true") || r.URL.Query().Get("ask_ai") == "1"
	ident := IdentifyDevice(ip, askAI)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ident)
}

// handleAllClientIdentities handles GET /api/clients/identities
func handleAllClientIdentities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	seen := make(map[string]bool)
	if clients, err := getAllClients(); err == nil {
		for _, c := range clients {
			if ip, ok := c["ip"].(string); ok && ip != "" {
				seen[ip] = true
			}
		}
	}
	configLock.RLock()
	for ip := range config.ClientAliases {
		if ip != "" {
			seen[ip] = true
		}
	}
	configLock.RUnlock()

	ips := make([]string, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	identities := make([]DeviceIdentity, 0, len(ips))
	for _, ip := range ips {
		identities = append(identities, IdentifyDevice(ip, false))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"identities": identities,
	})
}
