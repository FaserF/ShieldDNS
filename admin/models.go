package main

import (
	"os/exec"
	"sync"
	"time"
)

const (
	StatusAllowed          = "Allowed"
	StatusBlocked          = "Blocked"
	StatusBlockedPolicy    = "Blocked (Policy)"
	StatusBlockedClient    = "Blocked (Client IP)"
	StatusBlockedMalicious = "Blocked (Threat Intelligence)"
)

type Config struct {
	Upstreams                  []string                     `json:"upstreams"`
	UpstreamDoT                []string                     `json:"upstream_dot"`
	PreferEncrypted            bool                         `json:"prefer_encrypted"`
	UseFastestUpstream         bool                         `json:"use_fastest_upstream"`
	RetentionDays              int                          `json:"retention_days"`
	Lists                      []List                       `json:"lists"`
	Allowlists                 []List                       `json:"allowlists"`
	CustomBlocked              []string                     `json:"custom_blocked"`
	CustomAllowed              []string                     `json:"custom_allowed"`
	CustomMappings             map[string]string            `json:"custom_mappings"`
	AutoblockWhitelist         []string                     `json:"autoblock_whitelist"`
	SetupDone                  bool                         `json:"setup_done"`
	AdminPasswordHashed        string                       `json:"admin_password_hashed"`
	APIKeys                    []APIKey                     `json:"api_keys"`
	FilteringEnabled           bool                         `json:"filtering_enabled"`
	AdminDomain                string                       `json:"admin_domain"`  // e.g. dns.fabiseitz.de
	BlockPageIP                string                       `json:"block_page_ip"` // IP of the ShieldDNS server
	LatencyTestInterval        int                          `json:"latency_test_interval"`
	SmartSelectionPolicy       string                       `json:"smart_selection_policy"` // "fastest" or "random"
	DiagnosticsRefreshInterval int                          `json:"diagnostics_refresh_interval"`
	ServeStale                 bool                         `json:"serve_stale"`
	DNSSECEnabled              bool                         `json:"dnssec_enabled"`
	BlockedCountries           []string                     `json:"blocked_countries"`
	BlockedClients             []string                     `json:"blocked_clients"`
	BlockedClientsInfo         map[string]BlockedClientInfo `json:"blocked_clients_info"`
	AbuseDetectionEnabled      bool                         `json:"abuse_detection_enabled"`
	AbuseDGAThreshold          float64                      `json:"abuse_dga_threshold"`
	AbuseDGAMinLen             int                          `json:"abuse_dga_min_len"`
	ClientAliases              map[string]string            `json:"client_aliases"`
	MaliciousIPBlockingEnabled bool                         `json:"malicious_ip_blocking_enabled"`
	MaliciousIPInterval        int                          `json:"malicious_ip_interval"`
	SignMobileConfig           bool                         `json:"sign_mobileconfig"`
	VerifyUpstreamTLS          bool                         `json:"verify_upstream_tls"`
	DoHRateLimit               int                          `json:"doh_rate_limit"`
	DebugMode                  bool                         `json:"debug_mode"`
	ServerCountry              string                       `json:"server_country"`
	LastLogin                  time.Time                    `json:"last_login"`
	PreviousLogin              time.Time                    `json:"previous_login"`
}

type BlockedClientInfo struct {
	Reason      string    `json:"reason"`
	BlockedAt   time.Time `json:"blocked_at"`
	Auto        bool      `json:"auto"`
	CountryCode string    `json:"country_code"`
}

type APIKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	TokenHash   string    `json:"token_hash"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
}

type List struct {
	Name            string    `json:"name"`
	URL             string    `json:"url"`
	Enabled         bool      `json:"enabled"`
	Category        string    `json:"category,omitempty"`
	IsRecommended   bool      `json:"is_recommended"`
	Entries         int       `json:"entries"`
	UpdatedAt       time.Time `json:"updated_at"`
	RemoteUpdatedAt time.Time `json:"remote_updated_at"`
}

type Stats struct {
	TotalQueries         int64            `json:"total_queries"`
	BlockedQueries       int64            `json:"blocked_queries"`
	CacheHits            int64            `json:"cache_hits"`
	AverageLatency       float64          `json:"average_latency"` // in milliseconds
	UniqueClients        int              `json:"unique_clients"`
	QueryTypes           map[string]int64 `json:"query_types"`
	Version              string           `json:"version"`
	LatestVersion        string           `json:"latest_version,omitempty"`
	CoreDNSVersion       string           `json:"coredns_version"`
	LatestCoreDNSVersion string           `json:"latest_coredns_version,omitempty"`
	AlpineVersion        string           `json:"alpine_version"`
	LatestAlpineVersion  string           `json:"latest_alpine_version,omitempty"`
	// Enhanced Stats
	UptimeSeconds  int64            `json:"uptime_seconds"`
	DBSizeMB       float64          `json:"db_size_mb"`
	RAMUsedMB      float64          `json:"ram_used_mb"`
	RAMTotalMB     float64          `json:"ram_total_mb"`
	CPUUsage       float64          `json:"cpu_usage"`
	NumAutoBlocked int              `json:"num_auto_blocked"`
	ActiveQPS      float64          `json:"active_qps"`
	BlockedDomains int64            `json:"blocked_domains"`
	CoreDNSAlive   bool             `json:"coredns_alive"`
	TopCountries   map[string]int64 `json:"top_countries"`

	// Internal Cache Metadata
	LastUpdate time.Time `json:"-"`
}

type Query struct {
	ID          int64     `json:"id,omitempty"`
	Time        time.Time `json:"time"`
	Domain      string    `json:"domain"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	ClientIP    string    `json:"client_ip"`
	ClientAlias string    `json:"client_alias,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
	IsCacheHit  bool      `json:"is_cache_hit"`
	DurationMs  float64   `json:"duration_ms"`
	CountryCode string    `json:"country_code"`
}

type HourStats struct {
	Time    time.Time `json:"time"`
	Total   int64     `json:"total"`
	Blocked int64     `json:"blocked"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type ClientStats struct {
	Total      int64            `json:"total"`
	Blocked    int64            `json:"blocked"`
	QueryTypes map[string]int64 `json:"query_types"`
	Timeline   []HourStats      `json:"timeline"` // 24 entries
}

type DomainStats struct {
	Total        int64   `json:"total"`
	Blocked      int64   `json:"blocked"`
	ClientsCount int     `json:"clients_count"`
	History      []Query `json:"history"`
}

type ClientCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

var (
	config     Config
	configLock sync.RWMutex
	stats      Stats
	statsLock  sync.RWMutex
	dnsCmd     *exec.Cmd

	sessionStore sync.Map // token -> Session
	sessionLock  sync.RWMutex

	// Health monitoring
	healthyUpstreams []string
	healthyDoT       []string
	healthLock       sync.RWMutex

	// Log Buffering
	logBuffer  []Query
	bufferLock sync.Mutex

	// Login Throttling
	loginFailures = make(map[string]int)
	failureLock   sync.Mutex

	// SSE Logging
	sseClients = make(map[chan Query]struct{})
	sseLock    sync.Mutex

	// Latency Tracking
	latencyMap  = make(map[string]time.Duration)
	latencyLock sync.RWMutex

	// Blocklist & Allowlist Attribution
	blockAttribution     = make(map[string][]string)
	blockAttributionLock sync.RWMutex
	allowAttribution     = make(map[string][]string)
	allowAttributionLock sync.RWMutex

	// Client info caches
	ipToUA       sync.Map // IP -> User-Agent string
	lastUAUpdate sync.Map // IP -> time.Time of last DB persist
)

type Session struct {
	Token     string    `json:"token"`
	RemoteIP  string    `json:"remote_ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

var (
	DataDir           = "/data"
	ConfigPath        = "/data/config.json"
	BlocklistPath     = "/data/blocklist.hosts"
	AllowlistPath     = "/data/allowlist.hosts"
	MappingsPath      = "/data/mappings.hosts"
	CorefilePath      = "/data/Corefile"
	DBPath            = "/data/queries.db"
	CombinedHostsPath = "/data/shielddns.hosts"
)

const CookieName = "shielddns_session"

func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	newCfg := *c

	// Deep copy List slices
	if c.Lists != nil {
		newCfg.Lists = make([]List, len(c.Lists))
		copy(newCfg.Lists, c.Lists)
	}
	if c.Allowlists != nil {
		newCfg.Allowlists = make([]List, len(c.Allowlists))
		copy(newCfg.Allowlists, c.Allowlists)
	}

	// Deep copy string slices
	if c.CustomBlocked != nil {
		newCfg.CustomBlocked = make([]string, len(c.CustomBlocked))
		copy(newCfg.CustomBlocked, c.CustomBlocked)
	}
	if c.CustomAllowed != nil {
		newCfg.CustomAllowed = make([]string, len(c.CustomAllowed))
		copy(newCfg.CustomAllowed, c.CustomAllowed)
	}
	if c.Upstreams != nil {
		newCfg.Upstreams = make([]string, len(c.Upstreams))
		copy(newCfg.Upstreams, c.Upstreams)
	}
	if c.UpstreamDoT != nil {
		newCfg.UpstreamDoT = make([]string, len(c.UpstreamDoT))
		copy(newCfg.UpstreamDoT, c.UpstreamDoT)
	}
	if c.BlockedCountries != nil {
		newCfg.BlockedCountries = make([]string, len(c.BlockedCountries))
		copy(newCfg.BlockedCountries, c.BlockedCountries)
	}
	if c.BlockedClients != nil {
		newCfg.BlockedClients = make([]string, len(c.BlockedClients))
		copy(newCfg.BlockedClients, c.BlockedClients)
	}

	// Deep copy maps
	if c.CustomMappings != nil {
		newCfg.CustomMappings = make(map[string]string)
		for k, v := range c.CustomMappings {
			newCfg.CustomMappings[k] = v
		}
	}
	if c.BlockedClientsInfo != nil {
		newCfg.BlockedClientsInfo = make(map[string]BlockedClientInfo)
		for k, v := range c.BlockedClientsInfo {
			newCfg.BlockedClientsInfo[k] = v
		}
	}
	if c.ClientAliases != nil {
		newCfg.ClientAliases = make(map[string]string)
		for k, v := range c.ClientAliases {
			newCfg.ClientAliases[k] = v
		}
	}

	// Deep copy APIKeys
	if c.APIKeys != nil {
		newCfg.APIKeys = make([]APIKey, len(c.APIKeys))
		for i, k := range c.APIKeys {
			newCfg.APIKeys[i] = k
			if k.Permissions != nil {
				newCfg.APIKeys[i].Permissions = make([]string, len(k.Permissions))
				copy(newCfg.APIKeys[i].Permissions, k.Permissions)
			}
		}
	}

	return &newCfg
}
