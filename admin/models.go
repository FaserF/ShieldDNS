package main

import (
	"os/exec"
	"sync"
	"time"
)

type Config struct {
	Upstreams           []string `json:"upstreams"`
	UpstreamDoT         []string `json:"upstream_dot"`
	PreferEncrypted     bool     `json:"prefer_encrypted"`
	UseFastestUpstream  bool     `json:"use_fastest_upstream"`
	RetentionDays       int      `json:"retention_days"`
	Lists               []List   `json:"lists"`
	Allowlists          []List   `json:"allowlists"`
	CustomBlocked       []string `json:"custom_blocked"`
	CustomAllowed       []string `json:"custom_allowed"`
	CustomMappings      map[string]string `json:"custom_mappings"`
	SetupDone           bool     `json:"setup_done"`
	AdminPasswordHashed string   `json:"admin_password_hashed"`
	APIKeys             []APIKey `json:"api_keys"`
	FilteringEnabled    bool     `json:"filtering_enabled"`
	AdminDomain         string   `json:"admin_domain"`   // e.g. dns.fabiseitz.de
	BlockPageIP         string   `json:"block_page_ip"` // IP of the ShieldDNS server
	LatencyTestInterval int      `json:"latency_test_interval"`
	SmartSelectionPolicy string   `json:"smart_selection_policy"` // "fastest" or "random"
	DiagnosticsRefreshInterval int `json:"diagnostics_refresh_interval"`
	ServeStale          bool     `json:"serve_stale"`
	DNSSECEnabled       bool     `json:"dnssec_enabled"`
	BlockedCountries    []string          `json:"blocked_countries"`
	ClientAliases       map[string]string `json:"client_aliases"`
	SignMobileConfig    bool              `json:"sign_mobileconfig"`
	DebugMode           bool              `json:"debug_mode"`
	LastLogin           time.Time         `json:"last_login"`
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
	Name     string `json:"name"`
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	Category string `json:"category,omitempty"`
}

type Stats struct {
	TotalQueries           int64            `json:"total_queries"`
	BlockedQueries         int64            `json:"blocked_queries"`
	CacheHits              int64            `json:"cache_hits"`
	AverageLatency         float64          `json:"average_latency"` // in milliseconds
	UniqueClients          int              `json:"unique_clients"`
	QueryTypes             map[string]int64 `json:"query_types"`
	Version                string           `json:"version"`
	LatestVersion          string           `json:"latest_version,omitempty"`
	CoreDNSVersion         string           `json:"coredns_version"`
	LatestCoreDNSVersion   string           `json:"latest_coredns_version,omitempty"`
	AlpineVersion          string           `json:"alpine_version"`
	LatestAlpineVersion    string           `json:"latest_alpine_version,omitempty"`
}

type Query struct {
	ID         int64     `json:"id,omitempty"`
	Time       time.Time `json:"time"`
	Domain     string    `json:"domain"`
	Type       string    `json:"type"`
	Status     string    `json:"status"`
	ClientIP   string    `json:"client_ip"`
	UserAgent  string    `json:"user_agent,omitempty"`
	IsCacheHit bool      `json:"is_cache_hit"`
	DurationMs float64   `json:"duration_ms"`
}

type HourStats struct {
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

type DomainCount struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
}

type ClientStats struct {
	Total          int64            `json:"total"`
	Blocked        int64            `json:"blocked"`
	QueryTypes     map[string]int64 `json:"query_types"`
	Timeline       []HourStats      `json:"timeline"` // 24 entries
}

var (
	config         Config
	configLock     sync.RWMutex
	stats          Stats
	statsLock      sync.RWMutex
	dnsCmd         *exec.Cmd
	sessionToken   string
	sessionLock    sync.RWMutex
	history        [24]HourStats
	historyLock    sync.RWMutex

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

	// Blocklist Attribution (Domain -> List Names)
	blockAttribution     = make(map[string][]string)
	blockAttributionLock sync.RWMutex
)

var (
	DataDir       = "/etc/shielddns"
	ConfigPath    = "/etc/shielddns/config.json"
	BlocklistPath = "/etc/shielddns/blocklist.hosts"
	AllowlistPath = "/etc/shielddns/allowlist.hosts"
	MappingsPath  = "/etc/shielddns/mappings.hosts"
	CorefilePath  = "/etc/Corefile"
	DBPath        = "/etc/shielddns/queries.db"
)

const CookieName = "shielddns_session"
