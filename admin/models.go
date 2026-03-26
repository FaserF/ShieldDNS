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
	SetupDone           bool     `json:"setup_done"`
	AdminPasswordHashed string   `json:"admin_password_hashed"`
	APIKeys             []APIKey `json:"api_keys"`
	FilteringEnabled    bool     `json:"filtering_enabled"`
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
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type Stats struct {
	TotalQueries   int64            `json:"total_queries"`
	BlockedQueries int64            `json:"blocked_queries"`
	CacheHits      int64            `json:"cache_hits"`
	QueryTypes     map[string]int64 `json:"query_types"`
	Version        string           `json:"version"`
	CoreDNSVersion string           `json:"coredns_version"`
	AlpineVersion  string           `json:"alpine_version"`
}

type Query struct {
	Time     time.Time `json:"time"`
	Domain   string    `json:"domain"`
	Type     string    `json:"type"`
	Status   string    `json:"status"` // "Allowed" or "Blocked"
	ClientIP string    `json:"client_ip"`
}

type HourStats struct {
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

var (
	config         Config
	configLock     sync.RWMutex
	stats          Stats
	statsLock      sync.RWMutex
	dnsCmd         *exec.Cmd
	sessionToken   string
	sessionLock    sync.RWMutex
	recentQueries  []Query
	queryLock      sync.RWMutex
	history        [24]HourStats
	historyLock    sync.RWMutex
	Version        = "v1.0.1"

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
	CorefilePath  = "/etc/Corefile"
	DBPath        = "/etc/shielddns/queries.db"
)

const CookieName = "shielddns_session"
