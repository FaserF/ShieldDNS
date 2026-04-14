package main

import (
	"sync"
	"time"
)

var (
	// System logs state
	systemLogBuffer  []string
	systemLogLock    sync.RWMutex
	systemLogClients = make(map[chan string]struct{})

	// Shared caches
	ipInfoCache sync.Map // IP -> IPInfo
)

// IPInfo represents detailed information about a client IP.
type IPInfo struct {
	IP           string    `json:"ip"`
	Alias        string    `json:"alias,omitempty"`
	IsPrivate    bool      `json:"is_private"`
	Hostname     string    `json:"hostname"`
	Country      string    `json:"country"`
	CountryCode  string    `json:"country_code"`
	City         string    `json:"city"`
	ISP          string    `json:"isp"`
	Org          string    `json:"org"`
	AS           string    `json:"as"`
	MAC          string    `json:"mac,omitempty"`
	Manufacturer string    `json:"manufacturer,omitempty"`
	OS           string    `json:"os,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"-"`
}

// TokenInfo is a public-safe representation of an API Key for the UI.
type TokenInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
}

// UpstreamHealth represents the current status and latency of an upstream DNS server.
type UpstreamHealth struct {
	Server      string  `json:"server"`
	Status      string  `json:"status"`
	LatencyMs   float64 `json:"latency_ms"`
	IsPreferred bool    `json:"is_preferred"`
}
