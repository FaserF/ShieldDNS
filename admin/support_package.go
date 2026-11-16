package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// SupportPackageManifest describes the exported diagnostic archive and privacy obfuscation counts.
type SupportPackageManifest struct {
	GeneratedAt       time.Time      `json:"generated_at"`
	ObfuscationLevel  string         `json:"obfuscation_level"`
	ShieldDNSVersion  string         `json:"shielddns_version"`
	RedactedSecrets   int            `json:"redacted_secrets"`
	PseudonymizedIPs  int            `json:"pseudonymized_ips"`
	PseudonymizedRefs int            `json:"pseudonymized_refs"`
	Files             []string       `json:"files"`
	StatsSummary      map[string]int `json:"stats_summary,omitempty"`
}

// GenerateSupportPackage produces an in-memory .zip archive containing redacted configuration,
// system diagnostics, upstream health, change annotations, and behavioral anomalies.
func GenerateSupportPackage(level string) ([]byte, error) {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case "", "strict":
		level = "strict"
	case "standard", "none":
	default:
		return nil, fmt.Errorf("invalid obfuscation level %q: must be strict, standard, or none", level)
	}

	configLock.RLock()
	cfgCopy := config.Clone()
	configLock.RUnlock()

	manifest := SupportPackageManifest{
		GeneratedAt:      time.Now().UTC(),
		ObfuscationLevel: level,
		ShieldDNSVersion: FullVersion,
		Files:            []string{"manifest.json", "system_info.json", "config_redacted.json", "upstreams_health.json", "annotations.json", "anomalies.json"},
	}

	// Always scrub secrets by construction regardless of obfuscation level
	redactedSecrets := 0
	redact := func(s *string) {
		if s != nil && *s != "" {
			*s = "[REDACTED]"
			redactedSecrets++
		}
	}
	redact(&cfgCopy.AdminPasswordHashed)
	redact(&cfgCopy.AIAPIKey)
	redact(&cfgCopy.WebhookToken)
	redact(&cfgCopy.VPNPassword)
	redact(&cfgCopy.VPNUsername)
	redact(&cfgCopy.VPNConfigContent)
	redact(&cfgCopy.NextDNSAPIKey)
	redact(&cfgCopy.ClusterPrimaryToken)
	redact(&cfgCopy.ClusterWorkerToken)
	for i := range cfgCopy.TOTPConfigs {
		redact(&cfgCopy.TOTPConfigs[i].Secret)
	}
	for i := range cfgCopy.APIKeys {
		redact(&cfgCopy.APIKeys[i].TokenHash)
	}
	for i := range cfgCopy.ClusterReplicas {
		redact(&cfgCopy.ClusterReplicas[i].TokenHash)
	}
	for i := range cfgCopy.WebAuthnCredentials {
		cfgCopy.WebAuthnCredentials[i].PublicKey = nil
		redactedSecrets++
	}

	ipMap := make(map[string]string)
	domainMap := make(map[string]string)
	pseudonymizeIP := func(ip string) string {
		if level != "strict" || ip == "" {
			return ip
		}
		if p, ok := ipMap[ip]; ok {
			return p
		}
		p := fmt.Sprintf("client_%02d", len(ipMap)+1)
		ipMap[ip] = p
		return p
	}
	pseudonymizeDomain := func(d string) string {
		if level != "strict" || d == "" {
			return d
		}
		if p, ok := domainMap[d]; ok {
			return p
		}
		p := fmt.Sprintf("domain_%02d.redacted", len(domainMap)+1)
		domainMap[d] = p
		return p
	}

	if level == "strict" {
		if cfgCopy.AdminDomain != "" {
			cfgCopy.AdminDomain = "admin.redacted.local"
		}
		if cfgCopy.WebhookURL != "" {
			cfgCopy.WebhookURL = "https://webhook.redacted.local"
		}
		if cfgCopy.ClusterPrimaryURL != "" {
			cfgCopy.ClusterPrimaryURL = "https://primary.redacted.local"
		}
		newAliases := make(map[string]string)
		for ip := range cfgCopy.ClientAliases {
			pip := pseudonymizeIP(ip)
			newAliases[pip] = pip
		}
		cfgCopy.ClientAliases = newAliases

		for i, ip := range cfgCopy.BlockedClients {
			cfgCopy.BlockedClients[i] = pseudonymizeIP(ip)
		}
		newBlockedInfo := make(map[string]BlockedClientInfo)
		for ip, info := range cfgCopy.BlockedClientsInfo {
			newBlockedInfo[pseudonymizeIP(ip)] = info
		}
		cfgCopy.BlockedClientsInfo = newBlockedInfo

		for i := range cfgCopy.ClientRules {
			cfgCopy.ClientRules[i].ClientIP = pseudonymizeIP(cfgCopy.ClientRules[i].ClientIP)
			cfgCopy.ClientRules[i].Domain = pseudonymizeDomain(cfgCopy.ClientRules[i].Domain)
		}
		for i, d := range cfgCopy.CustomBlocked {
			cfgCopy.CustomBlocked[i] = pseudonymizeDomain(d)
		}
		for i, d := range cfgCopy.CustomAllowed {
			cfgCopy.CustomAllowed[i] = pseudonymizeDomain(d)
		}
		newMappings := make(map[string]string)
		for d, target := range cfgCopy.CustomMappings {
			newMappings[pseudonymizeDomain(d)] = pseudonymizeIP(target)
		}
		cfgCopy.CustomMappings = newMappings
	}

	// Build system_info.json
	s := getStatsData()
	sysInfo := map[string]interface{}{
		"version":         FullVersion,
		"coredns_version": getCoreDNSVersion(),
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"go_version":      runtime.Version(),
		"uptime_seconds":  s.UptimeSeconds,
		"ram_used_mb":     s.RAMUsedMB,
		"ram_total_mb":    s.RAMTotalMB,
		"db_size_mb":      s.DBSizeMB,
		"coredns_alive":   s.CoreDNSAlive,
		"total_queries":   s.TotalQueries,
		"blocked_queries": s.BlockedQueries,
		"blocked_domains": s.BlockedDomains,
	}

	// Build upstreams_health.json
	healthLock.RLock()
	hDNS := append([]string{}, healthyUpstreams...)
	hDoT := append([]string{}, healthyDoT...)
	healthLock.RUnlock()

	latencyLock.RLock()
	latCopy := make(map[string]float64, len(latencyMap))
	for k, v := range latencyMap {
		latCopy[k] = float64(v.Milliseconds())
	}
	latencyLock.RUnlock()

	upstreamsHealth := map[string]interface{}{
		"healthy_upstreams": hDNS,
		"healthy_dot":       hDoT,
		"latencies_ms":      latCopy,
	}

	annotations := GetAnnotations(100)
	anomalies, _ := DetectAnomalies()
	if anomalies == nil {
		anomalies = []AnomalyFinding{}
	}
	if level == "strict" {
		for i := range anomalies {
			anomalies[i].ClientIP = pseudonymizeIP(anomalies[i].ClientIP)
			anomalies[i].ClientAlias = ""
			anomalies[i].Domain = pseudonymizeDomain(anomalies[i].Domain)
			anomalies[i].Summary = "Redacted anomaly summary (" + anomalies[i].Kind + ")"
			anomalies[i].Evidence = "Redacted evidence"
		}
	}

	manifest.RedactedSecrets = redactedSecrets
	manifest.PseudonymizedIPs = len(ipMap)
	manifest.PseudonymizedRefs = len(domainMap)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	addJSON := func(name string, v interface{}) error {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(v)
	}

	if err := addJSON("manifest.json", manifest); err != nil {
		return nil, err
	}
	if err := addJSON("system_info.json", sysInfo); err != nil {
		return nil, err
	}
	if err := addJSON("config_redacted.json", cfgCopy); err != nil {
		return nil, err
	}
	if err := addJSON("upstreams_health.json", upstreamsHealth); err != nil {
		return nil, err
	}
	if err := addJSON("annotations.json", annotations); err != nil {
		return nil, err
	}
	if err := addJSON("anomalies.json", anomalies); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func handleSupportPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	level := r.URL.Query().Get("level")
	if level == "" {
		level = "strict"
	}

	zipBytes, err := GenerateSupportPackage(level)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("shielddns-support-%s-%s.zip", level, time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(zipBytes)
}
