package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// isDomainBlockStatus returns true only for domain/blocklist blocks, excluding IP, policy, or threat-intel client blocks.
func isDomainBlockStatus(status string) bool {
	return status == StatusBlocked || status == "Blocked (Blocklist)"
}

// isKnownTrackerOrAdDomain guards against AI Guardian false-positive auto-allowing well-known ad/telemetry domains.
func isKnownTrackerOrAdDomain(domain string) bool {
	d := NormalizeDomain(domain)
	if d == "" {
		return false
	}
	knownTrackers := []string{
		"posthog.com", "sentry.io", "doubleclick.net", "googlesyndication.com",
		"google-analytics.com", "app-measurement.com", "datadoghq.com", "datadoghq.eu",
		"appsflyersdk.com", "branch.io", "clarity.ms", "crashlytics.com",
	}
	for _, root := range knownTrackers {
		if d == root || strings.HasSuffix(d, "."+root) {
			return true
		}
	}
	return false
}

// RunAIGuardianAuditCycle runs a full background audit scanning recent queries.
func RunAIGuardianAuditCycle(ctx context.Context) (*AIAuditReport, error) {
	startTime := time.Now()

	configLock.RLock()
	enabled := config.AIEnabled
	autoBlockThreats := config.AIAutoBlockThreats
	autoBlockAds := config.AIAutoBlockAds
	autoFlagFP := config.AIAutoFlagFalsePositives
	threshold := config.AIConfidenceThreshold
	configLock.RUnlock()

	if !enabled {
		return nil, fmt.Errorf("AI Guardian is disabled in ShieldDNS configuration")
	}

	report := &AIAuditReport{
		ID:        fmt.Sprintf("audit_%d", time.Now().Unix()),
		Timestamp: startTime.UTC(),
		Verdicts:  make([]AITriageVerdict, 0),
	}

	if db == nil {
		report.DurationMs = time.Since(startTime).Milliseconds()
		return report, nil
	}

	// Fetch top 30 distinct domains from the last 30 minutes that need inspection
	cutoff := time.Now().UTC().Add(-30 * time.Minute)
	rows, err := dbQueryContext(ctx, `
		SELECT domain, client_ip, status, COUNT(*) as query_count
		FROM queries
		WHERE timestamp > ?
		  AND domain NOT LIKE '%.local'
		  AND domain NOT LIKE '%.lan'
		  AND domain NOT LIKE '%.internal'
		  AND domain NOT LIKE '%.ts.net'
		  AND domain NOT LIKE '%.home.arpa'
		GROUP BY domain, client_ip, status
		ORDER BY query_count DESC
		LIMIT 30
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("database query failed for AI audit: %w", err)
	}
	defer rows.Close()

	type Candidate struct {
		Domain   string
		ClientIP string
		Status   string
		Count    int
	}
	var candidates []Candidate

	configLock.RLock()
	customBlockedMap := make(map[string]bool, len(config.CustomBlocked))
	for _, d := range config.CustomBlocked {
		customBlockedMap[d] = true
	}
	customAllowedMap := make(map[string]bool, len(config.CustomAllowed))
	for _, d := range config.CustomAllowed {
		customAllowedMap[d] = true
	}
	configLock.RUnlock()

	for rows.Next() {
		var c Candidate
		var count int
		if err := rows.Scan(&c.Domain, &c.ClientIP, &c.Status, &count); err == nil {
			c.Count = count
			c.Domain = NormalizeDomain(c.Domain)
			if c.Domain == "" || isTrustedInfrastructureDomain(c.Domain) {
				continue
			}
			// Skip domains that already have custom rules unless checking for false positives
			isBlocked := isDomainBlockStatus(c.Status)
			if !isBlocked && customBlockedMap[c.Domain] {
				continue
			}
			if isBlocked && customAllowedMap[c.Domain] {
				continue
			}
			candidates = append(candidates, c)
		}
	}

	domainsToBlock := make([]string, 0)
	domainsToAllow := make([]string, 0)
	aiRuleUpdates := make(map[string]AIRuleMetadata)
	triageErrors := 0

	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}
		isBlocked := isDomainBlockStatus(cand.Status)
		verdict, err := TriageDomainWithAI(ctx, cand.Domain, cand.ClientIP, isBlocked)
		if err != nil {
			triageErrors++
			slog.Debug("AI triage failed for candidate", "domain", cand.Domain, "error", err)
			continue
		}

		report.DomainsInspected++
		report.Verdicts = append(report.Verdicts, *verdict)

		// Autonomous Threat Blocking (phishing, malware_c2, dga)
		if verdict.IsThreat && (verdict.ThreatType == "phishing" || verdict.ThreatType == "malware_c2" || verdict.ThreatType == "dga") {
			report.ThreatsDetected++
			if autoBlockThreats && verdict.RecommendedAction == "block" && verdict.Confidence >= threshold && !customBlockedMap[cand.Domain] {
				domainsToBlock = append(domainsToBlock, cand.Domain)
				aiRuleUpdates[cand.Domain] = AIRuleMetadata{
					Domain:     cand.Domain,
					Action:     "block",
					ThreatType: verdict.ThreatType,
					Confidence: verdict.Confidence,
					Reason:     verdict.Reason,
					Model:      verdict.Model,
					CreatedAt:  time.Now().UTC(),
					Source:     "ai_autonomous",
				}
				report.AutoBlockedDomains = append(report.AutoBlockedDomains, cand.Domain)
			}
		}

		// Autonomous Unblocked Ad / Tracker Blocking
		if verdict.ThreatType == "ad_tracker" || verdict.ThreatType == "telemetry" {
			report.AdsDetected++
			if autoBlockAds && verdict.RecommendedAction == "block" && verdict.Confidence >= threshold && !customBlockedMap[cand.Domain] {
				domainsToBlock = append(domainsToBlock, cand.Domain)
				aiRuleUpdates[cand.Domain] = AIRuleMetadata{
					Domain:     cand.Domain,
					Action:     "block",
					ThreatType: verdict.ThreatType,
					Confidence: verdict.Confidence,
					Reason:     verdict.Reason,
					Model:      verdict.Model,
					CreatedAt:  time.Now().UTC(),
					Source:     "ai_autonomous",
				}
				report.AutoBlockedDomains = append(report.AutoBlockedDomains, cand.Domain)
			}
		}

		// Autonomous False Positive Handling (Strictly restricted to trusted LAN/Tailnet queries to prevent reflection flood abuse)
		if isBlocked && !isKnownTrackerOrAdDomain(cand.Domain) && (verdict.ThreatType == "false_positive" || (verdict.ThreatType == "clean" && verdict.RecommendedAction == "allow")) {
			report.FalsePositives++
			if autoFlagFP && verdict.RecommendedAction == "allow" && verdict.Confidence >= threshold && !customAllowedMap[cand.Domain] && IsPrivateOrTailnetIP(cand.ClientIP) && cand.Count < 500 {
				domainsToAllow = append(domainsToAllow, cand.Domain)
				aiRuleUpdates[cand.Domain] = AIRuleMetadata{
					Domain:     cand.Domain,
					Action:     "allow",
					ThreatType: "false_positive",
					Confidence: verdict.Confidence,
					Reason:     verdict.Reason,
					Model:      verdict.Model,
					CreatedAt:  time.Now().UTC(),
					Source:     "ai_autonomous",
				}
				report.AutoAllowedDomains = append(report.AutoAllowedDomains, cand.Domain)
			}
		}
	}

	if triageErrors > 0 && report.DomainsInspected == 0 {
		slog.Warn("AI Guardian audit cycle: all candidate triages failed", "errors", triageErrors)
	}

	// Apply autonomous changes if any domains were marked
	if len(domainsToBlock) > 0 || len(domainsToAllow) > 0 {
		configLock.Lock()
		if config.AIRules == nil {
			config.AIRules = make(map[string]AIRuleMetadata)
		}
		for d, meta := range aiRuleUpdates {
			config.AIRules[d] = meta
		}

		for _, d := range domainsToBlock {
			exists := false
			for _, cb := range config.CustomBlocked {
				if cb == d {
					exists = true
					break
				}
			}
			if !exists {
				config.CustomBlocked = append(config.CustomBlocked, d)
				slog.Info("AI Guardian autonomously blocked threat domain", "domain", d, "threat_type", aiRuleUpdates[d].ThreatType, "confidence", aiRuleUpdates[d].Confidence)
			}
		}

		for _, d := range domainsToAllow {
			exists := false
			for _, ca := range config.CustomAllowed {
				if ca == d {
					exists = true
					break
				}
			}
			if !exists {
				config.CustomAllowed = append(config.CustomAllowed, d)
				slog.Info("AI Guardian autonomously allowed false positive domain", "domain", d, "confidence", aiRuleUpdates[d].Confidence)
			}
		}

		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config after autonomous AI rule update", "error", err)
		}
		reloadRulesFastNoLock(config.Clone())
		configLock.Unlock()
		RecordAnnotation("ai_audit", "ai-guardian", fmt.Sprintf("AI Guardian blocked %d, allowed %d domains", len(domainsToBlock), len(domainsToAllow)))
	}

	report.DurationMs = time.Since(startTime).Milliseconds()

	// Store report in memory ring-buffer
	aiAuditMu.Lock()
	recentAIAuditReports = append([]AIAuditReport{*report}, recentAIAuditReports...)
	if len(recentAIAuditReports) > 20 {
		recentAIAuditReports = recentAIAuditReports[:20]
	}
	aiAuditMu.Unlock()

	slog.Info("AI Guardian audit cycle completed", "domains", report.DomainsInspected, "threats", report.ThreatsDetected, "blocked", len(report.AutoBlockedDomains), "duration_ms", report.DurationMs)

	return report, nil
}
