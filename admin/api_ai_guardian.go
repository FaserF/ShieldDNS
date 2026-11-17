package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AITriageVerdict holds the structured evaluation of a domain by the AI model.
type AITriageVerdict struct {
	Domain            string    `json:"domain"`
	IsThreat          bool      `json:"is_threat"`
	ThreatType        string    `json:"threat_type"` // "phishing", "malware_c2", "dga", "ad_tracker", "telemetry", "false_positive", "clean"
	Confidence        float64   `json:"confidence"`
	Reason            string    `json:"reason"`
	RecommendedAction string    `json:"recommended_action"` // "block", "allow", "monitor"
	Model             string    `json:"model"`
	EvaluatedAt       time.Time `json:"evaluated_at"`
}

// AIAuditReport summarizes an autonomous or manual AI audit run.
type AIAuditReport struct {
	ID                 string            `json:"id"`
	Timestamp          time.Time         `json:"timestamp"`
	DomainsInspected   int               `json:"domains_inspected"`
	ThreatsDetected    int               `json:"threats_detected"`
	AdsDetected        int               `json:"ads_detected"`
	FalsePositives     int               `json:"false_positives"`
	AutoBlockedDomains []string          `json:"auto_blocked_domains"`
	AutoAllowedDomains []string          `json:"auto_allowed_domains"`
	Verdicts           []AITriageVerdict `json:"verdicts"`
	DurationMs         int64             `json:"duration_ms"`
}

var (
	aiCacheMu          sync.RWMutex
	aiVerdictCache     = make(map[string]AITriageVerdict)
	aiAuditMu          sync.RWMutex
	recentAIAuditReports []AIAuditReport
	triggerAIAuditChan = make(chan struct{}, 1)
)

// OpenAIChatMessage represents a message in the standard OpenAI chat completions API.
type OpenAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIChatRequest represents a standard chat completions request.
type OpenAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []OpenAIChatMessage `json:"messages"`
	Temperature float64             `json:"temperature"`
	MaxTokens   int                 `json:"max_tokens"`
}

// OpenAIChatResponse represents a standard chat completions response.
type OpenAIChatResponse struct {
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

// CallOpenAIChatCompletion sends an OpenAI-compatible /v1/chat/completions request.
func CallOpenAIChatCompletion(ctx context.Context, messages []OpenAIChatMessage) (string, error) {
	configLock.RLock()
	baseURL := strings.TrimRight(config.AIBaseURL, "/")
	apiKey := config.AIAPIKey
	model := config.AIModel
	timeoutSec := config.AITimeoutSeconds
	configLock.RUnlock()

	if baseURL == "" {
		baseURL = "http://127.0.0.1:20128/v1"
	}
	if model == "" {
		model = "security-threat-cascade"
	}
	if timeoutSec <= 0 {
		timeoutSec = 15
	}

	reqBody := OpenAIChatRequest{
		Model:       model,
		Messages:    messages,
		Temperature: 0.1,
		MaxTokens:   350,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := baseURL + "/chat/completions"
	if !isValidRedirectUrl(endpoint) {
		return "", fmt.Errorf("invalid or disallowed AI base URL")
	}
	parsedAI, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("failed to parse AI URL: %w", err)
	}
	if err := isSafeClusterTarget(parsedAI); err != nil {
		return "", fmt.Errorf("unsafe AI target URL: %w", err)
	}
	safeEndpoint := (&url.URL{
		Scheme: parsedAI.Scheme,
		Host:   parsedAI.Host,
		Path:   parsedAI.Path,
	}).String()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, safeEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI completion request failed (%s): %w", endpoint, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read AI completion response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("AI completion error (status %d): %s", resp.StatusCode, string(respBytes))
	}

	var chatResp OpenAIChatResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return "", fmt.Errorf("failed to parse AI JSON response: %w", err)
	}

	if chatResp.Error != nil && chatResp.Error.Message != "" {
		return "", fmt.Errorf("AI provider error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("AI returned no completion choices")
	}

	return strings.TrimSpace(chatResp.Choices[0].Message.Content), nil
}

// isTrustedInfrastructureDomain prevents autonomous AI or accidental blocking of major legitimate vendor/cloud infrastructure domains,
// while still allowing deliberate ad/tracking subdomains (e.g. adservice.google.com) to be filtered.
func isTrustedInfrastructureDomain(domain string) bool {
	d := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), "*."), ".")
	if d == "" {
		return false
	}
	// Exclude known ad/tracking subdomains from being protected
	adPrefixes := []string{"adservice.", "googleads.", "pagead", "doubleclick.", "ads."}
	for _, p := range adPrefixes {
		if strings.HasPrefix(d, p) {
			return false
		}
	}
	trustedRoots := []string{
		"googleapis.com", "gstatic.com", "google.com", "googleusercontent.com", "gvt1.com", "gvt2.com",
		"microsoft.com", "windowsupdate.com", "live.com", "office.com", "azure.com",
		"apple.com", "icloud.com", "mzstatic.com",
		"github.com", "githubusercontent.com", "ghcr.io",
		"cloudflare.com", "cloudflare-dns.com",
		"amazonaws.com", "cloudfront.net",
		"tailscale.com", "fabiseitz.de",
		"ubuntu.com", "debian.org", "docker.com", "docker.io",
	}
	for _, root := range trustedRoots {
		if d == root || strings.HasSuffix(d, "."+root) {
			return true
		}
	}
	return false
}

// TriageDomainWithAI performs structured threat and category triage on a domain.
func TriageDomainWithAI(ctx context.Context, domain string, clientIP string, isBlocked bool) (*AITriageVerdict, error) {
	normDomain := NormalizeDomain(domain)
	if normDomain == "" {
		return nil, fmt.Errorf("empty or invalid domain")
	}

	// 1. Check in-memory verdict cache (valid for 12 hours)
	aiCacheMu.RLock()
	cached, found := aiVerdictCache[normDomain]
	aiCacheMu.RUnlock()
	if found && time.Since(cached.EvaluatedAt) < 12*time.Hour {
		return &cached, nil
	}

	// 2. Perform local lexical vector assessment for initial heuristics
	vectorAssessment := EvaluateDomainVectorThreat(normDomain)

	// 3. Construct structured AI prompt
	systemPrompt := `You are ShieldDNS AI Guardian, an autonomous DNS security and network telemetry analyzer.
Analyze the target domain and output STRICTLY valid JSON with no conversational text or markdown fences.
CRITICAL CLASSIFICATION RULES:
1. Official vendor/cloud infrastructure subdomains (e.g., *.googleapis.com, *.gstatic.com, *.microsoft.com, *.amazonaws.com, *.github.com, *.cloudflare.com, *.apple.com) are LEGITIMATE ("clean"), NEVER classify them as phishing or DGA.
2. Only classify as "phishing" or "typosquat" if the root domain itself is a deceptive lookalike (e.g., paypa1-login.xyz, g00gle-verify.com).
3. Analytics, telemetry, and ad networks (e.g., posthog, sentry, doubleclick, app-measurement) are "ad_tracker" or "telemetry", NEVER "false_positive".
4. Only use "false_positive" for clearly legitimate user-facing websites or essential APIs that appear mistakenly blocked.

Output schema:
{
  "is_threat": boolean,
  "threat_type": "phishing" | "malware_c2" | "dga" | "ad_tracker" | "telemetry" | "false_positive" | "clean",
  "confidence": float between 0.0 and 1.0,
  "reason": "concise English reason under 100 characters",
  "recommended_action": "block" | "allow" | "monitor"
}`

	userPrompt := fmt.Sprintf(`Evaluate domain: "%s"
Local Lexical Assessment:
- Vector Threat Detected: %t
- Vector Threat Type: %s
- Shannon Entropy: %.2f
- Brand Typosquat Match: %s (Similarity: %.2f)
- Currently Blocked: %t
- Client IP: %s

Respond with JSON only.`, normDomain, vectorAssessment.IsThreat, vectorAssessment.ThreatType, vectorAssessment.Entropy, vectorAssessment.MatchedAnchor, vectorAssessment.SimilarityScore, isBlocked, clientIP)

	messages := []OpenAIChatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	content, err := CallOpenAIChatCompletion(ctx, messages)
	if err != nil {
		return nil, err
	}

	// Clean any markdown formatting backticks from response if returned
	cleaned := strings.TrimSpace(content)
	if strings.HasPrefix(cleaned, "```json") {
		cleaned = strings.TrimPrefix(cleaned, "```json")
		cleaned = strings.TrimSuffix(cleaned, "```")
	} else if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.TrimPrefix(cleaned, "```")
		cleaned = strings.TrimSuffix(cleaned, "```")
	}
	cleaned = strings.TrimSpace(cleaned)

	var verdict AITriageVerdict
	if err := json.Unmarshal([]byte(cleaned), &verdict); err != nil {
		slog.Warn("Failed to unmarshal AI response JSON, attempting fallback extraction", "raw", cleaned, "error", err)
		return nil, fmt.Errorf("failed to parse AI triage JSON: %w (raw: %s)", err, cleaned)
	}

	verdict.Domain = normDomain
	verdict.EvaluatedAt = time.Now().UTC()
	configLock.RLock()
	verdict.Model = config.AIModel
	configLock.RUnlock()

	// Cache verdict
	aiCacheMu.Lock()
	aiVerdictCache[normDomain] = verdict
	aiCacheMu.Unlock()

	return &verdict, nil
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
		  AND domain NOT LIKE '%.tailnet.fabiseitz.de'
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
			c.Domain = NormalizeDomain(c.Domain)
			if c.Domain == "" || isTrustedInfrastructureDomain(c.Domain) {
				continue
			}
			// Skip domains that already have custom rules unless checking for false positives
			isBlocked := strings.HasPrefix(c.Status, "Blocked")
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

	for _, cand := range candidates {
		if ctx.Err() != nil {
			break
		}
		isBlocked := strings.HasPrefix(cand.Status, "Blocked")
		verdict, err := TriageDomainWithAI(ctx, cand.Domain, cand.ClientIP, isBlocked)
		if err != nil {
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

		// Autonomous False Positive Handling
		if isBlocked && (verdict.ThreatType == "false_positive" || (verdict.ThreatType == "clean" && verdict.RecommendedAction == "allow")) {
			report.FalsePositives++
			if autoFlagFP && verdict.RecommendedAction == "allow" && verdict.Confidence >= 0.95 && !customAllowedMap[cand.Domain] {
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

// startAIGuardianWorker runs the background autonomous audit loop.
func startAIGuardianWorker(ctx context.Context) {
	slog.Info("Starting AI Guardian autonomous background worker")

	// Initial delay to let CoreDNS and database initialize
	select {
	case <-ctx.Done():
		return
	case <-time.After(15 * time.Second):
	}

	for {
		configLock.RLock()
		intervalMin := config.AIAuditIntervalMinutes
		enabled := config.AIEnabled
		configLock.RUnlock()

		if intervalMin <= 0 {
			intervalMin = 5
		}

		if enabled {
			if _, err := RunAIGuardianAuditCycle(ctx); err != nil {
				slog.Debug("AI Guardian cycle error", "error", err)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-triggerAIAuditChan:
			slog.Info("AI Guardian audit triggered immediately on-demand")
		case <-time.After(time.Duration(intervalMin) * time.Minute):
		}
	}
}

// HTTP Handler: POST /api/ai/triage
func handleAITriage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain   string `json:"domain"`
		ClientIP string `json:"client_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid JSON request: "+err.Error(), http.StatusBadRequest)
		return
	}

	domain := NormalizeDomain(req.Domain)
	if domain == "" {
		sendJSONError(w, "Domain is required", http.StatusUnprocessableEntity)
		return
	}

	verdict, err := TriageDomainWithAI(r.Context(), domain, req.ClientIP, false)
	if err != nil {
		sendJSONError(w, "AI Triage failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(verdict)
}

// HTTP Handler: POST /api/ai/audit
func handleAITriggerAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	report, err := RunAIGuardianAuditCycle(r.Context())
	if err != nil {
		sendJSONError(w, "AI Audit run failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// HTTP Handler: GET /api/ai/rules
func handleAIGetRules(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	rules := make([]AIRuleMetadata, 0, len(config.AIRules))
	for _, r := range config.AIRules {
		rules = append(rules, r)
	}
	configLock.RUnlock()

	aiAuditMu.RLock()
	lastReport := AIAuditReport{}
	if len(recentAIAuditReports) > 0 {
		lastReport = recentAIAuditReports[0]
	}
	aiAuditMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules":       rules,
		"last_report": lastReport,
	})
}

// MCP Tools for AI Threat Intelligence
var mcpAITools = []mcpToolDefinition{
	{
		tool: mcpTool{
			Name:        "ai_triage_domain",
			Description: "Analyzes a domain using ShieldDNS AI Guardian (connected to your Omniroute cascade) to classify it into phishing, malware C2, DGA, ad/tracker, false positive, or clean with a confidence score and action recommendation.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{
						"type":        "string",
						"description": "Domain name to analyze (e.g. suspicious-bank-verify.xyz)",
					},
					"client_ip": map[string]interface{}{
						"type":        "string",
						"description": "Optional client IP that queried the domain",
					},
				},
				"required": []string{"domain"},
			},
		},
		requiredPerm: "read:diagnostics",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			clientIP, _ := args["client_ip"].(string)
			if domain == "" {
				return nil, fmt.Errorf("domain parameter is required")
			}
			return TriageDomainWithAI(context.Background(), domain, clientIP, false)
		},
	},
	{
		tool: mcpTool{
			Name:        "ai_audit_anomalies",
			Description: "Triggers an immediate autonomous AI Guardian audit of recent DNS traffic. Scans for anomalous high-entropy queries, typosquats, and unblocked ad/telemetry beacons, applying auto-blocking or auto-whitelisting according to ShieldDNS configuration.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"force": map[string]interface{}{
						"type":        "boolean",
						"description": "Force immediate execution even if recently run",
					},
				},
			},
		},
		requiredPerm: "write:maintenance",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			return RunAIGuardianAuditCycle(context.Background())
		},
	},
	{
		tool: mcpTool{
			Name:        "get_ai_rules",
			Description: "Returns all domain rules that were autonomously created or flagged by ShieldDNS AI Guardian, including threat type, confidence score, and justification.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			defer configLock.RUnlock()
			rules := make([]AIRuleMetadata, 0, len(config.AIRules))
			for _, r := range config.AIRules {
				rules = append(rules, r)
			}
			return map[string]interface{}{
				"total": rules,
				"count": len(rules),
			}, nil
		},
	},
}
