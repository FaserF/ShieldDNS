package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ResolutionStage represents a single step evaluated in the DNS decision pipeline.
type ResolutionStage struct {
	Stage  string `json:"stage"`
	Status string `json:"status"` // "matched", "passed", "skipped"
	Detail string `json:"detail"`
}

// ResolutionExplanation contains full causal attribution for how a DNS query is decided.
type ResolutionExplanation struct {
	Domain         string            `json:"domain"`
	ClientIP       string            `json:"client_ip"`
	ClientAlias    string            `json:"client_alias,omitempty"`
	QueryType      string            `json:"qtype"`
	Outcome        string            `json:"outcome"` // "allowed", "blocked", "rewritten", "routed"
	Action         string            `json:"action"`  // "NOERROR", "NXDOMAIN", "NULL_IP", "CUSTOM_IP", "REFUSED", "FORWARD"
	Answer         string            `json:"answer,omitempty"`
	WinningRule    string            `json:"winning_rule"`
	MatchedSources []string          `json:"matched_sources"`
	UpstreamRoute  string            `json:"upstream_route"`
	Summary        string            `json:"summary"`
	FlowHighlight  string            `json:"flow_highlight"` // "blocked", "local", "route", "upstream", "refused"
	Stages         []ResolutionStage `json:"stages"`
	AIVerdict      *AITriageVerdict  `json:"ai_verdict,omitempty"`
}

// ExplainResolution simulates the full ShieldDNS resolution and filtering pipeline
// for a given domain, client IP, and query type without sending live DNS traffic.
func ExplainResolution(domain, clientIP, qtype string, askAI bool) (*ResolutionExplanation, error) {
	norm := NormalizeDomain(domain)
	if norm == "" || !isValidDomain(norm) {
		return nil, fmt.Errorf("invalid or empty domain: %q", domain)
	}

	clientIP = strings.TrimSpace(clientIP)
	qtype = strings.ToUpper(strings.TrimSpace(qtype))
	if qtype == "" {
		qtype = "A"
	}

	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	healthLock.RLock()
	hDoT := append([]string{}, healthyDoT...)
	hDNS := append([]string{}, healthyUpstreams...)
	healthLock.RUnlock()

	alias := ""
	if clientIP != "" && cfg.ClientAliases != nil {
		alias = cfg.ClientAliases[clientIP]
	}

	exp := &ResolutionExplanation{
		Domain:         norm,
		ClientIP:       clientIP,
		ClientAlias:    alias,
		QueryType:      qtype,
		Outcome:        "allowed",
		Action:         "FORWARD",
		MatchedSources: []string{},
		Stages:         []ResolutionStage{},
	}

	// Stage 1: Blocked Client IP check
	if clientIP != "" {
		for _, bc := range cfg.BlockedClients {
			if bc == clientIP {
				exp.Outcome = "blocked"
				exp.Action = "REFUSED"
				exp.WinningRule = "Client IP Block"
				exp.MatchedSources = append(exp.MatchedSources, "Blocked Client IP: "+clientIP)
				exp.FlowHighlight = "refused"
				exp.Summary = fmt.Sprintf("Refused: client %s is explicitly blocked.", clientIP)
				exp.Stages = append(exp.Stages, ResolutionStage{
					Stage:  "client_policy",
					Status: "matched",
					Detail: fmt.Sprintf("Client %s is in Blocked Clients list", clientIP),
				})
				return exp, nil
			}
		}

		// Check client-specific domain rules
		for _, cr := range cfg.ClientRules {
			if cr.ClientIP == clientIP && domainMatchesRule(norm, cr.Domain) {
				if cr.IsAllowlist {
					exp.Outcome = "allowed"
					exp.Action = "FORWARD"
					exp.WinningRule = fmt.Sprintf("Client Allow Rule (%s)", cr.Domain)
					exp.MatchedSources = append(exp.MatchedSources, exp.WinningRule)
					exp.FlowHighlight = "upstream"
					exp.Stages = append(exp.Stages, ResolutionStage{
						Stage:  "client_policy",
						Status: "matched",
						Detail: fmt.Sprintf("Allowed explicitly for client %s by rule %s", clientIP, cr.Domain),
					})
					goto evalRouting
				}
				exp.Outcome = "blocked"
				exp.Action = blockActionForIP(cfg.BlockPageIP)
				exp.Answer = cfg.BlockPageIP
				exp.WinningRule = fmt.Sprintf("Client Block Rule (%s)", cr.Domain)
				exp.MatchedSources = append(exp.MatchedSources, exp.WinningRule)
				exp.FlowHighlight = "blocked"
				exp.Summary = fmt.Sprintf("Blocked for client %s by client rule %s.", clientIP, cr.Domain)
				exp.Stages = append(exp.Stages, ResolutionStage{
					Stage:  "client_policy",
					Status: "matched",
					Detail: exp.Summary,
				})
				return exp, nil
			}
		}
		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "client_policy",
			Status: "passed",
			Detail: "No client-specific block or allow rule matched",
		})
	} else {
		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "client_policy",
			Status: "skipped",
			Detail: "No client IP supplied",
		})
	}

	// Stage 2: SafeSearch / YouTube Restricted Mode
	if targetHost, vip, engine, ok := GetSafeSearchMatch(norm, cfg); ok {
		exp.Outcome = "rewritten"
		exp.Action = "CUSTOM_IP"
		exp.Answer = vip
		exp.WinningRule = fmt.Sprintf("SafeSearch (%s -> %s)", engine, targetHost)
		exp.MatchedSources = append(exp.MatchedSources, exp.WinningRule)
		exp.FlowHighlight = "local"
		exp.Summary = fmt.Sprintf("Rewritten to %s (%s) by %s SafeSearch enforcement.", targetHost, vip, engine)
		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "safesearch",
			Status: "matched",
			Detail: exp.Summary,
		})
		return exp, nil
	}

	// Stage 1b: Policy Engine (Groups, Schedules, Local Records, Quick Rules, Regex)
	if qt, ok := dns.StringToType[qtype]; ok {
		probe := new(dns.Msg)
		probe.SetQuestion(dns.Fqdn(norm), qt)
		if pResp, pDec := EvaluateDNSQuery(probe, clientIP); pResp != nil {
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "policy_engine",
				Status: "matched",
				Detail: fmt.Sprintf("Group=%s Action=%s (%s)", pDec.GroupName, pDec.Action, pDec.Reason),
			})
			switch pDec.Action {
			case "local":
				exp.Outcome = "rewritten"
				exp.Action = "LOCAL_RECORD"
				exp.WinningRule = pDec.Reason
				exp.FlowHighlight = "local"
				exp.Summary = fmt.Sprintf("Answered locally by %s.", pDec.Reason)
				return exp, nil
			case "block":
				exp.Outcome = "blocked"
				exp.Action = "NULL_IP"
				exp.WinningRule = pDec.Reason
				exp.FlowHighlight = "blocked"
				exp.Summary = fmt.Sprintf("Blocked by policy: %s.", pDec.Reason)
				return exp, nil
			case "safesearch":
				exp.Outcome = "rewritten"
				exp.Action = "CUSTOM_IP"
				exp.WinningRule = pDec.Reason
				exp.FlowHighlight = "local"
				exp.Summary = fmt.Sprintf("Rewritten by %s.", pDec.Reason)
				return exp, nil
			}
		} else if pDec.GroupID != "" {
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "policy_engine",
				Status: "passed",
				Detail: "Matched group " + pDec.GroupName,
			})
		}
	}
	exp.Stages = append(exp.Stages, ResolutionStage{
		Stage:  "safesearch",
		Status: "passed",
		Detail: "Not a SafeSearch target domain",
	})

	// Stage 3: Local DNS / Custom Mappings
	if mappedIP, matchedPattern, ok := lookupCustomMapping(norm, cfg.CustomMappings); ok {
		exp.Outcome = "rewritten"
		exp.Action = "CUSTOM_IP"
		exp.Answer = mappedIP
		exp.WinningRule = fmt.Sprintf("Custom Mapping (%s -> %s)", matchedPattern, mappedIP)
		exp.MatchedSources = append(exp.MatchedSources, exp.WinningRule)
		exp.FlowHighlight = "local"
		exp.Summary = fmt.Sprintf("Answered locally with %s via Custom Mapping %s.", mappedIP, matchedPattern)
		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "custom_rules",
			Status: "matched",
			Detail: exp.Summary,
		})
		return exp, nil
	}

	// Stage 1b: Policy Engine (Groups, Schedules, Local Records, Quick Rules, Regex)
	if qt, ok := dns.StringToType[qtype]; ok {
		probe := new(dns.Msg)
		probe.SetQuestion(dns.Fqdn(norm), qt)
		if pResp, pDec := EvaluateDNSQuery(probe, clientIP); pResp != nil {
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "policy_engine",
				Status: "matched",
				Detail: fmt.Sprintf("Group=%s Action=%s (%s)", pDec.GroupName, pDec.Action, pDec.Reason),
			})
			switch pDec.Action {
			case "local":
				exp.Outcome = "rewritten"
				exp.Action = "LOCAL_RECORD"
				exp.WinningRule = pDec.Reason
				exp.FlowHighlight = "local"
				exp.Summary = fmt.Sprintf("Answered locally by %s.", pDec.Reason)
				return exp, nil
			case "block":
				exp.Outcome = "blocked"
				exp.Action = "NULL_IP"
				exp.WinningRule = pDec.Reason
				exp.FlowHighlight = "blocked"
				exp.Summary = fmt.Sprintf("Blocked by policy: %s.", pDec.Reason)
				return exp, nil
			case "safesearch":
				exp.Outcome = "rewritten"
				exp.Action = "CUSTOM_IP"
				exp.WinningRule = pDec.Reason
				exp.FlowHighlight = "local"
				exp.Summary = fmt.Sprintf("Rewritten by %s.", pDec.Reason)
				return exp, nil
			}
		} else if pDec.GroupID != "" {
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "policy_engine",
				Status: "passed",
				Detail: "Matched group " + pDec.GroupName,
			})
		}
	}

	// Stage 4: Global Filtering Check
	if !cfg.FilteringEnabled {
		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "blocklist",
			Status: "skipped",
			Detail: "Global filtering is currently disabled",
		})
		goto evalRouting
	}

	// Stage 5: Allowlist & Custom Allow evaluation
	{
		allowLists := getAllowlistAttribution(norm)
		for _, d := range cfg.CustomAllowed {
			if domainMatchesRule(norm, d) {
				allowLists = append(allowLists, "Custom Allowlist ("+d+")")
				break
			}
		}

		blockLists, isImportant := lookupBlockAttribution(norm)
		for _, d := range cfg.CustomBlocked {
			if domainMatchesRule(norm, d) {
				blockLists = append(blockLists, "Custom Blocklist ("+d+")")
				break
			}
		}
		serviceDomains := GetBlockedServiceDomains(cfg)
		if svcAttr, ok := serviceDomains[norm]; ok {
			blockLists = appendUniqueString(blockLists, svcAttr)
		} else if svcAttr, ok := lookupWildcardMap(norm, serviceDomains); ok {
			blockLists = appendUniqueString(blockLists, svcAttr)
		}

		if len(allowLists) > 0 {
			exp.MatchedSources = append(exp.MatchedSources, allowLists...)
		}
		if len(blockLists) > 0 {
			exp.MatchedSources = append(exp.MatchedSources, blockLists...)
		}

		// $important blocks override general allowlists unless overridden by Custom Allowlist
		customAllowed := false
		for _, d := range cfg.CustomAllowed {
			if domainMatchesRule(norm, d) {
				customAllowed = true
				break
			}
		}

		if len(allowLists) > 0 && (!isImportant || customAllowed) {
			exp.Outcome = "allowed"
			exp.Action = "FORWARD"
			exp.WinningRule = allowLists[0]
			exp.FlowHighlight = "upstream"
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "allowlist",
				Status: "matched",
				Detail: fmt.Sprintf("Allowed by %s", strings.Join(allowLists, ", ")),
			})
			goto evalRouting
		}

		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "allowlist",
			Status: "passed",
			Detail: "No overriding allowlist rule matched",
		})

		if len(blockLists) > 0 {
			exp.Outcome = "blocked"
			exp.Action = blockActionForIP(cfg.BlockPageIP)
			exp.Answer = cfg.BlockPageIP
			exp.WinningRule = blockLists[0]
			exp.FlowHighlight = "blocked"
			exp.Summary = fmt.Sprintf("Blocked (%s) by %s.", exp.Action, strings.Join(blockLists, ", "))
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "blocklist",
				Status: "matched",
				Detail: exp.Summary,
			})
			goto evalAI
		}

		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "blocklist",
			Status: "passed",
			Detail: "Not present on any active blocklist or blocked service",
		})
	}

evalRouting:
	// Stage 6: Conditional Forwarding / Routing Rules
	for _, rr := range cfg.RoutingRules {
		if !rr.Enabled {
			continue
		}
		if rr.MatchType == "domain" && domainMatchesRule(norm, rr.Match) {
			exp.Outcome = "routed"
			exp.FlowHighlight = "route"
			routeTarget := rr.Target
			if rr.HostTarget != "" {
				routeTarget += " (" + rr.HostTarget + ")"
			} else if rr.Country != "" {
				routeTarget += " (" + rr.Country + ")"
			}
			exp.UpstreamRoute = routeTarget
			exp.WinningRule = fmt.Sprintf("Routing Rule (%s -> %s)", rr.Match, routeTarget)
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "geo_routing",
				Status: "matched",
				Detail: exp.WinningRule,
			})
			goto evalSummary
		}
	}
	exp.Stages = append(exp.Stages, ResolutionStage{
		Stage:  "geo_routing",
		Status: "passed",
		Detail: "No domain-specific routing rule matched",
	})

	// Default Upstream selection
	if cfg.PreferEncrypted && len(hDoT) > 0 {
		exp.UpstreamRoute = "DoT: " + strings.Join(hDoT, ", ")
	} else if len(hDNS) > 0 {
		exp.UpstreamRoute = "DNS: " + strings.Join(hDNS, ", ")
	} else if len(cfg.UpstreamDoT) > 0 && cfg.PreferEncrypted {
		exp.UpstreamRoute = "DoT: " + strings.Join(cfg.UpstreamDoT, ", ")
	} else if len(cfg.Upstreams) > 0 {
		exp.UpstreamRoute = "DNS: " + strings.Join(cfg.Upstreams, ", ")
	} else {
		exp.UpstreamRoute = "Default Fallback (8.8.8.8, 1.1.1.1)"
	}

	if exp.FlowHighlight == "" {
		exp.FlowHighlight = "upstream"
	}
	if exp.WinningRule == "" {
		exp.WinningRule = "Default Upstream Forwarder"
	}
	exp.Stages = append(exp.Stages, ResolutionStage{
		Stage:  "upstream",
		Status: "matched",
		Detail: fmt.Sprintf("Forwarded via %s (%s)", exp.UpstreamRoute, cfg.SmartSelectionPolicy),
	})

evalSummary:
	if exp.Summary == "" {
		if exp.Outcome == "routed" {
			exp.Summary = fmt.Sprintf("Allowed and routed via %s.", exp.UpstreamRoute)
		} else {
			exp.Summary = fmt.Sprintf("Allowed (%s) -> forwarded to %s.", exp.WinningRule, exp.UpstreamRoute)
		}
	}

evalAI:
	// Check cached AI rule metadata or optionally invoke Omniroute AI Guardian
	if aiMeta, ok := cfg.AIRules[norm]; ok {
		exp.Stages = append(exp.Stages, ResolutionStage{
			Stage:  "ai_guardian",
			Status: "matched",
			Detail: fmt.Sprintf("AI Guardian rule (%s, %.0f%% confidence): %s", aiMeta.Action, aiMeta.Confidence*100, aiMeta.Reason),
		})
	}

	if askAI && cfg.AIEnabled {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		verdict, err := TriageDomainWithAI(ctx, norm, clientIP, exp.Outcome == "blocked")
		if err == nil && verdict != nil {
			exp.AIVerdict = verdict
			exp.Stages = append(exp.Stages, ResolutionStage{
				Stage:  "ai_guardian",
				Status: "matched",
				Detail: fmt.Sprintf("Omniroute AI assessment: %s (%.0f%%) — %s", verdict.ThreatType, verdict.Confidence*100, verdict.Reason),
			})
		}
	}

	return exp, nil
}

func domainMatchesRule(domain, rule string) bool {
	d := NormalizeDomain(domain)
	r := strings.ToLower(strings.TrimSpace(rule))
	r = strings.TrimPrefix(r, "*.")
	r = NormalizeDomain(r)
	if d == "" || r == "" {
		return false
	}
	return d == r || strings.HasSuffix(d, "."+r)
}

func lookupCustomMapping(domain string, mappings map[string]string) (ip, pattern string, ok bool) {
	if len(mappings) == 0 {
		return "", "", false
	}
	if v, found := mappings[domain]; found {
		return v, domain, true
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		wc := "*." + strings.Join(parts[i:], ".")
		if v, found := mappings[wc]; found {
			return v, wc, true
		}
	}
	return "", "", false
}

func lookupBlockAttribution(domain string) ([]string, bool) {
	blockAttributionLock.RLock()
	defer blockAttributionLock.RUnlock()
	importantAttributionLock.RLock()
	defer importantAttributionLock.RUnlock()

	var matched []string
	isImportant := false

	if lists, ok := blockAttribution[domain]; ok {
		for _, l := range lists {
			matched = appendUniqueString(matched, l)
		}
		if _, imp := importantAttribution[domain]; imp {
			isImportant = true
		}
	}

	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		wc := "*." + strings.Join(parts[i:], ".")
		if lists, ok := blockAttribution[wc]; ok {
			for _, l := range lists {
				matched = appendUniqueString(matched, l)
			}
			if _, imp := importantAttribution[wc]; imp {
				isImportant = true
			}
		}
	}
	return matched, isImportant
}

func lookupWildcardMap(domain string, m map[string]string) (string, bool) {
	parts := strings.Split(domain, ".")
	for i := 0; i < len(parts); i++ {
		wc := "*." + strings.Join(parts[i:], ".")
		if v, ok := m[wc]; ok {
			return v, true
		}
	}
	return "", false
}

func appendUniqueString(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func blockActionForIP(blockIP string) string {
	ip := strings.TrimSpace(blockIP)
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "NULL_IP"
	}
	return "CUSTOM_IP"
}
