package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EvaluateDNSQuery evaluates policy rules (groups, schedules, local records, client rules, regex, SafeSearch)
// for a given DNS request and client IP. Returns a direct DNS response if handled locally, or nil to forward.
func EvaluateDNSQuery(req *dns.Msg, clientIP string) (*dns.Msg, PolicyDecision) {
	dec := PolicyDecision{Action: "forward", Status: StatusAllowed}
	if req == nil || len(req.Question) == 0 {
		return nil, dec
	}
	snap := policySnapshotPtr.Load()
	if snap == nil {
		ReloadPolicySnapshot()
		snap = policySnapshotPtr.Load()
		if snap == nil {
			return nil, dec
		}
	}

	q := req.Question[0]
	qName := normalizePolicyDomain(q.Name)
	qTypeStr := dns.TypeToString[q.Qtype]
	now := time.Now()

	grp := snap.matchGroup(clientIP)
	if grp != nil {
		dec.GroupID = grp.raw.ID
		dec.GroupName = grp.raw.Name
		dec.FilterAAAA = grp.raw.FilterAAAA
		if len(grp.raw.Upstreams) > 0 {
			dec.Upstream = grp.raw.Upstreams[0]
		}
	}

	// Check client_ip routing override
	if up, ok := snap.clientUpstreams[clientIP]; ok && up != "" {
		dec.Upstream = up
	}

	// 1. Local Records & Auto-PTR (always honored, including RFC 6761 localhost)
	if resp := snap.matchLocalRecord(req, qName, q.Qtype, dec.FilterAAAA); resp != nil {
		dec.Action = "local"
		dec.Reason = "Local DNS record"
		return resp, dec
	}

	// 2. FilterAAAA for group, global config, or domain match
	if q.Qtype == dns.TypeAAAA && (dec.FilterAAAA || snap.filterAAAA || snap.matchFilterAAAADomain(qName)) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = req.RecursionDesired
		dec.Action = "block"
		dec.Status = StatusBlockedPolicy
		dec.Reason = "FilterAAAA enabled"
		return resp, dec
	}

	if !snap.filteringEnabled {
		return nil, dec
	}

	// 3. Active Schedules for group
	if grp != nil {
		for _, sid := range grp.raw.ScheduleIDs {
			if sched, ok := snap.activeSchedules[sid]; ok {
				if sched.Action == "block_all" {
					dec.Action = "block"
					dec.Status = StatusBlockedPolicy
					dec.ScheduleID = sched.ID
					dec.ScheduleName = sched.Name
					dec.Reason = fmt.Sprintf("Schedule '%s' (block_all)", sched.Name)
					return buildBlockedReply(req, snap.blockPageIP), dec
				}
				if sched.Action == "blocked_services" && matchesAnyService(qName, sched.BlockedServices) {
					dec.Action = "block"
					dec.Status = StatusBlockedPolicy
					dec.ScheduleID = sched.ID
					dec.ScheduleName = sched.Name
					dec.Reason = fmt.Sprintf("Schedule '%s' service block", sched.Name)
					return buildBlockedReply(req, snap.blockPageIP), dec
				}
			}
		}
	}

	// 4. Per-Client Allow/Block rules
	if clientIP != "" {
		if allowMap := snap.clientAllow[clientIP]; allowMap != nil && matchesDomainOrParent(qName, allowMap) {
			dec.Action = "allow"
			dec.Reason = "Client allow rule"
			return nil, dec
		}
		if blockMap := snap.clientBlock[clientIP]; blockMap != nil && matchesDomainOrParent(qName, blockMap) {
			dec.Action = "block"
			dec.Status = StatusBlockedPolicy
			dec.Reason = "Client block rule"
			return buildBlockedReply(req, snap.blockPageIP), dec
		}
	}

	// 5. Group Custom Allow/Block & Group Blocked Services
	if grp != nil {
		if matchesDomainOrParent(qName, grp.allowedExact) {
			dec.Action = "allow"
			dec.Reason = fmt.Sprintf("Group '%s' allow rule", grp.raw.Name)
			return nil, dec
		}
		if matchesDomainOrParent(qName, grp.blockedExact) {
			dec.Action = "block"
			dec.Status = StatusBlockedPolicy
			dec.Reason = fmt.Sprintf("Group '%s' block rule", grp.raw.Name)
			return buildBlockedReply(req, snap.blockPageIP), dec
		}
		if len(grp.raw.BlockedServices) > 0 && matchesAnyService(qName, grp.raw.BlockedServices) {
			dec.Action = "block"
			dec.Status = StatusBlockedPolicy
			dec.Reason = fmt.Sprintf("Group '%s' blocked service", grp.raw.Name)
			return buildBlockedReply(req, snap.blockPageIP), dec
		}
	}

	// 6. QuickRules (exact, wildcard, regex with TTL)
	groupID := ""
	if grp != nil {
		groupID = grp.raw.ID
	}
	for _, qr := range snap.quickRules {
		if qr.expiresAt != nil && now.After(*qr.expiresAt) {
			continue
		}
		if qr.clientIP != "" && qr.clientIP != clientIP {
			continue
		}
		if qr.groupID != "" && qr.groupID != groupID {
			continue
		}
		matched := false
		if qr.isWildcard {
			matched = qName == qr.domain || strings.HasSuffix(qName, "."+qr.domain)
		} else {
			matched = qName == qr.domain
		}
		if matched {
			if qr.isAllowlist {
				dec.Action = "allow"
				dec.Reason = "Quick allow rule"
				return nil, dec
			}
			dec.Action = "block"
			dec.Status = StatusBlockedPolicy
			dec.Reason = "Quick block rule"
			return buildBlockedReply(req, snap.blockPageIP), dec
		}
	}
	for _, rr := range snap.regexRules {
		if rr.expiresAt != nil && now.After(*rr.expiresAt) {
			continue
		}
		if rr.clientIP != "" && rr.clientIP != clientIP {
			continue
		}
		if rr.groupID != "" && rr.groupID != groupID {
			continue
		}
		if rr.re.MatchString(qName) {
			if rr.isAllowlist {
				dec.Action = "allow"
				dec.Reason = fmt.Sprintf("Regex allow /%s/", rr.pattern)
				return nil, dec
			}
			dec.Action = "block"
			dec.Status = StatusBlockedPolicy
			dec.Reason = fmt.Sprintf("Regex block /%s/", rr.pattern)
			return buildBlockedReply(req, snap.blockPageIP), dec
		}
	}

	// 7. Group-level SafeSearch override (when group overrides global)
	if grp != nil && grp.raw.SafeSearchEnabled != nil && *grp.raw.SafeSearchEnabled {
		ytMode := grp.raw.YouTubeRestriction
		if ytMode == "" {
			ytMode = snap.globalYTMode
		}
		if _, _, targetIP, matched := GetSafeSearchMatch(qName, &Config{
			SafeSearchEnabled:  true,
			YouTubeRestriction: ytMode,
		}); matched && targetIP != "" {
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
				dec.Action = "safesearch"
				dec.Reason = fmt.Sprintf("Group '%s' SafeSearch (%s)", grp.raw.Name, qTypeStr)
				return buildIPReply(req, targetIP), dec
			}
		}
	}

	return nil, dec
}

// InspectUpstreamCNAMEs checks Answer-section CNAME targets for CNAME cloaking against blocklists/group rules.
func InspectUpstreamCNAMEs(resp *dns.Msg, clientIP string) (string, bool) {
	snap := policySnapshotPtr.Load()
	if snap == nil || !snap.cnameCloaking || !snap.filteringEnabled || resp == nil {
		return "", false
	}
	for _, rr := range resp.Answer {
		cname, ok := rr.(*dns.CNAME)
		if !ok {
			continue
		}
		target := normalizePolicyDomain(cname.Target)
		if target == "" {
			continue
		}
		if isDomainBlockedByLists(target) {
			return target, true
		}
		if clientIP != "" && snap.clientBlock[clientIP] != nil && matchesDomainOrParent(target, snap.clientBlock[clientIP]) {
			return target, true
		}
	}
	return "", false
}

func isDomainBlockedByLists(domain string) bool {
	blockAttributionLock.RLock()
	defer blockAttributionLock.RUnlock()
	if len(blockAttribution) == 0 {
		return false
	}
	cur := domain
	for cur != "" {
		if sources, ok := blockAttribution[cur]; ok && len(sources) > 0 {
			return true
		}
		idx := strings.IndexByte(cur, '.')
		if idx < 0 {
			break
		}
		cur = cur[idx+1:]
	}
	return false
}

func matchesDomainOrParent(domain string, set map[string]struct{}) bool {
	if len(set) == 0 {
		return false
	}
	cur := domain
	for cur != "" {
		if _, ok := set[cur]; ok {
			return true
		}
		idx := strings.IndexByte(cur, '.')
		if idx < 0 {
			break
		}
		cur = cur[idx+1:]
	}
	return false
}

func matchesAnyService(domain string, serviceIDs []string) bool {
	for _, sid := range serviceIDs {
		for _, p := range DefaultServicePresets {
			if strings.EqualFold(p.ID, sid) {
				for _, sd := range p.Domains {
					sd = normalizePolicyDomain(sd)
					if domain == sd || strings.HasSuffix(domain, "."+sd) {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *PolicySnapshot) matchLocalRecord(req *dns.Msg, qName string, qType uint16, filterAAAA bool) *dns.Msg {
	// RFC 6761 Special-Use Domain Names: localhost, *.localhost, and search-suffix localhost.* loopback resolution
	if qName == "localhost" || strings.HasSuffix(qName, ".localhost") || strings.HasPrefix(qName, "localhost.") {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.RecursionAvailable = req.RecursionDesired
		qFqdn := req.Question[0].Name
		switch qType {
		case dns.TypeA:
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.IPv4(127, 0, 0, 1),
			})
		case dns.TypeAAAA:
			if s == nil || (!filterAAAA && !s.filterAAAA && !s.matchFilterAAAADomain(qName)) {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
					AAAA: net.IPv6loopback,
				})
			}
		}
		return resp
	}

	// RFC 6761 reverse PTR loopback
	if qType == dns.TypePTR && (qName == "1.0.0.127.in-addr.arpa" || qName == "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		resp.RecursionAvailable = req.RecursionDesired
		resp.Answer = append(resp.Answer, &dns.PTR{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 3600},
			Ptr: "localhost.",
		})
		return resp
	}

	// Auto-PTR lookup
	if qType == dns.TypePTR {
		if target, ok := s.autoPTR[strings.ToLower(dns.Fqdn(qName))]; ok {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Authoritative = true
			resp.RecursionAvailable = req.RecursionDesired
			resp.Answer = append(resp.Answer, &dns.PTR{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 300},
				Ptr: target,
			})
			return resp
		}
	}

	var matched []compiledLocalRecord
	for _, rec := range s.localRecords {
		if rec.isWildcard {
			base := strings.TrimPrefix(rec.domain, "*.")
			if qName == base || strings.HasSuffix(qName, "."+base) {
				matched = append(matched, rec)
			}
		} else if qName == rec.domain {
			matched = append(matched, rec)
		}
	}
	if len(matched) == 0 {
		return nil
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = req.RecursionDesired
	qFqdn := req.Question[0].Name

	for _, rec := range matched {
		ttl := rec.raw.TTL
		if ttl == 0 {
			ttl = 300
		}
		rType := strings.ToUpper(strings.TrimSpace(rec.raw.Type))
		switch rType {
		case "A":
			if qType == dns.TypeA {
				if ip := net.ParseIP(rec.raw.Value).To4(); ip != nil {
					resp.Answer = append(resp.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
						A:   ip,
					})
				}
			}
		case "AAAA":
			if qType == dns.TypeAAAA {
				if ip := net.ParseIP(rec.raw.Value).To16(); ip != nil && ip.To4() == nil {
					resp.Answer = append(resp.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
						AAAA: ip,
					})
				}
			}
		case "CNAME":
			resp.Answer = append(resp.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
				Target: dns.Fqdn(rec.raw.Value),
			})
		case "TXT":
			if qType == dns.TypeTXT {
				resp.Answer = append(resp.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
					Txt: []string{rec.raw.Value},
				})
			}
		case "MX":
			if qType == dns.TypeMX {
				pref := rec.raw.Priority
				if pref == 0 {
					pref = 10
				}
				resp.Answer = append(resp.Answer, &dns.MX{
					Hdr:        dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
					Preference: pref,
					Mx:         dns.Fqdn(rec.raw.Value),
				})
			}
		case "SRV":
			if qType == dns.TypeSRV {
				resp.Answer = append(resp.Answer, &dns.SRV{
					Hdr:      dns.RR_Header{Name: qFqdn, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl},
					Priority: rec.raw.Priority,
					Weight:   rec.raw.Weight,
					Port:     rec.raw.Port,
					Target:   dns.Fqdn(rec.raw.Value),
				})
			}
		case "PTR":
			if qType == dns.TypePTR {
				resp.Answer = append(resp.Answer, &dns.PTR{
					Hdr: dns.RR_Header{Name: qFqdn, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
					Ptr: dns.Fqdn(rec.raw.Value),
				})
			}
		}
	}

	if len(resp.Answer) == 0 {
		return nil
	}
	return resp
}

func buildBlockedReply(req *dns.Msg, blockPageIP string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = req.RecursionDesired
	if len(req.Question) == 0 {
		return resp
	}
	q := req.Question[0]
	if blockPageIP != "" && q.Qtype == dns.TypeA {
		if ip := net.ParseIP(blockPageIP).To4(); ip != nil {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   ip,
			})
			return resp
		}
	}
	if q.Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4zero,
		})
	} else if q.Qtype == dns.TypeAAAA {
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.IPv6zero,
		})
	} else {
		resp.SetRcode(req, dns.RcodeNameError)
	}
	return resp
}

func buildIPReply(req *dns.Msg, ipStr string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = req.RecursionDesired
	if len(req.Question) == 0 {
		return resp
	}
	q := req.Question[0]
	if ip := net.ParseIP(ipStr); ip != nil {
		if ip4 := ip.To4(); ip4 != nil && q.Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip4,
			})
		} else if ip.To4() == nil && q.Qtype == dns.TypeAAAA {
			resp.Answer = append(resp.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: ip,
			})
		}
	}
	return resp
}
