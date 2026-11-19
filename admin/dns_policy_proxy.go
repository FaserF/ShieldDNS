package main

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// PolicyDecision describes the outcome of evaluating a DNS query against ShieldDNS policy.
type PolicyDecision struct {
	Action       string // "allow", "block", "local", "safesearch", "cname_block", "forward"
	Reason       string
	GroupID      string
	GroupName    string
	ScheduleID   string
	ScheduleName string
	Upstream     string
	FilterAAAA   bool
	Status       string
}

type compiledGroup struct {
	raw             ClientGroup
	ips             map[string]struct{}
	cidrs           []*net.IPNet
	macs            map[string]struct{}
	blockedExact    map[string]struct{}
	allowedExact    map[string]struct{}
	blockedServices map[string]struct{}
}

type compiledRegexRule struct {
	pattern     string
	re          *regexp.Regexp
	isAllowlist bool
	groupID     string
	clientIP    string
	expiresAt   *time.Time
}

type compiledQuickRule struct {
	domain      string
	isWildcard  bool
	isAllowlist bool
	groupID     string
	clientIP    string
	expiresAt   *time.Time
}

type compiledLocalRecord struct {
	raw        LocalRecord
	domain     string
	isWildcard bool
}

// PolicySnapshot is an immutable, lock-free compiled view of Config for query evaluation.
type PolicySnapshot struct {
	groups           []compiledGroup
	activeSchedules  map[string]ScheduleRule // scheduleID -> active rule
	localRecords     []compiledLocalRecord
	autoPTR          map[string]string // arpa name -> fqdn
	regexRules       []compiledRegexRule
	quickRules       []compiledQuickRule
	clientBlock      map[string]map[string]struct{} // clientIP -> domains
	clientAllow      map[string]map[string]struct{} // clientIP -> domains
	clientUpstreams  map[string]string              // clientIP/CIDR -> upstream
	blockedClients   map[string]struct{}            // clientIP -> blocked
	cnameCloaking    bool
	filteringEnabled bool
	blockPageIP      string
	globalSafeSearch bool
	globalYTMode     string
	engineAddr       string
	compiledAt       time.Time
}

var (
	policySnapshotPtr atomic.Pointer[PolicySnapshot]
	policyProxyOnce   sync.Once
	policyProxyPort   = "5354"
)

// ReloadPolicySnapshot compiles the current Config and active schedule states into an atomic snapshot.
func ReloadPolicySnapshot() {
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()
	if cfg == nil {
		return
	}

	now := time.Now()
	snap := compilePolicySnapshot(cfg, now)
	policySnapshotPtr.Store(snap)
}

func compilePolicySnapshot(cfg *Config, now time.Time) *PolicySnapshot {
	enginePort := getInternalEnginePort()
	snap := &PolicySnapshot{
		activeSchedules:  make(map[string]ScheduleRule),
		autoPTR:          make(map[string]string),
		clientBlock:      make(map[string]map[string]struct{}),
		clientAllow:      make(map[string]map[string]struct{}),
		clientUpstreams:  make(map[string]string),
		blockedClients:   make(map[string]struct{}),
		cnameCloaking:    cfg.CNAMECloakingEnabled,
		filteringEnabled: cfg.FilteringEnabled,
		blockPageIP:      cfg.BlockPageIP,
		globalSafeSearch: cfg.SafeSearchEnabled,
		globalYTMode:     cfg.YouTubeRestriction,
		engineAddr:       "127.0.0.1:" + enginePort,
		compiledAt:       now,
	}

	for _, bc := range cfg.BlockedClients {
		if bc != "" {
			snap.blockedClients[bc] = struct{}{}
		}
	}

	for _, s := range cfg.Schedules {
		if s.Enabled && isScheduleActive(s, now) {
			snap.activeSchedules[s.ID] = s
		}
	}

	for _, g := range cfg.Groups {
		cg := compiledGroup{
			raw:             g,
			ips:             make(map[string]struct{}),
			macs:            make(map[string]struct{}),
			blockedExact:    make(map[string]struct{}),
			allowedExact:    make(map[string]struct{}),
			blockedServices: make(map[string]struct{}),
		}
		for _, m := range g.Members {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if strings.Contains(m, "/") {
				if _, ipNet, err := net.ParseCIDR(m); err == nil {
					cg.cidrs = append(cg.cidrs, ipNet)
				}
			} else if strings.Count(m, ":") == 5 && net.ParseIP(m) == nil {
				cg.macs[strings.ToLower(m)] = struct{}{}
			} else {
				cg.ips[m] = struct{}{}
			}
		}
		for _, d := range g.CustomBlocked {
			cg.blockedExact[normalizePolicyDomain(d)] = struct{}{}
		}
		for _, d := range g.CustomAllowed {
			cg.allowedExact[normalizePolicyDomain(d)] = struct{}{}
		}
		for _, svc := range g.BlockedServices {
			cg.blockedServices[strings.ToLower(strings.TrimSpace(svc))] = struct{}{}
		}
		snap.groups = append(snap.groups, cg)
	}

	for _, rec := range cfg.LocalRecords {
		dom := normalizePolicyDomain(rec.Domain)
		if dom == "" {
			continue
		}
		isWild := strings.HasPrefix(dom, "*.")
		snap.localRecords = append(snap.localRecords, compiledLocalRecord{
			raw:        rec,
			domain:     dom,
			isWildcard: isWild,
		})
		if cfg.AutoPTR && !isWild && (strings.EqualFold(rec.Type, "A") || strings.EqualFold(rec.Type, "AAAA")) {
			if arpa, err := dns.ReverseAddr(strings.TrimSpace(rec.Value)); err == nil {
				snap.autoPTR[strings.ToLower(arpa)] = dns.Fqdn(dom)
			}
		}
	}
	if cfg.AutoPTR {
		for dom, val := range cfg.CustomMappings {
			norm := normalizePolicyDomain(dom)
			if norm == "" || strings.HasPrefix(norm, "*.") {
				continue
			}
			if arpa, err := dns.ReverseAddr(strings.TrimSpace(val)); err == nil {
				snap.autoPTR[strings.ToLower(arpa)] = dns.Fqdn(norm)
			}
		}
	}

	for _, cr := range cfg.ClientRules {
		dom := normalizePolicyDomain(cr.Domain)
		if dom == "" || cr.ClientIP == "" {
			continue
		}
		target := snap.clientBlock
		if cr.IsAllowlist {
			target = snap.clientAllow
		}
		if target[cr.ClientIP] == nil {
			target[cr.ClientIP] = make(map[string]struct{})
		}
		target[cr.ClientIP][dom] = struct{}{}
	}

	for _, qr := range cfg.QuickRules {
		if qr.ExpiresAt != nil && now.After(*qr.ExpiresAt) {
			continue
		}
		dom := strings.TrimSpace(qr.Domain)
		if strings.HasPrefix(dom, "/") && strings.HasSuffix(dom, "/") && len(dom) > 2 {
			pattern := dom[1 : len(dom)-1]
			if re, err := regexp.Compile(pattern); err == nil {
				snap.regexRules = append(snap.regexRules, compiledRegexRule{
					pattern:     pattern,
					re:          re,
					isAllowlist: qr.IsAllowlist,
					groupID:     qr.GroupID,
					clientIP:    qr.ClientIP,
					expiresAt:   qr.ExpiresAt,
				})
			}
			continue
		}
		norm := normalizePolicyDomain(dom)
		if norm == "" {
			continue
		}
		snap.quickRules = append(snap.quickRules, compiledQuickRule{
			domain:      strings.TrimPrefix(norm, "*."),
			isWildcard:  strings.HasPrefix(norm, "*."),
			isAllowlist: qr.IsAllowlist,
			groupID:     qr.GroupID,
			clientIP:    qr.ClientIP,
			expiresAt:   qr.ExpiresAt,
		})
	}

	for _, rr := range cfg.RoutingRules {
		if rr.Enabled && rr.MatchType == "client_ip" && rr.Match != "" && rr.HostTarget != "" {
			snap.clientUpstreams[strings.TrimSpace(rr.Match)] = strings.TrimSpace(rr.HostTarget)
		}
	}

	return snap
}

func normalizePolicyDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

// isScheduleActive checks whether a ScheduleRule is active at the given time.
func isScheduleActive(s ScheduleRule, now time.Time) bool {
	if !s.Enabled {
		return false
	}
	loc := time.Local
	if s.Timezone != "" && !strings.EqualFold(s.Timezone, "Local") {
		if loaded, err := time.LoadLocation(s.Timezone); err == nil {
			loc = loaded
		}
	}
	localNow := now.In(loc)

	startMin, ok1 := parseHHMM(s.StartTime)
	endMin, ok2 := parseHHMM(s.EndTime)
	if !ok1 || !ok2 {
		return false
	}
	curMin := localNow.Hour()*60 + localNow.Minute()

	// Check day-of-week. For overnight windows (start > end), if we're in the post-midnight tail,
	// check yesterday's weekday as well.
	dayAllowed := func(wd time.Weekday) bool {
		if len(s.Days) == 0 {
			return true
		}
		code := weekdayCode(wd)
		for _, d := range s.Days {
			if strings.EqualFold(strings.TrimSpace(d), code) {
				return true
			}
		}
		return false
	}

	if startMin <= endMin {
		return dayAllowed(localNow.Weekday()) && curMin >= startMin && curMin < endMin
	}
	// Overnight window (e.g., 22:00 -> 07:00)
	if curMin >= startMin {
		return dayAllowed(localNow.Weekday())
	}
	if curMin < endMin {
		yesterday := localNow.AddDate(0, 0, -1).Weekday()
		return dayAllowed(yesterday)
	}
	return false
}

func parseHHMM(val string) (int, bool) {
	parts := strings.Split(strings.TrimSpace(val), ":")
	if len(parts) != 2 {
		return 0, false
	}
	var h, m int
	if _, err := fmt.Sscanf(parts[0], "%d", &h); err != nil || h < 0 || h > 23 {
		return 0, false
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &m); err != nil || m < 0 || m > 59 {
		return 0, false
	}
	return h*60 + m, true
}

func weekdayCode(wd time.Weekday) string {
	switch wd {
	case time.Monday:
		return "mon"
	case time.Tuesday:
		return "tue"
	case time.Wednesday:
		return "wed"
	case time.Thursday:
		return "thu"
	case time.Friday:
		return "fri"
	case time.Saturday:
		return "sat"
	case time.Sunday:
		return "sun"
	}
	return ""
}

func (s *PolicySnapshot) matchGroup(clientIP string) *compiledGroup {
	if s == nil || clientIP == "" {
		return nil
	}
	// 1. Exact IP match
	for i := range s.groups {
		if _, ok := s.groups[i].ips[clientIP]; ok {
			return &s.groups[i]
		}
	}
	// 2. Most-specific CIDR match
	ip := net.ParseIP(clientIP)
	if ip != nil {
		var best *compiledGroup
		bestOnes := -1
		for i := range s.groups {
			for _, cidr := range s.groups[i].cidrs {
				if cidr.Contains(ip) {
					ones, _ := cidr.Mask.Size()
					if ones > bestOnes {
						bestOnes = ones
						best = &s.groups[i]
					}
				}
			}
		}
		if best != nil {
			return best
		}
	}
	return nil
}

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

	// 1. Local Records & Auto-PTR (always honored)
	if resp := snap.matchLocalRecord(req, qName, q.Qtype); resp != nil {
		dec.Action = "local"
		dec.Reason = "Local DNS record"
		return resp, dec
	}

	// 2. FilterAAAA for group
	if dec.FilterAAAA && q.Qtype == dns.TypeAAAA {
		resp := new(dns.Msg)
		resp.SetReply(req)
		dec.Action = "block"
		dec.Status = StatusBlockedPolicy
		dec.Reason = "Group FilterAAAA enabled"
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

func (s *PolicySnapshot) matchLocalRecord(req *dns.Msg, qName string, qType uint16) *dns.Msg {
	// Auto-PTR lookup
	if qType == dns.TypePTR {
		if target, ok := s.autoPTR[strings.ToLower(dns.Fqdn(qName))]; ok {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Authoritative = true
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

// StartPolicyProxy starts the local DNS Policy Proxy (UDP + TCP) and schedule ticker.
func StartPolicyProxy() {
	policyProxyOnce.Do(func() {
		ReloadPolicySnapshot()

		// Refresh schedule active states every 15s
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-appCtx.Done():
					return
				case <-ticker.C:
					ReloadPolicySnapshot()
				}
			}
		}()

		addr := "127.0.0.1:" + policyProxyPort
		handler := dns.HandlerFunc(handlePolicyDNSRequest)

		for _, netType := range []string{"udp", "tcp"} {
			srv := &dns.Server{
				Addr:    addr,
				Net:     netType,
				Handler: handler,
			}
			go func(nt string, s *dns.Server) {
				slog.Info("DNS Policy Proxy listening", "net", nt, "addr", addr)
				if err := s.ListenAndServe(); err != nil {
					slog.Error("DNS Policy Proxy stopped", "net", nt, "error", err)
				}
			}(netType, srv)
		}
	})
}

func handlePolicyDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := extractRemoteIP(w.RemoteAddr())
	// Check ECS option if forwarded from local CoreDNS
	if clientIP == "127.0.0.1" || clientIP == "::1" {
		if ecsIP := extractECSClientIP(r); ecsIP != "" {
			clientIP = ecsIP
		}
	}

	snap := policySnapshotPtr.Load()
	if snap != nil && len(snap.blockedClients) > 0 {
		if _, blocked := snap.blockedClients[clientIP]; blocked {
			refused := new(dns.Msg)
			refused.SetRcode(r, dns.RcodeRefused)
			_ = w.WriteMsg(refused)
			RecordFlowAndSLO("", "client_blocked", "local", "REFUSED", 0.05)
			return
		}
	}

	if directResp, dec := EvaluateDNSQuery(r, clientIP); directResp != nil {
		_ = w.WriteMsg(directResp)
		if len(r.Question) > 0 {
			RecordFlowAndSLO(dec.GroupID, dec.Action, "local", dns.RcodeToString[directResp.Rcode], 0.1)
		}
		return
	}

	upstream := "127.0.0.1:" + getInternalEnginePort()
	if snap != nil {
		if grp := snap.matchGroup(clientIP); grp != nil && len(grp.raw.Upstreams) > 0 {
			upstream = grp.raw.Upstreams[0]
			if !strings.Contains(upstream, ":") {
				upstream += ":53"
			}
		} else if up, ok := snap.clientUpstreams[clientIP]; ok && up != "" {
			upstream = up
			if !strings.Contains(upstream, ":") {
				upstream += ":53"
			}
		}
	}

	start := time.Now()
	c := new(dns.Client)
	c.Timeout = 4 * time.Second
	isTCP := (w.RemoteAddr() != nil && w.RemoteAddr().Network() == "tcp")
	if isTCP {
		c.Net = "tcp"
	}
	resp, _, err := c.Exchange(r, upstream)
	if err == nil && resp != nil && resp.Truncated && !isTCP {
		c.Net = "tcp"
		resp, _, err = c.Exchange(r, upstream)
	}
	durMs := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil || resp == nil {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(fail)
		RecordFlowAndSLO("", "error", upstream, "SERVFAIL", durMs)
		return
	}

	// CNAME Cloaking inspection on upstream answer
	if cloakedTarget, blocked := InspectUpstreamCNAMEs(resp, clientIP); blocked {
		slog.Info("CNAME cloaking blocked", "target", cloakedTarget, "client", clientIP)
		blockedMsg := buildBlockedReply(r, "")
		if snap != nil {
			blockedMsg = buildBlockedReply(r, snap.blockPageIP)
		}
		_ = w.WriteMsg(blockedMsg)
		RecordFlowAndSLO("", "cname_block", upstream, "NOERROR", durMs)
		return
	}

	_ = w.WriteMsg(resp)
	RecordFlowAndSLO("", "forward", upstream, dns.RcodeToString[resp.Rcode], durMs)
}

func extractRemoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func extractECSClientIP(r *dns.Msg) string {
	if r == nil {
		return ""
	}
	opt := r.IsEdns0()
	if opt == nil {
		return ""
	}
	for _, o := range opt.Option {
		if subnet, ok := o.(*dns.EDNS0_SUBNET); ok && subnet.Address != nil {
			return subnet.Address.String()
		}
	}
	return ""
}
