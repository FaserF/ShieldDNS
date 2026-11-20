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
	cnameCloaking     bool
	filteringEnabled  bool
	filterAAAA        bool
	filterAAAADomains []string
	blockPageIP       string
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
		cnameCloaking:     cfg.CNAMECloakingEnabled,
		filteringEnabled:  cfg.FilteringEnabled,
		filterAAAA:        cfg.FilterAAAA,
		filterAAAADomains: append([]string(nil), cfg.FilterAAAADomains...),
		blockPageIP:       cfg.BlockPageIP,
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

func (s *PolicySnapshot) matchFilterAAAADomain(qName string) bool {
	if s == nil {
		return false
	}
	clean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qName)), ".")
	if clean == "" {
		return false
	}
	// Built-in mitigation for Google Cloud Code / Antigravity / Gemini Code Assist endpoints,
	// Google OAuth / APIs / assets, YouTube playback, and Reddit CDN / Fastly endpoints which suffer from IPv6 PMTU stalls on residential WAN
	if clean == "google.com" || strings.HasSuffix(clean, ".google.com") ||
		clean == "gstatic.com" || strings.HasSuffix(clean, ".gstatic.com") ||
		clean == "googleapis.com" || strings.HasSuffix(clean, ".googleapis.com") ||
		clean == "googleusercontent.com" || strings.HasSuffix(clean, ".googleusercontent.com") ||
		clean == "google" || strings.HasSuffix(clean, ".google") ||
		clean == "gvt1.com" || strings.HasSuffix(clean, ".gvt1.com") ||
		clean == "gvt2.com" || strings.HasSuffix(clean, ".gvt2.com") ||
		clean == "ggpht.com" || strings.HasSuffix(clean, ".ggpht.com") ||
		clean == "youtube.com" || strings.HasSuffix(clean, ".youtube.com") ||
		clean == "youtu.be" || strings.HasSuffix(clean, ".youtu.be") ||
		clean == "googlevideo.com" || strings.HasSuffix(clean, ".googlevideo.com") ||
		clean == "reddit.com" || strings.HasSuffix(clean, ".reddit.com") ||
		clean == "redd.it" || strings.HasSuffix(clean, ".redd.it") ||
		clean == "redditmedia.com" || strings.HasSuffix(clean, ".redditmedia.com") ||
		clean == "redditstatic.com" || strings.HasSuffix(clean, ".redditstatic.com") {
		return true
	}
	for _, d := range s.filterAAAADomains {
		cd := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*."), ".")
		if cd != "" && (clean == cd || strings.HasSuffix(clean, "."+cd)) {
			return true
		}
	}
	return false
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
			refused.RecursionAvailable = r.RecursionDesired
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
		fail.RecursionAvailable = r.RecursionDesired
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
