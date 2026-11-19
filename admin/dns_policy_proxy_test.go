package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPolicyProxy_GroupsSchedulesLocalRecordsAndCNAMECloaking(t *testing.T) {
	// Save and restore global config
	configLock.Lock()
	orig := config
	config = Config{
		FilteringEnabled:     true,
		CNAMECloakingEnabled: true,
		AutoPTR:              true,
		BlockPageIP:          "10.0.0.5",
		Groups: []ClientGroup{
			{
				ID:            "kids",
				Name:          "Kids VLAN",
				Members:       []string{"192.168.50.0/24", "10.10.10.2"},
				CustomBlocked: []string{"badgame.com"},
				CustomAllowed: []string{"allowed-kid.org"},
				FilterAAAA:    true,
				ScheduleIDs:   []string{"bedtime"},
			},
		},
		Schedules: []ScheduleRule{
			{
				ID:        "bedtime",
				Name:      "Bedtime",
				StartTime: "22:00",
				EndTime:   "07:00",
				Timezone:  "UTC",
				Action:    "block_all",
				Enabled:   true,
			},
		},
		LocalRecords: []LocalRecord{
			{ID: "r1", Domain: "nas.home.arpa", Type: "A", Value: "192.168.1.50", TTL: 120},
			{ID: "r2", Domain: "files.home.arpa", Type: "CNAME", Value: "nas.home.arpa"},
			{ID: "r3", Domain: "home.arpa", Type: "TXT", Value: "v=spf1 -all"},
			{ID: "r4", Domain: "home.arpa", Type: "MX", Value: "mail.home.arpa", Priority: 10},
			{ID: "r5", Domain: "_ldap._tcp.home.arpa", Type: "SRV", Value: "dc.home.arpa", Priority: 0, Weight: 100, Port: 389},
		},
		ClientRules: []ClientRule{
			{Domain: "tiktok.com", ClientIP: "192.168.1.99", IsAllowlist: false},
		},
		QuickRules: []QuickRule{
			{ID: "q1", Domain: "/^ad[0-9]+\\.tracker\\.net$/", IsAllowlist: false, CreatedAt: time.Now()},
		},
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = orig
		configLock.Unlock()
		ReloadPolicySnapshot()
	}()

	// Compile snapshot at 12:00 UTC (outside bedtime schedule)
	midday := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	configLock.RLock()
	snap := compilePolicySnapshot(config.Clone(), midday)
	configLock.RUnlock()
	policySnapshotPtr.Store(snap)

	// 1. Local A + Auto-PTR
	reqA := new(dns.Msg)
	reqA.SetQuestion("nas.home.arpa.", dns.TypeA)
	resp, dec := EvaluateDNSQuery(reqA, "192.168.1.10")
	if resp == nil || dec.Action != "local" || len(resp.Answer) != 1 {
		t.Fatalf("expected local A record, got resp=%v dec=%+v", resp, dec)
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(net.ParseIP("192.168.1.50")) {
		t.Fatalf("unexpected A answer: %+v", resp.Answer[0])
	}

	reqPTR := new(dns.Msg)
	reqPTR.SetQuestion("50.1.168.192.in-addr.arpa.", dns.TypePTR)
	resp, dec = EvaluateDNSQuery(reqPTR, "192.168.1.10")
	if resp == nil || dec.Action != "local" || len(resp.Answer) != 1 {
		t.Fatalf("expected AutoPTR response, got resp=%v dec=%+v", resp, dec)
	}

	// 2. Local CNAME / TXT / MX / SRV
	for _, tc := range []struct {
		name  string
		qtype uint16
	}{
		{"files.home.arpa.", dns.TypeCNAME},
		{"home.arpa.", dns.TypeTXT},
		{"home.arpa.", dns.TypeMX},
		{"_ldap._tcp.home.arpa.", dns.TypeSRV},
	} {
		m := new(dns.Msg)
		m.SetQuestion(tc.name, tc.qtype)
		r, d := EvaluateDNSQuery(m, "192.168.1.10")
		if r == nil || d.Action != "local" || len(r.Answer) == 0 {
			t.Fatalf("expected local record for %s (%d), got r=%v d=%+v", tc.name, tc.qtype, r, d)
		}
	}

	// 3. Group matching & FilterAAAA
	reqAAAA := new(dns.Msg)
	reqAAAA.SetQuestion("example.com.", dns.TypeAAAA)
	resp, dec = EvaluateDNSQuery(reqAAAA, "192.168.50.25")
	if resp == nil || dec.GroupID != "kids" || dec.Action != "block" {
		t.Fatalf("expected kids FilterAAAA block, got resp=%v dec=%+v", resp, dec)
	}

	// 4. ClientRule enforcement
	reqCR := new(dns.Msg)
	reqCR.SetQuestion("tiktok.com.", dns.TypeA)
	resp, dec = EvaluateDNSQuery(reqCR, "192.168.1.99")
	if resp == nil || dec.Action != "block" {
		t.Fatalf("expected ClientRule block for 192.168.1.99, got dec=%+v", dec)
	}

	// 5. Regex QuickRule
	reqRx := new(dns.Msg)
	reqRx.SetQuestion("ad42.tracker.net.", dns.TypeA)
	resp, dec = EvaluateDNSQuery(reqRx, "192.168.1.10")
	if resp == nil || dec.Action != "block" {
		t.Fatalf("expected regex quick rule block, got dec=%+v", dec)
	}

	// 6. Overnight schedule check at 23:30 UTC
	night := time.Date(2026, 11, 18, 23, 30, 0, 0, time.UTC)
	configLock.RLock()
	nightSnap := compilePolicySnapshot(config.Clone(), night)
	configLock.RUnlock()
	policySnapshotPtr.Store(nightSnap)

	reqBed := new(dns.Msg)
	reqBed.SetQuestion("google.com.", dns.TypeA)
	resp, dec = EvaluateDNSQuery(reqBed, "192.168.50.25")
	if resp == nil || dec.Action != "block" || dec.ScheduleID != "bedtime" {
		t.Fatalf("expected bedtime schedule block at 23:30, got dec=%+v", dec)
	}

	// 7. CNAME Cloaking inspection
	blockAttributionLock.Lock()
	blockAttribution["cloaked.tracker.example"] = []string{"TestList"}
	blockAttributionLock.Unlock()
	defer func() {
		blockAttributionLock.Lock()
		delete(blockAttribution, "cloaked.tracker.example")
		blockAttributionLock.Unlock()
	}()

	upstreamResp := new(dns.Msg)
	upstreamResp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "metrics.mysite.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: "sub.cloaked.tracker.example.",
		},
	}
	target, blocked := InspectUpstreamCNAMEs(upstreamResp, "192.168.1.10")
	if !blocked || target != "sub.cloaked.tracker.example" {
		t.Fatalf("expected CNAME cloaking detection, got blocked=%v target=%q", blocked, target)
	}

	// 8. Built-in and domain FilterAAAA suppression (mitigates IPv6 PMTU stalls)
	for _, aaaaDom := range []string{"daily-cloudcode-pa.googleapis.com.", "preview.redd.it.", "i.redd.it.", "www.reddit.com."} {
		reqTest := new(dns.Msg)
		reqTest.SetQuestion(aaaaDom, dns.TypeAAAA)
		resp, dec = EvaluateDNSQuery(reqTest, "192.168.1.10")
		if resp == nil || dec.Action != "block" || dec.Reason != "FilterAAAA enabled" {
			t.Fatalf("expected %s FilterAAAA suppression, got resp=%v dec=%+v", aaaaDom, resp, dec)
		}
		if len(resp.Answer) != 0 || resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("expected empty NOERROR for %s FilterAAAA suppression, got rcode=%d ancount=%d", aaaaDom, resp.Rcode, len(resp.Answer))
		}
	}
}
