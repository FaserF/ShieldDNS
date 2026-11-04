// Category: Configuration Tests
// Tests for loading configuration, blocklist downloading, parsing adblock/hosts
// formats, and handling config environments.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessList_StreamingMemoryEfficiency(t *testing.T) {
	// Create a mock server generating a list of domains
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "# Blocklist")
		for i := 0; i < 100; i++ {
			fmt.Fprintf(w, "||adservice%d.com^\n", i)
		}
	}))
	defer ts.Close()

	list := List{
		Name:    "TestList",
		URL:     ts.URL,
		Enabled: true,
	}

	blockMap := make(map[string][]string)
	allowMap := make(map[string]struct{})

	// Should not crash and should parse correctly
	processList(&list, blockMap, allowMap, nil)

	// We expect 200: for each || rule we add the domain AND the *.domain wildcard
	if len(blockMap) != 200 {
		t.Errorf("expected 200 domains, got %d", len(blockMap))
	}

	if _, ok := blockMap["adservice0.com"]; !ok {
		t.Errorf("adservice0.com not found in blockMap")
	}

	if _, ok := blockMap["*.adservice0.com"]; !ok {
		t.Errorf("*.adservice0.com wildcard not found in blockMap")
	}

	if lists := blockMap["adservice0.com"]; len(lists) != 1 || lists[0] != "TestList" {
		t.Errorf("attribution incorrect: %v", lists)
	}
}

func TestProcessList_AllowlistSupport(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "@@||good-site.com^")
		fmt.Fprintln(w, "0.0.0.0 bad-site.com")
	}))
	defer ts.Close()

	list := List{
		Name:    "MixedList",
		URL:     ts.URL,
		Enabled: true,
	}

	blockMap := make(map[string][]string)
	allowMap := make(map[string]struct{})

	processList(&list, blockMap, allowMap, nil)

	if _, ok := allowMap["good-site.com"]; !ok {
		t.Errorf("allowlist parsing failed, good-site.com not in allowMap")
	}

	if _, ok := blockMap["bad-site.com"]; !ok {
		t.Errorf("blocklist parsing failed for mixed list")
	}
}

func TestProcessList_AdGuardSyntax(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "||adservice.org^$important,dnstype=A")
		fmt.Fprintln(w, "@@||friendly-domain.com^$important")
		fmt.Fprintln(w, "||ignored-badfilter.com^$badfilter")
		fmt.Fprintln(w, "|https://secure-tracker.com/")
		fmt.Fprintln(w, "malware-domain.net^")
	}))
	defer ts.Close()

	list := List{
		Name:    "AdGuardTestList",
		URL:     ts.URL,
		Enabled: true,
	}

	blockMap := make(map[string][]string)
	allowMap := make(map[string]struct{})

	processList(&list, blockMap, allowMap, nil)

	if _, ok := blockMap["adservice.org"]; !ok {
		t.Errorf("expected adservice.org in blockMap")
	}
	if _, ok := blockMap["*.adservice.org"]; !ok {
		t.Errorf("expected *.adservice.org in blockMap")
	}
	if _, ok := allowMap["friendly-domain.com"]; !ok {
		t.Errorf("expected friendly-domain.com in allowMap")
	}
	if _, ok := blockMap["ignored-badfilter.com"]; ok {
		t.Errorf("expected ignored-badfilter.com to be excluded due to $badfilter")
	}
	if _, ok := blockMap["secure-tracker.com"]; !ok {
		t.Errorf("expected secure-tracker.com in blockMap")
	}
	if _, ok := blockMap["malware-domain.net"]; !ok {
		t.Errorf("expected malware-domain.net in blockMap")
	}
}

func TestLoadConfig_BlockPageIPEnv(t *testing.T) {
	// Simulate initial startup by removing any existing config
	os.Remove(ConfigPath)

	t.Setenv("BLOCK_PAGE_IP", "192.168.1.100")
	loadConfig()

	configLock.RLock()
	defer configLock.RUnlock()

	if config.BlockPageIP != "192.168.1.100" {
		t.Errorf("expected BlockPageIP 192.168.1.100 from ENV, got %s", config.BlockPageIP)
	}
}

func TestApplyCurrentRules_NoIPv6BlackholeForCustomMappings(t *testing.T) {
	origCombined := CombinedHostsPath
	origMappings := MappingsPath
	tmpDir := t.TempDir()
	CombinedHostsPath = filepath.Join(tmpDir, "shielddns.hosts")
	MappingsPath = filepath.Join(tmpDir, "mappings.hosts")
	defer func() {
		CombinedHostsPath = origCombined
		MappingsPath = origMappings
	}()

	mappings := map[string]string{
		"jellyfin.tailnet.fabiseitz.de": "100.64.0.1",
		"ipv6.local":                    "2001:db8::1",
	}

	applyCurrentRules(make(map[string][]string), make(map[string][]string), make(map[string]struct{}), mappings, "127.0.0.1", false)

	combinedData, err := os.ReadFile(CombinedHostsPath)
	if err != nil {
		t.Fatalf("Failed to read CombinedHostsPath: %v", err)
	}
	content := string(combinedData)

	if !strings.Contains(content, "100.64.0.1 jellyfin.tailnet.fabiseitz.de") {
		t.Errorf("Expected IPv4 mapping for jellyfin, got:\n%s", content)
	}
	if strings.Contains(content, ":: jellyfin.tailnet.fabiseitz.de") {
		t.Errorf("Did not expect synthesized :: mapping for IPv4 custom mapping, got:\n%s", content)
	}
	if strings.Contains(content, ":: ipv6.local") {
		t.Errorf("Did not expect synthesized :: mapping for native IPv6 mapping")
	}
}

func TestApplyCurrentRules_SynthesizeIPv6ForBlocklist(t *testing.T) {
	origCombined := CombinedHostsPath
	origBlocklist := BlocklistPath
	tmpDir := t.TempDir()
	CombinedHostsPath = filepath.Join(tmpDir, "shielddns.hosts")
	BlocklistPath = filepath.Join(tmpDir, "blocklist.hosts")
	defer func() {
		CombinedHostsPath = origCombined
		BlocklistPath = origBlocklist
	}()

	blockAttribution := map[string][]string{
		"adservice.google.com": {"AdGuard"},
	}

	applyCurrentRules(blockAttribution, make(map[string][]string), make(map[string]struct{}), nil, "0.0.0.0", false)

	combinedData, err := os.ReadFile(CombinedHostsPath)
	if err != nil {
		t.Fatalf("Failed to read CombinedHostsPath: %v", err)
	}
	content := string(combinedData)

	if !strings.Contains(content, "0.0.0.0 adservice.google.com") {
		t.Errorf("Expected IPv4 block record for adservice.google.com, got:\n%s", content)
	}
	if !strings.Contains(content, ":: adservice.google.com") {
		t.Errorf("Expected IPv6 synthesized record (::) for adservice.google.com, got:\n%s", content)
	}
}

func TestProcessList_CosmeticAndFallbackParsing(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Cosmetic rules and exceptions that should NEVER be parsed as domains
		fmt.Fprintln(w, "chefkoch.de#@#.ad-unit")
		fmt.Fprintln(w, "spiegel.de,heise.de##.header-ad")
		fmt.Fprintln(w, "bild.de#?#.article-banner")
		fmt.Fprintln(w, "zeit.de#$#.paywall-fix")
		fmt.Fprintln(w, "golem.de#%#//scriptlet('prevent-ad')")
		fmt.Fprintln(w, "focus.de$$div[class='ad']")
		// Real valid rules
		fmt.Fprintln(w, "0.0.0.0 real-ad.com # trailing comment")
		fmt.Fprintln(w, "||tracker.com^")
		fmt.Fprintln(w, "bad-domain.net")
	}))
	defer ts.Close()

	list := List{
		Name:    "CosmeticTestList",
		URL:     ts.URL,
		Enabled: true,
	}

	blockMap := make(map[string][]string)
	allowMap := make(map[string]struct{})

	processList(&list, blockMap, allowMap, nil)

	for _, domain := range []string{"chefkoch.de", "spiegel.de", "heise.de", "bild.de", "zeit.de", "golem.de", "focus.de"} {
		if _, ok := blockMap[domain]; ok {
			t.Errorf("Cosmetic rule domain '%s' was incorrectly added to blockMap!", domain)
		}
	}

	if _, ok := blockMap["real-ad.com"]; !ok {
		t.Errorf("Expected real-ad.com to be parsed")
	}
	if _, ok := blockMap["tracker.com"]; !ok {
		t.Errorf("Expected tracker.com to be parsed")
	}
	if _, ok := blockMap["bad-domain.net"]; !ok {
		t.Errorf("Expected bad-domain.net to be parsed")
	}
}

func TestProcessList_BrowserModifiersAndPathSkipped(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Browser-scoped rules that must NOT be converted to DNS rules
		fmt.Fprintln(w, "doubleclick.net^$domain=video.sport1.de")
		fmt.Fprintln(w, "securepubads.g.doubleclick.net/gpt/pubads_impl_*.js$domain=gamestar.de")
		fmt.Fprintln(w, "ib.adnxs.com/ptv$domain=tele5.de")
		fmt.Fprintln(w, "g.doubleclick.net/gampad/adx?*/sparta/*&t=ad_type%3Dtoolbar%26$document,subdocument,domain=wetter.com,badfilter")
		fmt.Fprintln(w, "banner.gif$image,script")
		// Valid DNS rules
		fmt.Fprintln(w, "@@||valid-whitelist.org^")
		fmt.Fprintln(w, "||valid-block.com^")
	}))
	defer ts.Close()

	list := List{
		Name:    "BrowserScopeList",
		URL:     ts.URL,
		Enabled: true,
	}

	blockMap := make(map[string][]string)
	allowMap := make(map[string]struct{})

	processList(&list, blockMap, allowMap, nil)

	// Verify browser-scoped rules were discarded
	for _, domain := range []string{"doubleclick.net", "securepubads.g.doubleclick.net", "ib.adnxs.com", "g.doubleclick.net", "banner.gif"} {
		if _, ok := allowMap[domain]; ok {
			t.Errorf("Browser-scoped rule '%s' was incorrectly added to allowMap!", domain)
		}
		if _, ok := blockMap[domain]; ok {
			t.Errorf("Browser-scoped rule '%s' was incorrectly added to blockMap!", domain)
		}
	}

	// Verify valid DNS rules were retained
	if _, ok := allowMap["valid-whitelist.org"]; !ok {
		t.Errorf("Expected valid-whitelist.org to be in allowMap")
	}
	if _, ok := blockMap["valid-block.com"]; !ok {
		t.Errorf("Expected valid-block.com to be in blockMap")
	}
}

func TestIsLocalOrTailnetHost(t *testing.T) {
	tests := []struct {
		host     string
		expected bool
	}{
		{"localhost", true},
		{"localhost:9443", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8090", true},
		{"::1", true},
		{"shielddns.local", true},
		{"router.local", true},
		{"ha.tailnet.fabiseitz.de", true},
		{"oracle-vm.tailnet.fabiseitz.de:9443", true},
		{"100.64.0.1:9443", true},
		{"100.64.0.2", true},
		{"100.127.255.254", true},
		{"192.168.1.100:443", true},
		{"10.0.0.5", true},
		{"172.16.0.1", true},
		{"google.com", false},
		{"attacker.com:9443", false},
		{"100.128.0.1", false},
	}

	for _, tt := range tests {
		got := isLocalOrTailnetHost(tt.host)
		if got != tt.expected {
			t.Errorf("isLocalOrTailnetHost(%q) = %v; want %v", tt.host, got, tt.expected)
		}
	}
}

func TestNormalizeDomain_RobustURLAndSlashHandling(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"www.communicationads.net/", "www.communicationads.net"},
		{"https://www.communicationads.net/deal/123", "www.communicationads.net"},
		{"http://mydealz.digidip.net/?clickref=abc", "mydealz.digidip.net"},
		{"mydealz.digidip.net:443", "mydealz.digidip.net"},
		{"*.digidip.net", "*.digidip.net"},
		{"SHOULD-LOWERCASE.COM", "should-lowercase.com"},
		{"/etc/passwd", ""},
		{"../../../etc/shadow", ""},
		{"invalid domain with spaces.com", ""},
	}

	for _, tt := range tests {
		got := NormalizeDomain(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeDomain(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestApplyCurrentRules_SubdomainAllowPruningWildcard(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shielddns-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	oldCombined := CombinedHostsPath
	oldBlocklist := BlocklistPath
	oldAllowlist := AllowlistPath
	oldMappings := MappingsPath
	CombinedHostsPath = filepath.Join(tmpDir, "combined.hosts")
	BlocklistPath = filepath.Join(tmpDir, "blocklist.hosts")
	AllowlistPath = filepath.Join(tmpDir, "allowlist.hosts")
	MappingsPath = filepath.Join(tmpDir, "mappings.hosts")
	defer func() {
		CombinedHostsPath = oldCombined
		BlocklistPath = oldBlocklist
		AllowlistPath = oldAllowlist
		MappingsPath = oldMappings
	}()

	// Simulate blocklist with parent apex and wildcard
	attribution := map[string][]string{
		"digidip.net":        {"TestBlocklist"},
		"*.digidip.net":      {"TestBlocklist"},
		"static.digidip.net": {"TestBlocklist"},
		"other-bad.com":      {"TestBlocklist"},
	}
	allowAttr := make(map[string][]string)

	// User specifically allowlists subdomain "mydealz.digidip.net"
	allowSet := map[string]struct{}{
		"mydealz.digidip.net":   {},
		"*.mydealz.digidip.net": {},
	}

	applyCurrentRules(attribution, allowAttr, allowSet, nil, "0.0.0.0", false)

	// Parent wildcard must be removed to avoid masking allowlisted subdomain in CoreDNS
	if _, ok := attribution["*.digidip.net"]; ok {
		t.Errorf("Conflicting wildcard '*.digidip.net' was NOT pruned from attribution!")
	}

	// Apex domain and explicit subdomains must remain blocked
	if _, ok := attribution["digidip.net"]; !ok {
		t.Errorf("Apex domain 'digidip.net' was unexpectedly removed from attribution")
	}
	if _, ok := attribution["static.digidip.net"]; !ok {
		t.Errorf("Explicit subdomain 'static.digidip.net' was unexpectedly removed from attribution")
	}

	// Read generated hosts file
	contentBytes, err := os.ReadFile(CombinedHostsPath)
	if err != nil {
		t.Fatalf("failed to read generated hosts file: %v", err)
	}
	content := string(contentBytes)

	if strings.Contains(content, "*.digidip.net") {
		t.Errorf("Generated hosts file contains '*.digidip.net' which blocks allowlisted subdomain")
	}
	if strings.Contains(content, "mydealz.digidip.net") {
		t.Errorf("Generated hosts file unexpectedly blocked 'mydealz.digidip.net'")
	}
	if !strings.Contains(content, "0.0.0.0 digidip.net") {
		t.Errorf("Generated hosts file missing '0.0.0.0 digidip.net'")
	}
}
