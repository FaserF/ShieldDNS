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

func TestApplyCurrentRules_SynthesizeIPv6ForCustomMappings(t *testing.T) {
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
	if !strings.Contains(content, ":: jellyfin.tailnet.fabiseitz.de") {
		t.Errorf("Expected synthesized :: mapping for jellyfin, got:\n%s", content)
	}
	if strings.Contains(content, ":: ipv6.local") {
		t.Errorf("Did not expect synthesized :: mapping for native IPv6 mapping")
	}
}
