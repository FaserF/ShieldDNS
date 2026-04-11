// Category: Configuration Tests
// Tests for loading configuration, blocklist downloading, parsing adblock/hosts
// formats, and handling config environments.
package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
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
	processList(&list, blockMap, allowMap)

	if len(blockMap) != 100 {
		t.Errorf("expected 100 domains, got %d", len(blockMap))
	}

	if _, ok := blockMap["adservice0.com"]; !ok {
		t.Errorf("adservice0.com not found in blockMap")
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

	processList(&list, blockMap, allowMap)

	if _, ok := allowMap["good-site.com"]; !ok {
		t.Errorf("allowlist parsing failed, good-site.com not in allowMap")
	}

	if _, ok := blockMap["bad-site.com"]; !ok {
		t.Errorf("blocklist parsing failed for mixed list")
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
