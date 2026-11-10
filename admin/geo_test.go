package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetRoutingZoneBlocks_NoACL(t *testing.T) {
	cfg := &Config{
		DNSSECEnabled:    true,
		FilteringEnabled: true,
		NextDNSProfileID: "2351bb",
		NextDNSReddit:    true,
		NextDNSYouTube:   true,
		BlockedCountries: []string{"CN", "RU"},
		BlockedClients:   []string{"1.2.3.4", "5.6.7.8"},
	}

	blocks := getRoutingZoneBlocks(cfg, "53", "853", "5553", true, "/ssl/cert.pem", "/ssl/key.pem")

	if strings.Contains(blocks, "acl {") {
		t.Errorf("Routing zone blocks must NOT contain duplicate ACL blocks! Found 'acl {' in output")
	}
	if strings.Contains(blocks, "block net") {
		t.Errorf("Routing zone blocks must NOT contain 'block net' rules! Found in output")
	}
	if !strings.Contains(blocks, "reddit.com:53 {") {
		t.Errorf("Expected reddit.com:53 zone block in output")
	}
}

func TestGetGeoACLRules_DeduplicationAndCapping(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shielddns_geo_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origCache := geoCacheDir
	geoCacheDir = tmpDir
	defer func() { geoCacheDir = origCache }()

	// Create a mock country zone with redundant and narrower subnets
	mockCN := strings.Join([]string{
		"1.0.0.0/16",   // Broad
		"1.0.1.0/24",   // Narrower (covered by /16, should be skipped)
		"1.0.2.0/24",   // Narrower (covered by /16, should be skipped)
		"2.0.0.0/8",    // Very broad
		"2.1.0.0/16",   // Narrower (covered by /8, should be skipped)
		"100.64.0.0/24",
	}, "\n")

	if err := os.WriteFile(filepath.Join(tmpDir, "cn.zone"), []byte(mockCN), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		BlockedCountries: []string{"cn"},
		BlockedClients:   []string{"192.168.1.50"},
	}

	rules := getGeoACLRules(cfg)

	if !strings.Contains(rules, "1.0.0.0/16") {
		t.Errorf("Expected broad prefix 1.0.0.0/16 in rules")
	}
	if !strings.Contains(rules, "2.0.0.0/8") {
		t.Errorf("Expected broad prefix 2.0.0.0/8 in rules")
	}
	if strings.Contains(rules, "1.0.1.0/24") {
		t.Errorf("Redundant subnet 1.0.1.0/24 should have been deduplicated")
	}
	if strings.Contains(rules, "2.1.0.0/16") {
		t.Errorf("Redundant subnet 2.1.0.0/16 should have been deduplicated")
	}
	if !strings.Contains(rules, "192.168.1.50") {
		t.Errorf("Manual client block 192.168.1.50 must be present")
	}
}
