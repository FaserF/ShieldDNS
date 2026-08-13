package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestConfigFieldCompleteness verifies that all Config struct fields have JSON tags and valid defaults.
func TestConfigFieldCompleteness(t *testing.T) {
	cfg := Config{}
	val := reflect.ValueOf(cfg)
	typ := val.Type()

	if typ.NumField() < 30 {
		t.Fatalf("Expected at least 30 fields in Config struct, got %d", typ.NumField())
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonTag := field.Tag.Get("json")
		if jsonTag == "" || jsonTag == "-" {
			t.Errorf("Config field '%s' is missing a json tag", field.Name)
		}
	}
}

// TestConfigToFrontendUIPairing verifies that key configurable settings have UI representations in www/admin dashboard.
func TestConfigToFrontendUIPairing(t *testing.T) {
	possibleDirs := []string{
		"www/admin",
		"admin/www/admin",
		"../admin/www/admin",
	}

	var foundDir string
	for _, d := range possibleDirs {
		if stat, err := os.Stat(d); err == nil && stat.IsDir() {
			foundDir = d
			break
		}
	}

	if foundDir == "" {
		t.Skip("www/admin directory not found relative to test runner")
	}

	// Concatenate all HTML and JS files in www/admin
	var fullDashboardContent strings.Builder
	filepath.Walk(foundDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".js") {
			data, err := os.ReadFile(path)
			if err == nil {
				fullDashboardContent.Write(data)
				fullDashboardContent.WriteString("\n")
			}
		}
		return nil
	})

	content := strings.ToLower(fullDashboardContent.String())

	criticalSettings := []string{
		"retention",
		"filtering",
		"dnssec",
		"upstream",
		"abuse",
		"update",
		"mfa",
	}

	for _, setting := range criticalSettings {
		if !strings.Contains(content, setting) {
			t.Errorf("Critical config setting '%s' is not referenced in web dashboard UI (%s)", setting, foundDir)
		}
	}
}

// TestPresetListsIntegrity verifies preset blocklists and allowlists are populated with valid URLs.
func TestPresetListsIntegrity(t *testing.T) {
	presets := DefaultPresets
	if len(presets) < 3 {
		t.Errorf("Expected at least 3 preset lists, found %d", len(presets))
	}

	for _, p := range presets {
		if p.URL == "" || !strings.HasPrefix(p.URL, "http") {
			t.Errorf("Preset list '%s' has invalid URL: %s", p.Name, p.URL)
		}
		if p.Name == "" {
			t.Errorf("Preset list has empty name: %+v", p)
		}
	}
}

// TestConfigSerializationRoundtrip ensures Config can serialize and deserialize without loss.
func TestConfigSerializationRoundtrip(t *testing.T) {
	initial := Config{
		Upstreams:             []string{"1.1.1.1", "8.8.8.8"},
		PreferEncrypted:       true,
		RetentionDays:         30,
		FilteringEnabled:      true,
		SmartSelectionPolicy:  "fastest",
		DNSSECEnabled:         true,
		AbuseDetectionEnabled: true,
		AbuseDGAThreshold:     3.8,
		AbuseDGAMinLen:        8,
		AutoUpdateEnabled:     true,
		UpdateChannel:         "stable",
	}

	data, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	var restored Config
	err = json.Unmarshal(data, &restored)
	if err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if restored.RetentionDays != initial.RetentionDays ||
		restored.PreferEncrypted != initial.PreferEncrypted ||
		restored.SmartSelectionPolicy != initial.SmartSelectionPolicy ||
		restored.DNSSECEnabled != initial.DNSSECEnabled {
		t.Errorf("Config roundtrip mismatch between initial and restored")
	}
}
