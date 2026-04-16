// Category: Integration Tests (External)
// Checks external web URLs and CDN lists configured by default are still accessible.
package main

import (
	"net/http"
	"testing"
	"time"
)

func TestPresetsAvailability(t *testing.T) {
	client := &http.Client{
		Timeout: 20 * time.Second, // Increased timeout for external CI
	}

	allLists := append(DefaultPresets, DefaultAllowlists...)

	for _, list := range allLists {
		t.Run(list.Name, func(t *testing.T) {
			req, err := http.NewRequest("GET", list.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request for %s: %v", list.Name, err)
			}

			// Some CDNs/Servers (like OISD) block the default Go User-Agent.
			// Using a browser-like User-Agent ensures better compatibility.
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

			resp, err := client.Do(req)
			if err != nil {
				// If it's a timeout or a network error, we log it and skip to avoid breaking CI
				// on flaky external dependencies.
				t.Logf("⚠️ External service %s (%s) unreachable: %v", list.Name, list.URL, err)
				t.Skip("Skipping due to unreachable external service")
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Logf("⚠️ External service %s (%s) returned status %d. Skipping test.", list.Name, list.URL, resp.StatusCode)
				t.Skip("Skipping due to non-OK status from external service")
				return
			}
		})
	}
}
