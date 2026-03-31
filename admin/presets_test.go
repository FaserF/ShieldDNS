package main

import (
	"net/http"
	"testing"
	"time"
)

func TestPresetsAvailability(t *testing.T) {
	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	allLists := append(DefaultPresets, DefaultAllowlists...)

	for _, list := range allLists {
		t.Run(list.Name, func(t *testing.T) {
			// Using GET instead of HEAD because some servers (like GitHub raw)
			// or CDNs might behave differently or block HEAD requests.
			// Plus we only need the first byte to verify availability.
			resp, err := client.Get(list.URL)
			if err != nil {
				t.Fatalf("Failed to reach %s (%s): %v", list.Name, list.URL, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s (%s) returned status %d", list.Name, list.URL, resp.StatusCode)
			}
		})
	}
}
