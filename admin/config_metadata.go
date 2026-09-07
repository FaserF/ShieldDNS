package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	metadataCache   = make(map[string]List)
	metadataMu      sync.RWMutex
	commitDateCache = make(map[string]time.Time)
	commitDateMu    sync.RWMutex
)

// startMetadataUpdater periodically refreshes metadata for all lists and presets.
// Uses a 24h ticker for full refresh and a 1h ticker for missing information retries.
func startMetadataUpdater(ctx context.Context) {
	fullTicker := time.NewTicker(24 * time.Hour)
	missingTicker := time.NewTicker(1 * time.Hour)
	defer fullTicker.Stop()
	defer missingTicker.Stop()

	go func() {
		// Initial wait to let main startup finish
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		// Run once on startup
		refreshAllMetadata(false)

		for {
			select {
			case <-ctx.Done():
				return
			case <-fullTicker.C:
				refreshAllMetadata(false) // Full refresh
			case <-missingTicker.C:
				refreshAllMetadata(true) // Only missing metadata
			}
		}
	}()
}

func refreshAllMetadata(onlyMissing bool) {
	mode := "Full"
	if onlyMissing {
		mode = "Missing-Only"
	}
	slog.Info("Starting background metadata refresh", "mode", mode)

	configLock.RLock()
	allLists := append([]List{}, config.Lists...)
	allLists = append(allLists, config.Allowlists...)
	configLock.RUnlock()

	// Also include all presets
	allLists = append(allLists, DefaultPresets...)
	allLists = append(allLists, DefaultAllowlists...)

	// Deduplicate by URL
	uniqueURLs := make(map[string]List)
	for _, l := range allLists {
		uniqueURLs[l.URL] = l
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Concurrency limit

	for _, l := range uniqueURLs {
		// If onlyMissing is requested, skip lists that already have metadata
		if onlyMissing {
			metadataMu.RLock()
			cached, ok := metadataCache[l.URL]
			metadataMu.RUnlock()
			if ok && cached.Entries > 0 && !cached.RemoteUpdatedAt.IsZero() {
				continue
			}
		}

		wg.Add(1)
		go func(list List) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Local fallback check for official ShieldDNS lists
			useLocal := false
			var file *os.File
			var err error
			if strings.Contains(list.URL, "raw.githubusercontent.com/FaserF/ShieldDNS/") {
				parts := strings.Split(list.URL, "/official/")
				if len(parts) == 2 {
					switch parts[1] {
					case "allowlists/default.txt":
						file, err = os.Open("official/allowlists/default.txt")
						useLocal = true
					case "blocklists/default.txt":
						file, err = os.Open("official/blocklists/default.txt")
						useLocal = true
					case "blocklists/search-ads-hybrid.txt":
						file, err = os.Open("official/blocklists/search-ads-hybrid.txt")
						useLocal = true
					}
				}
			}

			if useLocal {
				if err == nil {
					defer file.Close()
					list.RemoteUpdatedAt = time.Now()
					if info, err := file.Stat(); err == nil {
						list.RemoteUpdatedAt = info.ModTime()
					}

					scanner := bufio.NewScanner(file)
					count := 0
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
							count++
						}
					}
					list.Entries = count

					metadataMu.Lock()
					metadataCache[list.URL] = list
					metadataMu.Unlock()
					return
				}
			}

			if !isValidListURL(list.URL) {
				slog.Warn("Metadata fetch skipped: not a safe remote URL", "url", list.URL)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			ua := fmt.Sprintf("ShieldDNS/%s (MetadataFetcher)", FullVersion)
			resp, err := fetchBlocklistURLWithContext(ctx, list.URL, ua, map[string]string{
				"Range": "bytes=0-102400", // Fetch first 100KB to estimate entries if needed
			})
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
				list.RemoteUpdatedAt = getRemoteUpdateTime(list.URL, resp.Header)

				// Quick entry estimate if entries are 0
				if list.Entries == 0 {
					scanner := bufio.NewScanner(resp.Body)
					count := 0
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
							count++
						}
					}
					list.Entries = count
				}

				metadataMu.Lock()
				metadataCache[list.URL] = list
				metadataMu.Unlock()
			}
		}(l)
	}
	wg.Wait()
	slog.Info("Background metadata refresh completed", "count", len(uniqueURLs))
}

// getRemoteUpdateTime attempts to find the best possible modification timestamp for a remote file.
func getRemoteUpdateTime(rawURL string, headers http.Header) time.Time {
	// 1. Standard HTTP header (static files)
	if lm := headers.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			return t
		}
	}

	// 2. Fallback to Date header - DISABLED
	// The Date header is just when the server sent the response, not when the file changed.
	// Returning empty time is better than a false "now" timestamp.
	/*
		if d := headers.Get("Date"); d != "" {
			if t, err := http.ParseTime(d); err == nil {
				return t
			}
		}
	*/

	// 3. Specialized support for GitHub Raw Content
	// raw.githubusercontent.com does not send Last-Modified, so we check the Commit API
	if strings.Contains(rawURL, "raw.githubusercontent.com") {
		// Return cached commit date if already known to avoid exhausting GitHub rate limits
		commitDateMu.RLock()
		if cachedDate, ok := commitDateCache[rawURL]; ok {
			commitDateMu.RUnlock()
			return cachedDate
		}
		commitDateMu.RUnlock()

		// URL: https://raw.githubusercontent.com/user/repo/branch/folder/file.txt
		parts := strings.Split(strings.TrimPrefix(rawURL, "https://"), "/")
		if len(parts) >= 5 {
			user := parts[1]
			repo := parts[2]
			branch := parts[3]
			path := strings.Join(parts[4:], "/")

			apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=%s&sha=%s&per_page=1", user, repo, path, branch)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			req.Header.Set("User-Agent", "ShieldDNS-Update-Tracker")

			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var commitInfo []struct {
						Commit struct {
							Committer struct {
								Date time.Time `json:"date"`
							} `json:"committer"`
						} `json:"commit"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&commitInfo); err == nil && len(commitInfo) > 0 {
						d := commitInfo[0].Commit.Committer.Date
						commitDateMu.Lock()
						commitDateCache[rawURL] = d
						commitDateMu.Unlock()
						return d
					}
				} else if resp.StatusCode == http.StatusForbidden {
					slog.Debug("GitHub API rate limited while fetching list metadata", "url", rawURL)
				}
			}
		}
	}

	// 4. Specialized support for GitLab Raw Content
	// gitlab.com does not send Last-Modified, so we check the Commits API
	if strings.Contains(rawURL, "gitlab.com") && (strings.Contains(rawURL, "/raw/") || strings.Contains(rawURL, "/-/raw/")) {
		// Example: https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter-hosts.txt
		// or https://gitlab.com/group/project/-/raw/ref/path/file.txt

		separator := "/raw/"
		if strings.Contains(rawURL, "/-/raw/") {
			separator = "/-/raw/"
		}

		parts := strings.Split(rawURL, separator)
		if len(parts) == 2 {
			// Extract project path (e.g. curben/urlhaus-filter)
			// Remove domain and any leading slashes
			projectPath := parts[0]
			for _, prefix := range []string{"https://gitlab.com/", "http://gitlab.com/", "gitlab.com/"} {
				projectPath = strings.TrimPrefix(projectPath, prefix)
			}
			projectPath = strings.Trim(projectPath, "/")

			refPath := parts[1]
			refParts := strings.Split(refPath, "/")
			if len(refParts) >= 2 {
				ref := refParts[0]
				filePath := strings.Join(refParts[1:], "/")

				// GitLab Project ID is the URL-encoded path
				projectID := url.PathEscape(projectPath)
				committedURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/commits?path=%s&ref_name=%s&per_page=1",
					projectID, url.PathEscape(filePath), url.PathEscape(ref))

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				req, _ := http.NewRequestWithContext(ctx, "GET", committedURL, nil)
				req.Header.Set("User-Agent", "ShieldDNS-Update-Tracker")

				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						var commitInfo []struct {
							CreatedAt time.Time `json:"created_at"`
						}
						if err := json.NewDecoder(resp.Body).Decode(&commitInfo); err == nil && len(commitInfo) > 0 {
							return commitInfo[0].CreatedAt
						}
					}
				}
			}
		}
	}

	return time.Time{}
}

// buildClusterConfigExport generates an export tailored for a replica, considering instance type.
