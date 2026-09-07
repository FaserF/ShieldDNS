package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleClusterWorkerScript generates a ready-to-deploy Cloudflare Worker script
// tailored to the current cluster topology (Primary + Replicas) with universal geo-steering.
func handleClusterWorkerScript(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	role := config.ClusterRole
	primaryURL := config.ClusterPrimaryURL
	nodeName := config.ClusterNodeName
	adminDomain := config.AdminDomain
	replicas := append([]ClusterReplica{}, config.ClusterReplicas...)
	configLock.RUnlock()

	if primaryURL == "" {
		if adminDomain != "" {
			primaryURL = "https://" + adminDomain
		} else if r.Host != "" {
			primaryURL = "https://" + r.Host
		} else {
			primaryURL = "https://dns1.yourdomain.com"
		}
	}

	type WorkerNode struct {
		ID                  string   `json:"id"`
		Name                string   `json:"name"`
		URL                 string   `json:"url"`
		Role                string   `json:"role"`
		PreferredCountries  []string `json:"preferredCountries"`
		PreferredContinents []string `json:"preferredContinents"`
	}

	var nodes []WorkerNode

	if role == "primary" || role == "standalone" {
		primaryName := nodeName
		if primaryName == "" {
			primaryName = "Primary Node"
		}
		nodes = append(nodes, WorkerNode{
			ID:                  "primary",
			Name:                primaryName,
			URL:                 primaryURL,
			Role:                "primary",
			PreferredCountries:  []string{"DE", "AT", "CH", "NL", "FR"},
			PreferredContinents: []string{"EU"},
		})

		for idx, rep := range replicas {
			repID := fmt.Sprintf("node-%d", idx+1)
			repName := rep.Name
			if repName == "" {
				repName = fmt.Sprintf("Replica Node %d", idx+1)
			}
			repURL := rep.URL
			if repURL == "" {
				repURL = fmt.Sprintf("https://dns%d.yourdomain.com", idx+2)
			}
			nodes = append(nodes, WorkerNode{
				ID:                  repID,
				Name:                repName,
				URL:                 repURL,
				Role:                "secondary",
				PreferredCountries:  []string{"TR", "GR", "US", "GB"},
				PreferredContinents: []string{"EU", "AS", "NA"},
			})
		}
	} else {
		// Replica node view
		nodes = append(nodes, WorkerNode{
			ID:                  "primary",
			Name:                "Primary Node",
			URL:                 primaryURL,
			Role:                "primary",
			PreferredCountries:  []string{"DE", "AT", "CH", "NL", "FR"},
			PreferredContinents: []string{"EU"},
		})
		localURL := "https://" + r.Host
		localName := nodeName
		if localName == "" {
			localName = "Secondary Node"
		}
		nodes = append(nodes, WorkerNode{
			ID:                  "secondary",
			Name:                localName,
			URL:                 localURL,
			Role:                "secondary",
			PreferredCountries:  []string{"DE", "AT", "CH"},
			PreferredContinents: []string{"EU"},
		})
	}

	nodesJSON, err := json.MarshalIndent(nodes, "  ", "  ")
	if err != nil {
		http.Error(w, "Failed to marshal node topology", http.StatusInternalServerError)
		return
	}

	script := CloudflareWorkerScriptTemplate
	if script == "" {
		http.Error(w, "Worker template not found", http.StatusInternalServerError)
		return
	}

	// Dedicated API Token for Worker according to Principle of Least Privilege (proxy:worker)
	var workerTokenSecret string
	configLock.Lock()
	const workerKeyName = "Cloudflare Worker Dispatcher"

	// Check if already configured and valid
	if config.ClusterWorkerToken != "" {
		expectedHash := hashToken(config.ClusterWorkerToken)
		for _, k := range config.APIKeys {
			if k.TokenHash == expectedHash && len(k.Permissions) == 1 && k.Permissions[0] == "proxy:worker" {
				workerTokenSecret = config.ClusterWorkerToken
				break
			}
		}
	}

	// If no existing valid token found, generate new on button click and persist
	if workerTokenSecret == "" {
		workerTokenSecret = generateToken()
		config.ClusterWorkerToken = workerTokenSecret
		newKey := APIKey{
			ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
			Name:        workerKeyName,
			TokenHash:   hashToken(workerTokenSecret),
			Permissions: []string{"proxy:worker"},
			CreatedAt:   time.Now(),
		}
		config.APIKeys = append(config.APIKeys, newKey)
		_ = saveConfigNoLock()
	}
	configLock.Unlock()

	script = strings.ReplaceAll(script, "__NODES_CONFIG_JSON__", string(nodesJSON))
	script = strings.ReplaceAll(script, "__WORKER_SHARED_SECRET__", workerTokenSecret)

	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"worker.js\"")
	w.Write([]byte(script))
}

