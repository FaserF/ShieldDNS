package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

type WebhookPayload struct {
	Event     string                 `json:"event"`
	Title     string                 `json:"title"`
	Node      string                 `json:"node"`
	Timestamp string                 `json:"timestamp"`
	Details   map[string]interface{} `json:"details"`
}

type webhookJob struct {
	targetURL string
	authToken string
	payload   WebhookPayload
}

var (
	webhookDedupeMu   sync.Mutex
	webhookLastFired  = make(map[string]time.Time)
	webhookClient     = &http.Client{Timeout: 5 * time.Second}
	webhookQueueOnce  sync.Once
	webhookQueue      = make(chan webhookJob, 64)
	webhookCooldownMu sync.Mutex
	webhookCooldowns  = make(map[string]time.Time)
)

func startWebhookWorker() {
	webhookQueueOnce.Do(func() {
		go func() {
			for job := range webhookQueue {
				deliverWebhookJob(job)
			}
		}()
	})
}

func deliverWebhookJob(job webhookJob) {
	if !isValidRedirectUrl(job.targetURL) {
		slog.Warn("Rejected invalid or unsafe webhook target URL", "url", job.targetURL)
		return
	}

	webhookCooldownMu.Lock()
	if until, ok := webhookCooldowns[job.targetURL]; ok && time.Now().Before(until) {
		webhookCooldownMu.Unlock()
		return
	}
	webhookCooldownMu.Unlock()

	body, err := json.Marshal(job.payload)
	if err != nil {
		slog.Error("Failed to marshal webhook payload", "error", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.targetURL, bytes.NewReader(body))
	if err != nil {
		slog.Error("Failed to create webhook request", "error", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	if job.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+job.authToken)
	}

	resp, err := webhookClient.Do(req)
	if err != nil {
		webhookCooldownMu.Lock()
		webhookCooldowns[job.targetURL] = time.Now().Add(60 * time.Second)
		webhookCooldownMu.Unlock()
		slog.Warn("Failed to deliver security webhook", "url", job.targetURL, "event", job.payload.Event, "error", err)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		slog.Warn("Security webhook rejected", "url", job.targetURL, "status", resp.StatusCode)
	} else {
		slog.Info("Delivered security webhook", "event", job.payload.Event, "node", job.payload.Node)
	}
}

// SendSecurityWebhook sends an asynchronous HTTP POST webhook to the configured webhook_url.
// Alerts are debounced per event+key to prevent alert storms.
func SendSecurityWebhook(event string, title string, details map[string]interface{}) {
	configLock.RLock()
	enabled := config.WebhookEnabled
	url := config.WebhookURL
	token := config.WebhookToken
	node := config.ClusterNodeName
	configLock.RUnlock()

	// Check environment variable fallback
	if url == "" {
		url = os.Getenv("WEBHOOK_URL")
		if url != "" {
			enabled = true
		}
	}
	if token == "" {
		token = os.Getenv("WEBHOOK_TOKEN")
	}

	if !enabled || url == "" || !isValidRedirectUrl(url) {
		return
	}

	if node == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			node = h
		} else {
			node = "shielddns"
		}
	}

	// Debounce check: max 1 notification per 30 seconds for same event+target
	dedupeKey := event
	if ip, ok := details["client_ip"].(string); ok && ip != "" {
		dedupeKey += ":" + ip
	} else if target, ok := details["target"].(string); ok && target != "" {
		dedupeKey += ":" + target
	} else if domain, ok := details["domain"].(string); ok && domain != "" {
		dedupeKey += ":" + domain
	}

	now := time.Now()
	webhookDedupeMu.Lock()
	if last, ok := webhookLastFired[dedupeKey]; ok && now.Sub(last) < 30*time.Second {
		webhookDedupeMu.Unlock()
		return
	}
	webhookLastFired[dedupeKey] = now

	// Clean up old entries if map grows large
	if len(webhookLastFired) > 500 {
		cutoff := now.Add(-5 * time.Minute)
		for k, t := range webhookLastFired {
			if t.Before(cutoff) {
				delete(webhookLastFired, k)
			}
		}
	}
	webhookDedupeMu.Unlock()

	payload := WebhookPayload{
		Event:     event,
		Title:     title,
		Node:      node,
		Timestamp: now.UTC().Format(time.RFC3339),
		Details:   details,
	}

	go func(targetURL, authToken string, p WebhookPayload) {
		if !isValidRedirectUrl(targetURL) {
			slog.Warn("Rejected invalid or unsafe webhook target URL", "url", targetURL)
			return
		}

		body, err := json.Marshal(p)
		if err != nil {
			slog.Error("Failed to marshal webhook payload", "error", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
		if err != nil {
			slog.Error("Failed to create webhook request", "error", err)
			return
		}

		req.Header.Set("Content-Type", "application/json")
		if authToken != "" {
			req.Header.Set("Authorization", "Bearer "+authToken)
		}

		resp, err := webhookClient.Do(req)
		if err != nil {
			slog.Warn("Failed to deliver security webhook", "url", targetURL, "event", p.Event, "error", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			slog.Warn("Security webhook rejected", "url", targetURL, "status", resp.StatusCode)
		} else {
			slog.Info("Delivered security webhook", "event", p.Event, "node", p.Node)
		}
	}(url, token, payload)
}
