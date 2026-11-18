package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	siemChan         = make(chan Query, 2048)
	siemDroppedTotal atomic.Int64
	siemOnce         sync.Once
	siemHTTPClient   = &http.Client{Timeout: 5 * time.Second}
)

// StartSIEMSinks starts the background SIEM dispatcher and optional OTLP/HTTP metrics exporter.
func StartSIEMSinks(ctx context.Context) {
	siemOnce.Do(func() {
		go runSIEMDispatcher(ctx)
		go runOTLPExporter(ctx)
	})
}

func validateSinkTarget(target string, isFile bool) error {
	if isFile {
		// Ensure file path is within a designated safe directory
		// ShieldDNS default log directory or similar
		safeDir := "/var/log/shielddns/"
		// Ensure it's treated as absolute for security
		absPath, err := filepath.Abs(target)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(absPath, safeDir) {
			return fmt.Errorf("file path outside of safe directory: %s", target)
		}
		return nil
	}

	// For URL-based targets (SSRF protection)
	// Simple check, in production this should be a strict allowlist
	if strings.Contains(target, "://") {
		// Basic URL validation: ensure it's not a private IP or local host
		if IsPrivateOrTailnetIP(target) {
			return fmt.Errorf("target URL is a private IP")
		}
	}
	return nil
}

// EmitQueryToSIEM non-blockingly enqueues a Query to configured SIEM sinks.
func EmitQueryToSIEM(q Query) {
	configLock.RLock()
	hasSinks := false
	for _, s := range config.SIEMSinks {
		if s.Enabled && s.Target != "" {
			hasSinks = true
			break
		}
	}
	configLock.RUnlock()
	if !hasSinks {
		return
	}
	select {
	case siemChan <- q:
	default:
		siemDroppedTotal.Add(1)
	}
}

func runSIEMDispatcher(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var batch []Query
	flush := func() {
		if len(batch) == 0 {
			return
		}
		configLock.RLock()
		sinks := append([]SIEMSinkConfig(nil), config.SIEMSinks...)
		configLock.RUnlock()

		for _, s := range sinks {
			if !s.Enabled || s.Target == "" {
				continue
			}
			switch s.Type {
			case "file":
				writeFileSink(s.Target, batch)
			case "syslog":
				sendSyslogSink(s.Target, s.Protocol, batch)
			case "webhook":
				sendWebhookSink(s.Target, s.Token, batch)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case q := <-siemChan:
			batch = append(batch, q)
			if len(batch) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func writeFileSink(path string, batch []Query) {
	if err := validateSinkTarget(path, true); err != nil {
		slog.Error("SIEM file sink target invalid", "path", path, "error", err)
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		slog.Debug("SIEM file sink open failed", "path", path, "error", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, q := range batch {
		_ = enc.Encode(q)
	}
}

func formatRFC5424Syslog(q Query) string {
	b, _ := json.Marshal(q)
	return fmt.Sprintf("<14>1 %s shielddns dns-query - - - %s\n", q.Time.UTC().Format(time.RFC3339), string(b))
}

func sendSyslogSink(target, proto string, batch []Query) {
	if proto == "" {
		proto = "udp"
	}
	var conn net.Conn
	var err error
	if proto == "tls" {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", target, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = net.DialTimeout(proto, target, 3*time.Second)
	}
	if err != nil {
		slog.Debug("SIEM syslog sink dial failed", "target", target, "error", err)
		return
	}
	defer conn.Close()
	for _, q := range batch {
		_, _ = conn.Write([]byte(formatRFC5424Syslog(q)))
	}
}

func sendWebhookSink(targetURL, token string, batch []Query) {
	if err := validateSinkTarget(targetURL, false); err != nil {
		slog.Error("SIEM webhook sink target invalid", "url", targetURL, "error", err)
		return
	}
	var buf bytes.Buffer
	for _, q := range batch {
		b, err := json.Marshal(q)
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	req, err := http.NewRequest(http.MethodPost, targetURL, &buf)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if token != "" && token != "********" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := siemHTTPClient.Do(req)
	if err != nil {
		slog.Debug("SIEM webhook sink failed", "url", targetURL, "error", err)
		return
	}
	_ = resp.Body.Close()
}

func runOTLPExporter(ctx context.Context) {
	for {
		configLock.RLock()
		endpoint := config.OTLPEndpoint
		interval := config.OTLPIntervalSeconds
		configLock.RUnlock()

		if interval <= 0 {
			interval = 30
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}

		if endpoint == "" {
			continue
		}
		pushOTLPMetrics(endpoint)
	}
}

func pushOTLPMetrics(endpoint string) {
	if err := validateSinkTarget(endpoint, false); err != nil {
		slog.Error("OTLP exporter target invalid", "endpoint", endpoint, "error", err)
		return
	}
	statsLock.RLock()
	tot := stats.TotalQueries
	blk := stats.BlockedQueries
	hits := stats.CacheHits
	avgLat := stats.AverageLatency
	statsLock.RUnlock()

	nowNs := fmt.Sprintf("%d", time.Now().UnixNano())
	payload := map[string]interface{}{
		"resourceMetrics": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": []map[string]interface{}{
						{"key": "service.name", "value": map[string]string{"stringValue": "shielddns"}},
					},
				},
				"scopeMetrics": []map[string]interface{}{
					{
						"scope": map[string]string{"name": "shielddns.dns"},
						"metrics": []map[string]interface{}{
							{
								"name": "shielddns.queries.total",
								"sum": map[string]interface{}{
									"dataPoints":             []map[string]interface{}{{"asInt": fmt.Sprintf("%d", tot), "timeUnixNano": nowNs}},
									"isMonotonic":            true,
									"aggregationTemporality": 2,
								},
							},
							{
								"name": "shielddns.queries.blocked",
								"sum": map[string]interface{}{
									"dataPoints":             []map[string]interface{}{{"asInt": fmt.Sprintf("%d", blk), "timeUnixNano": nowNs}},
									"isMonotonic":            true,
									"aggregationTemporality": 2,
								},
							},
							{
								"name": "shielddns.queries.cache_hits",
								"sum": map[string]interface{}{
									"dataPoints":             []map[string]interface{}{{"asInt": fmt.Sprintf("%d", hits), "timeUnixNano": nowNs}},
									"isMonotonic":            true,
									"aggregationTemporality": 2,
								},
							},
							{
								"name": "shielddns.query.latency_ms",
								"gauge": map[string]interface{}{
									"dataPoints": []map[string]interface{}{{"asDouble": avgLat, "timeUnixNano": nowNs}},
								},
							},
						},
					},
				},
			},
		},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	target := bytes.TrimRight([]byte(endpoint), "/")
	url := string(target) + "/v1/metrics"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := siemHTTPClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}
