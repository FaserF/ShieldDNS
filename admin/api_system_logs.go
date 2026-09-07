package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)


func AddSystemLog(line string) {
	// Add timestamp for UI display if not present
	if !strings.HasPrefix(line, "[") {
		line = fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
	}

	systemLogLock.Lock()
	systemLogBuffer = append(systemLogBuffer, line)
	if len(systemLogBuffer) > 500 {
		systemLogBuffer = systemLogBuffer[1:]
	}
	// Notify clients
	clients := make([]chan string, 0, len(systemLogClients))
	for ch := range systemLogClients {
		clients = append(clients, ch)
	}
	systemLogLock.Unlock()

	for _, ch := range clients {
		select {
		case ch <- line:
		default:
		}
	}
}

var debugModeEnabled atomic.Bool

func DebugLog(msg string) {
	if debugModeEnabled.Load() {
		slog.Debug(msg)
	}
}

// SlogUIHandler is a custom slog.Handler that writes JSON to a writer
// and plain text to the ShieldDNS UI system log buffer.
type SlogUIHandler struct {
	jsonHandler slog.Handler
}

func NewSlogUIHandler(w io.Writer, opts *slog.HandlerOptions) *SlogUIHandler {
	return &SlogUIHandler{
		jsonHandler: slog.NewJSONHandler(w, opts),
	}
}

func (h *SlogUIHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.jsonHandler.Enabled(ctx, level)
}

func (h *SlogUIHandler) Handle(ctx context.Context, r slog.Record) error {
	// 1. Send to System UI Log (Human Readable)
	levelStr := ""
	if r.Level != slog.LevelInfo {
		levelStr = "[" + r.Level.String() + "] "
	}

	// Extract attributes for UI log
	attrs := ""
	r.Attrs(func(a slog.Attr) bool {
		attrs += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		return true
	})

	AddSystemLog(levelStr + r.Message + attrs)

	// 2. Pass to JSON Handler (Machine Readable)
	return h.jsonHandler.Handle(ctx, r)
}

func (h *SlogUIHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SlogUIHandler{jsonHandler: h.jsonHandler.WithAttrs(attrs)}
}

func (h *SlogUIHandler) WithGroup(name string) slog.Handler {
	return &SlogUIHandler{jsonHandler: h.jsonHandler.WithGroup(name)}
}

var noiseLogTracker sync.Map // IP -> lastLogTime

type LogWriter struct{}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	// Suppress noisy TLS and HTTP/2 handshake errors (e.g. from probes, bots, or premature client disconnects)
	// These are handled by the standard library but logged to the error log, creating unnecessary noise.
	isTLS := strings.Contains(msg, "http: TLS handshake error")
	isHTTP2 := strings.Contains(msg, "http2: server: error reading preface")

	if isTLS || isHTTP2 {
		noisePatterns := []string{
			"EOF",
			"i/o timeout",
			"connection reset by peer",
			"unknown certificate",
			"bad certificate",
			"bad record MAC",
			"remote error",
			"broken pipe",
		}

		isNoise := isHTTP2
		if !isNoise {
			for _, pattern := range noisePatterns {
				if strings.Contains(msg, pattern) {
					isNoise = true
					break
				}
			}
			// Additional specific handshake noise patterns
			if !isNoise && isTLS {
				extraNoise := []string{
					"client sent an HTTP request to an HTTPS server",
					"first record does not look like a TLS handshake",
					"unsupported SSLv2 handshake received",
					"client offered only unsupported versions",
					"client requested unsupported application protocols",
					"no cipher suite supported by both client and server",
					"missing signature_algorithms",
					"signature algorithms",
					"no key exchanges supported",
				}
				for _, pattern := range extraNoise {
					if strings.Contains(msg, pattern) {
						isNoise = true
						break
					}
				}
			}
		}

		if isNoise {
			// Extract IP from log message to allow automated blocking
			ip := extractIPFromLog(msg)

			if ip != "" {
				// Suppression: Only log once every 5 minutes per IP to avoid "log-flooding" by bots
				now := time.Now()
				if last, ok := noiseLogTracker.Load(ip); ok {
					if now.Sub(last.(time.Time)) < 5*time.Minute {
						// still allow auto-block check below, but skip the Info log
						goto blockCheck
					}
				}
				noiseLogTracker.Store(ip, now)

				// Log as Info with an English explanation as requested by the user
				slog.Info("[Bot/Scanner Activity] " + msg + " -- Note: This message is typically caused by automated scanners, bots, or interrupted connections. It does not indicate a problem with ShieldDNS.")
			}

		blockCheck:
			// Auto-block if Abuse Detection is enabled and it's not a critical IP
			if ip != "" {
				configLock.RLock()
				abuseEnabled := config.AbuseDetectionEnabled
				configLock.RUnlock()
				if abuseEnabled {
					go blockClientAuto(ip, "threat:bot_scanner")
				}
			}
			return len(p), nil
		}
	}

	slog.Info(msg)
	return len(p), nil
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if activeSSEClients.Load() >= 50 {
		http.Error(w, "Server busy: too many active streams", http.StatusServiceUnavailable)
		return
	}
	activeSSEClients.Add(1)
	defer activeSSEClients.Add(-1)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan string, 50)
	systemLogLock.Lock()
	systemLogClients[ch] = struct{}{}
	// Send existing history
	for _, line := range systemLogBuffer {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	systemLogLock.Unlock()

	defer func() {
		systemLogLock.Lock()
		delete(systemLogClients, ch)
		systemLogLock.Unlock()
	}()

	flusher, _ := w.(http.Flusher)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case line := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		case <-ticker.C:
			// Heartbeat comment to keep connection alive
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
func handleEvents(w http.ResponseWriter, r *http.Request) {
	if activeSSEClients.Load() >= 50 {
		http.Error(w, "Server busy: too many active streams", http.StatusServiceUnavailable)
		return
	}
	activeSSEClients.Add(1)
	defer activeSSEClients.Add(-1)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan Query, 500) // Increased buffer for high query volume
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
		DebugLog("SSE client disconnected")
	}()

	flusher, _ := w.(http.Flusher)
	flusher.Flush()
	DebugLog("SSE client connected")

	// Send initial ping to keep connection alive
	fmt.Fprintf(w, "data: {\"type\":\"ping\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case q := <-ch:
			data, _ := json.Marshal(q)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		case <-ticker.C:
			// Heartbeat comment to keep connection alive
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

