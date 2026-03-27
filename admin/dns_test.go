package main

import (
	"testing"
	"time"
)

// TestParseLogLine_Structured tests the new structured CoreDNS log format parser.
func TestParseLogLine_Structured(t *testing.T) {
	statsLock.Lock()
	stats.TotalQueries = 0
	stats.BlockedQueries = 0
	stats.QueryTypes = make(map[string]int64)
	statsLock.Unlock()

	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// Test allowed query in default CoreDNS format
	parseLogLine(`[INFO] plugin/log: 127.0.0.1:46111 - 10 "A IN google.com. udp 512 false 512" NOERROR qr,rd,ra 512 0.00123s`)

	bufferLock.Lock()
	length := len(logBuffer)
	var q Query
	if length > 0 {
		q = logBuffer[0]
	}
	bufferLock.Unlock()

	if length != 1 {
		t.Fatalf("Expected 1 query in buffer, got %d", length)
	}
	if q.ClientIP != "127.0.0.1" {
		t.Errorf("Expected ClientIP 127.0.0.1, got %s", q.ClientIP)
	}
	if q.Type != "A" {
		t.Errorf("Expected Type A, got %s", q.Type)
	}
	if q.Domain != "google.com" {
		t.Errorf("Expected Domain google.com, got %s", q.Domain)
	}
	if q.Status != "Allowed" {
		t.Errorf("Expected Status Allowed, got %s", q.Status)
	}
	// 0.00123s = 1.23ms
	if q.DurationMs < 1.2 || q.DurationMs > 1.4 {
		t.Errorf("Expected Duration ~1.23ms, got %f", q.DurationMs)
	}
}

func TestParseLogLine_Blocked(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	statsLock.Lock()
	stats.BlockedQueries = 0
	statsLock.Unlock()

	// qr,aa flags = blocked (local hosts file match)
	parseLogLine(`10.0.0.5:1234 - 11 "AAAA IN tiktok.com. udp 512 false 512" NOERROR qr,aa 512 0.05s`)

	bufferLock.Lock()
	length := len(logBuffer)
	var q Query
	if length > 0 {
		q = logBuffer[0]
	}
	bufferLock.Unlock()

	if length != 1 {
		t.Fatalf("Expected 1 query in buffer, got %d", length)
	}
	if q.Domain != "tiktok.com" {
		t.Errorf("Expected tiktok.com, got %s", q.Domain)
	}
	if q.Status != "Blocked" {
		t.Errorf("Expected Blocked, got %s", q.Status)
	}
	// 0.05s = 50ms
	if q.DurationMs < 49.9 || q.DurationMs > 50.1 {
		t.Errorf("Expected Duration ~50ms, got %f", q.DurationMs)
	}
}

func TestParseLogLine_ShortLine(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// A line with fewer than 6 fields should be ignored
	parseLogLine(`just a short line`)

	bufferLock.Lock()
	length := len(logBuffer)
	bufferLock.Unlock()

	if length != 0 {
		t.Errorf("expected 0 queries for short line, got %d", length)
	}
}

func TestParseLogLine_SSEBroadcast(t *testing.T) {
	ch := make(chan Query, 1)
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
	}()

	parseLogLine(`192.168.1.10:4321 - 12 "A IN example.com. udp 512 false 512" NOERROR qr,rd 512 0.001s`)

	select {
	case q := <-ch:
		if q.Domain != "example.com" {
			t.Errorf("expected example.com in SSE broadcast, got %s", q.Domain)
		}
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for SSE broadcast")
	}
}

func TestParseLogLine_InvalidLogs(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// 1. Startup message - Should be ignored (too short)
	parseLogLine(`maxprocs: Honoring GOMAXPROCS="4" as set in environment`)

	bufferLock.Lock()
	length := len(logBuffer)
	bufferLock.Unlock()

	if length != 0 {
		t.Errorf("expected 0 queries for invalid/non-matching logs, got %d", length)
	}
}
