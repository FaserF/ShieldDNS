package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AuditEntry represents a tamper-evident security audit record.
type AuditEntry struct {
	Seq       int64  `json:"seq"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	RemoteIP  string `json:"remote_ip"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
}

var (
	auditLock   sync.Mutex
	auditMemLog []AuditEntry
)

func initAuditLogTable() {
	if db == nil {
		return
	}
	ddl := `CREATE TABLE IF NOT EXISTS audit_log (
		seq INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		actor TEXT NOT NULL,
		remote_ip TEXT NOT NULL,
		action TEXT NOT NULL,
		target TEXT NOT NULL,
		detail TEXT NOT NULL,
		prev_hash TEXT NOT NULL,
		entry_hash TEXT NOT NULL
	)`
	if dbDriver == "postgres" {
		ddl = `CREATE TABLE IF NOT EXISTS audit_log (
			seq SERIAL PRIMARY KEY,
			timestamp TEXT NOT NULL,
			actor TEXT NOT NULL,
			remote_ip TEXT NOT NULL,
			action TEXT NOT NULL,
			target TEXT NOT NULL,
			detail TEXT NOT NULL,
			prev_hash TEXT NOT NULL,
			entry_hash TEXT NOT NULL
		)`
	}
	_, _ = dbExec(ddl)
}

func computeAuditHash(prevHash string, seq int64, ts, actor, remoteIP, action, target, detail string) string {
	payload := fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s|%s", prevHash, seq, ts, actor, remoteIP, action, target, detail)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}

// RecordAuditEvent appends a hash-chained security audit entry.
func RecordAuditEvent(r *http.Request, action, target, detail string) {
	actor := "system"
	remoteIP := "127.0.0.1"
	if r != nil {
		remoteIP = extractRemoteIPFromRequest(r)
		if r.Header.Get("X-API-Key") != "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			actor = "api_key"
		} else if _, err := r.Cookie(CookieName); err == nil {
			actor = "admin"
		} else {
			actor = "anonymous"
		}
	}
	RecordAuditEventExplicit(actor, remoteIP, action, target, detail)
}

// RecordAuditEventExplicit appends a hash-chained audit entry with explicit actor & IP.
func RecordAuditEventExplicit(actor, remoteIP, action, target, detail string) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	auditLock.Lock()
	defer auditLock.Unlock()

	if db == nil {
		seq := int64(len(auditMemLog) + 1)
		prevHash := strings.Repeat("0", 64)
		if len(auditMemLog) > 0 {
			prevHash = auditMemLog[len(auditMemLog)-1].EntryHash
		}
		entryHash := computeAuditHash(prevHash, seq, ts, actor, remoteIP, action, target, detail)
		auditMemLog = append(auditMemLog, AuditEntry{
			Seq:       seq,
			Timestamp: ts,
			Actor:     actor,
			RemoteIP:  remoteIP,
			Action:    action,
			Target:    target,
			Detail:    detail,
			PrevHash:  prevHash,
			EntryHash: entryHash,
		})
		return
	}

	initAuditLogTable()
	var prevHash string
	var lastSeq int64
	row := dbQueryRow("SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
	if row != nil {
		if err := row.Scan(&lastSeq, &prevHash); err != nil {
			prevHash = strings.Repeat("0", 64)
			lastSeq = 0
		}
	} else {
		prevHash = strings.Repeat("0", 64)
	}
	nextSeq := lastSeq + 1
	entryHash := computeAuditHash(prevHash, nextSeq, ts, actor, remoteIP, action, target, detail)
	_, _ = dbExec(
		"INSERT INTO audit_log (seq, timestamp, actor, remote_ip, action, target, detail, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		nextSeq, ts, actor, remoteIP, action, target, detail, prevHash, entryHash,
	)
}

// VerifyAuditChain validates the entire hash chain and returns (valid, count, errorMessage).
func VerifyAuditChain() (bool, int, string) {
	auditLock.Lock()
	defer auditLock.Unlock()

	expectedPrev := strings.Repeat("0", 64)
	if db == nil {
		for _, e := range auditMemLog {
			if e.PrevHash != expectedPrev {
				return false, len(auditMemLog), fmt.Sprintf("prev_hash mismatch at seq %d", e.Seq)
			}
			calc := computeAuditHash(e.PrevHash, e.Seq, e.Timestamp, e.Actor, e.RemoteIP, e.Action, e.Target, e.Detail)
			if calc != e.EntryHash {
				return false, len(auditMemLog), fmt.Sprintf("entry_hash mismatch at seq %d", e.Seq)
			}
			expectedPrev = e.EntryHash
		}
		return true, len(auditMemLog), ""
	}

	initAuditLogTable()
	rows, err := dbQuery("SELECT seq, timestamp, actor, remote_ip, action, target, detail, prev_hash, entry_hash FROM audit_log ORDER BY seq ASC")
	if err != nil {
		return false, 0, err.Error()
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.Seq, &e.Timestamp, &e.Actor, &e.RemoteIP, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.EntryHash); err != nil {
			return false, count, err.Error()
		}
		count++
		if e.PrevHash != expectedPrev {
			return false, count, fmt.Sprintf("prev_hash mismatch at seq %d", e.Seq)
		}
		calc := computeAuditHash(e.PrevHash, e.Seq, e.Timestamp, e.Actor, e.RemoteIP, e.Action, e.Target, e.Detail)
		if calc != e.EntryHash {
			return false, count, fmt.Sprintf("entry_hash mismatch at seq %d", e.Seq)
		}
		expectedPrev = e.EntryHash
	}
	return true, count, ""
}

func extractRemoteIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

func handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	auditLock.Lock()
	defer auditLock.Unlock()

	entries := []AuditEntry{}
	if db == nil {
		start := len(auditMemLog) - limit
		if start < 0 {
			start = 0
		}
		for i := len(auditMemLog) - 1; i >= start; i-- {
			entries = append(entries, auditMemLog[i])
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
		return
	}

	initAuditLogTable()
	rows, err := dbQuery("SELECT seq, timestamp, actor, remote_ip, action, target, detail, prev_hash, entry_hash FROM audit_log ORDER BY seq DESC LIMIT ?", limit)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e AuditEntry
			if err := rows.Scan(&e.Seq, &e.Timestamp, &e.Actor, &e.RemoteIP, &e.Action, &e.Target, &e.Detail, &e.PrevHash, &e.EntryHash); err == nil {
				entries = append(entries, e)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

func handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	valid, count, msg := VerifyAuditChain()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   valid,
		"entries": count,
		"error":   msg,
	})
}
