package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func initDB() {
	var err error
	os.MkdirAll(filepath.Dir(DBPath), 0755)
	db, err = sql.Open("sqlite", DBPath)
	if err != nil {
		log.Fatalf("Fatal: Could not open database: %v", err)
	}

	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		CREATE TABLE IF NOT EXISTS queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME,
			domain TEXT,
			type TEXT,
			status TEXT,
			client_ip TEXT,
			is_cache_hit BOOLEAN DEFAULT 0,
			duration_ms REAL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON queries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_status ON queries(status);
		CREATE INDEX IF NOT EXISTS idx_client ON queries(client_ip);
		CREATE TABLE IF NOT EXISTS clients (
			ip TEXT PRIMARY KEY,
			user_agent TEXT,
			last_seen DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip);
	`)
	if err != nil {
		log.Fatalf("Fatal: Could not initialize database schema: %v", err)
	}

	// Migrations for existing databases
	db.Exec("ALTER TABLE queries ADD COLUMN is_cache_hit BOOLEAN DEFAULT 0")
	db.Exec("ALTER TABLE queries ADD COLUMN duration_ms REAL DEFAULT 0")
}

func startDBWorker() {
	ticker := time.NewTicker(24 * time.Hour)
	cleanup := func() {
		configLock.RLock()
		days := config.RetentionDays
		configLock.RUnlock()

		if days <= 0 {
			days = 30
		}

		if db != nil {
			_, err := db.Exec("DELETE FROM queries WHERE timestamp < datetime('now', ?)", fmt.Sprintf("-%d days", days))
			if err != nil {
				log.Printf("Error purging old queries: %v", err)
			} else {
				log.Printf("Database maintenance: Queries older than %d days purged.", days)
			}
		}
	}

	go cleanup() // Initial cleanup
	for range ticker.C {
		cleanup()
	}
}

func startLogWorker() {
	// Periodically flush buffered queries to SQLite
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		bufferLock.Lock()
		if len(logBuffer) == 0 {
			bufferLock.Unlock()
			continue
		}
		toFlush := logBuffer
		logBuffer = nil
		bufferLock.Unlock()

		if db == nil {
			continue
		}
		flushLogs(toFlush)
	}
}

func flushLogs(toFlush []Query) {
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting log transaction: %v", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO queries (timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("Error preparing log statement: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, q := range toFlush {
		_, err = stmt.Exec(q.Time.Format(time.RFC3339), q.Domain, q.Type, q.Status, q.ClientIP, q.IsCacheHit, q.DurationMs)
		if err != nil {
			log.Printf("Error executing log statement: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing log transaction: %v", err)
	}
}

func initializeStatsFromDB() {
	if db == nil {
		return
	}

	statsLock.Lock()
	defer statsLock.Unlock()

	// 1. Total, Blocked, Cache Hits and Latency (last 24h)
	var total, blocked, cacheHits int64
	var avgLatency float64
	row := db.QueryRow(`
		SELECT 
			COUNT(*), 
			COALESCE(SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_cache_hit = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(AVG(CASE WHEN duration_ms > 0 THEN duration_ms ELSE NULL END), 0)
		FROM queries 
		WHERE timestamp > datetime('now', '-24 hours')
	`)
	row.Scan(&total, &blocked, &cacheHits, &avgLatency)
	stats.TotalQueries = total
	stats.BlockedQueries = blocked
	stats.CacheHits = cacheHits
	stats.AverageLatency = avgLatency

	// 2. Populate History (bars for chart)
	historyLock.Lock()
	defer historyLock.Unlock()

	// Reset history
	for i := range history {
		history[i] = HourStats{}
	}

	rows, err := db.Query(`
		SELECT 
			(23 - (strftime('%H', 'now') - strftime('%H', timestamp) + 24) % 24) as hour_index,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE timestamp > datetime('now', '-24 hours')
		GROUP BY hour_index
	`)

	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var idx int
			var hTotal, hBlocked int64
			if err := rows.Scan(&idx, &hTotal, &hBlocked); err == nil {
				if idx >= 0 && idx < 24 {
					history[idx] = HourStats{Total: hTotal, Blocked: hBlocked}
				}
			}
		}
	} else {
		log.Printf("Error initializing history from DB: %v", err)
	}
	
	log.Printf("Statistics initialized from database: %d total queries, %d blocked, avg latency %.2fms", stats.TotalQueries, stats.BlockedQueries, stats.AverageLatency)
}

func getClientStats(ip string) (ClientStats, error) {
	var cs ClientStats
	cs.QueryTypes = make(map[string]int64)
	cs.Timeline = make([]HourStats, 24)

	if db == nil {
		return cs, fmt.Errorf("DB not initialized")
	}

	// 1. Total and Blocked (24h)
	row := db.QueryRow(`
		SELECT 
			COUNT(*), 
			COALESCE(SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END), 0)
		FROM queries 
		WHERE client_ip = ? AND timestamp > datetime('now', '-24 hours')
	`, ip)
	if err := row.Scan(&cs.Total, &cs.Blocked); err != nil {
		return cs, err
	}

	// 2. Query Types (24h)
	rows, err := db.Query(`
		SELECT type, COUNT(*) 
		FROM queries 
		WHERE client_ip = ? AND timestamp > datetime('now', '-24 hours')
		GROUP BY type
	`, ip)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var qType string
			var count int64
			if err := rows.Scan(&qType, &count); err == nil {
				cs.QueryTypes[qType] = count
			}
		}
	}

	// 3. Timeline (24h)
	tRows, err := db.Query(`
		SELECT 
			(23 - (strftime('%H', 'now') - strftime('%H', timestamp) + 24) % 24) as hour_index,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE client_ip = ? AND timestamp > datetime('now', '-24 hours')
		GROUP BY hour_index
	`, ip)
	if err == nil {
		defer tRows.Close()
		for tRows.Next() {
			var idx int
			var hTotal, hBlocked int64
			if err := tRows.Scan(&idx, &hTotal, &hBlocked); err == nil {
				if idx >= 0 && idx < 24 {
					cs.Timeline[idx] = HourStats{Total: hTotal, Blocked: hBlocked}
				}
			}
		}
	}

	return cs, nil
}

func getClientTopBlocked(ip string, limit int) ([]DomainCount, error) {
	var results []DomainCount
	if db == nil {
		return results, fmt.Errorf("DB not initialized")
	}

	rows, err := db.Query(`
		SELECT domain, COUNT(*) as c
		FROM queries
		WHERE client_ip = ? AND status = 'Blocked' AND timestamp > datetime('now', '-24 hours')
		GROUP BY domain
		ORDER BY c DESC
		LIMIT ?
	`, ip, limit)

	if err != nil {
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		var dc DomainCount
		if err := rows.Scan(&dc.Domain, &dc.Count); err == nil {
			results = append(results, dc)
		}
	}

	return results, nil
}

func saveClientUA(ip, ua string) {
	if db == nil || ip == "" || ua == "" {
		return
	}
	// Upsert: Try to insert, update if exists
	_, err := db.Exec(`
		INSERT INTO clients (ip, user_agent, last_seen) 
		VALUES (?, ?, datetime('now'))
		ON CONFLICT(ip) DO UPDATE SET 
			user_agent = CASE WHEN excluded.user_agent != '' THEN excluded.user_agent ELSE clients.user_agent END,
			last_seen = datetime('now')
	`, ip, ua)
	if err != nil {
		log.Printf("Error saving client UA: %v", err)
	}
}

func getClientUA(ip string) string {
	if db == nil || ip == "" {
		return ""
	}
	var ua string
	err := db.QueryRow("SELECT user_agent FROM clients WHERE ip = ?", ip).Scan(&ua)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("Error getting client UA: %v", err)
		}
		return ""
	}
	return ua
}
