package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

func closeDB() {
	if db != nil {
		db.Close()
		db = nil
	}
}

func initDB() {
	var err error
	os.MkdirAll(filepath.Dir(DBPath), 0755)
	db, err = sql.Open("sqlite", DBPath+"?_busy_timeout=10000")
	if err != nil {
		slog.Error("Could not open database", "path", DBPath, "error", err)
		os.Exit(1)
	}

	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA cache_size=-64000;
		PRAGMA mmap_size=268435456;
		PRAGMA temp_store=MEMORY;
		PRAGMA busy_timeout=10000;
		PRAGMA auto_vacuum=INCREMENTAL;
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
		CREATE INDEX IF NOT EXISTS idx_domain ON queries(domain);
		CREATE INDEX IF NOT EXISTS idx_timestamp_status ON queries(timestamp, status);
		CREATE INDEX IF NOT EXISTS idx_queries_client_ts ON queries(client_ip, timestamp);
		CREATE INDEX IF NOT EXISTS idx_queries_domain_ts ON queries(domain, timestamp);
		CREATE TABLE IF NOT EXISTS clients (
			ip TEXT PRIMARY KEY,
			user_agent TEXT,
			last_seen DATETIME
		);
		CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip);
		CREATE TABLE IF NOT EXISTS hourly_stats (
			timestamp DATETIME PRIMARY KEY,
			total INTEGER DEFAULT 0,
			blocked INTEGER DEFAULT 0,
			cache_hits INTEGER DEFAULT 0
		);
		PRAGMA incremental_vacuum;
	`)
	if err != nil {
		slog.Error("Could not initialize database schema", "error", err)
		os.Exit(1)
	}

	// Migrations for existing databases
	addColumnIfNotExists("queries", "is_cache_hit", "BOOLEAN DEFAULT 0")
	addColumnIfNotExists("queries", "duration_ms", "REAL DEFAULT 0")
}

func addColumnIfNotExists(table, column, definition string) {
	// Check if column exists
	query := fmt.Sprintf("PRAGMA table_info(%s)", table)
	rows, err := db.Query(query)
	if err != nil {
		slog.Error("Error checking table info", "table", table, "error", err)
		return
	}
	defer rows.Close()

	exists := false
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull, pk int
		var dfltValue interface{}
		rows.Scan(&cid, &name, &dtype, &notnull, &dfltValue, &pk)
		if name == column {
			exists = true
			break
		}
	}

	if !exists {
		alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
		_, err := db.Exec(alterQuery)
		if err != nil {
			slog.Error("Error adding column", "table", table, "column", column, "error", err)
		} else {
			slog.Info("Database Migration: Added column", "table", table, "column", column)
		}
	}
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
				slog.Error("Error purging old queries", "error", err)
			} else {
				slog.Info("Database maintenance complete", "days_purged", days)

				// Reclaim space incrementally
				_, err = db.Exec("PRAGMA incremental_vacuum(1000)")
				if err != nil {
					slog.Error("Error running incremental vacuum", "error", err)
				} else {
					slog.Debug("Database maintenance: Incremental vacuum completed")
				}
			}
		}
	}

	go cleanup() // Initial cleanup
	
	// Start hourly aggregation ticker
	aggTicker := time.NewTicker(1 * time.Hour)
	go func() {
		// Initial aggregation for the previous hour
		aggregateHourlyStats()
		for range aggTicker.C {
			aggregateHourlyStats()
		}
	}()

	for range ticker.C {
		cleanup()
	}
}

func aggregateHourlyStats() {
	if db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Aggregate the full previous hour (e.g., if now is 14:05, aggregate 13:00-14:00)
	targetHour := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
	
	slog.Debug("Starting hourly aggregation", "hour", targetHour)

	_, err := db.ExecContext(ctx, `
		INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits)
		SELECT 
			strftime('%Y-%m-%d %H:00:00', timestamp) as hr,
			COUNT(*),
			SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END),
			SUM(CASE WHEN is_cache_hit = 1 THEN 1 ELSE 0 END)
		FROM queries
		WHERE datetime(timestamp) >= datetime(?, 'start of hour') 
		  AND datetime(timestamp) < datetime(?, 'start of hour', '+1 hour')
		GROUP BY hr
		ON CONFLICT(timestamp) DO UPDATE SET
			total = excluded.total,
			blocked = excluded.blocked,
			cache_hits = excluded.cache_hits
	`, targetHour, targetHour)

	if err != nil {
		slog.Error("Error aggregating hourly stats", "hour", targetHour, "error", err)
	} else {
		slog.Info("Successfully aggregated hourly stats", "hour", targetHour)
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
		slog.Error("Error starting log transaction", "error", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO queries (timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		slog.Error("Error preparing log statement", "error", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, q := range toFlush {
		_, err = stmt.Exec(q.Time.UTC().Format("2006-01-02 15:04:05"), q.Domain, q.Type, q.Status, q.ClientIP, q.IsCacheHit, q.DurationMs)
		if err != nil {
			slog.Error("Error executing log statement", "domain", q.Domain, "error", err)
		}
		// Record Prometheus Metrics
		RecordQuery(q)
	}

	if err := tx.Commit(); err != nil {
		slog.Error("Error committing log transaction", "error", err)
	}
}

func initializeStatsFromDB() {
	if db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	statsLock.Lock()
	defer statsLock.Unlock()

	// 1. Total, Blocked, Cache Hits and Latency (last 24h)
	// Optimization: Use hourly_stats for the first 23 hours, and queries for the current hour
	var total, blocked, cacheHits int64
	var avgLatency float64

	// Current hour start
	curHour := time.Now().UTC().Truncate(time.Hour).Format("2006-01-02 15:04:05")

	// Get aggregated stats for the previous 23 hours
	row := db.QueryRowContext(ctx, `
		SELECT 
			COALESCE(SUM(total), 0), 
			COALESCE(SUM(blocked), 0),
			COALESCE(SUM(cache_hits), 0)
		FROM hourly_stats 
		WHERE timestamp > datetime('now', '-24 hours') AND timestamp < ?
	`, curHour)
	row.Scan(&total, &blocked, &cacheHits)

	// Get current hour's live stats and overall average latency
	var curTotal, curBlocked, curCacheHits int64
	row = db.QueryRowContext(ctx, `
		SELECT 
			COUNT(*), 
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_cache_hit = 1 THEN 1 ELSE 0 END), 0),
			COALESCE(AVG(CASE WHEN duration_ms > 0 THEN duration_ms ELSE NULL END), 0)
		FROM queries 
		WHERE timestamp >= ?
	`, curHour)
	row.Scan(&curTotal, &curBlocked, &curCacheHits, &avgLatency)

	stats.TotalQueries = total + curTotal
	stats.BlockedQueries = blocked + curBlocked
	stats.CacheHits = cacheHits + curCacheHits
	stats.AverageLatency = avgLatency
	stats.LastUpdate = time.Now()

	// 2. Populate History (bars for chart)
	historyLock.Lock()
	defer historyLock.Unlock()

	// Reset history
	for i := range history {
		history[i] = HourStats{}
	}

	rows, err := db.QueryContext(ctx, `
		SELECT 
			(23 - (strftime('%H', 'now') - strftime('%H', timestamp) + 24) % 24) as hour_index,
			total,
			blocked
		FROM hourly_stats
		WHERE timestamp > datetime('now', '-24 hours')
		UNION ALL
		SELECT
			23 as hour_index,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE timestamp >= ?
		GROUP BY hour_index
	`, curHour)

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
		slog.Error("Error initializing history from DB", "error", err)
	}

	// 3. Query Types (last 24h)
	if stats.QueryTypes == nil {
		stats.QueryTypes = make(map[string]int64)
	}
	tRows, err := db.QueryContext(ctx, `
		SELECT type, COUNT(*) 
		FROM queries 
		WHERE timestamp > datetime('now', '-24 hours')
		GROUP BY type
	`)
	if err == nil {
		defer tRows.Close()
		for tRows.Next() {
			var qt string
			var count int64
			if err := tRows.Scan(&qt, &count); err == nil {
				stats.QueryTypes[qt] = count
			}
		}
	} else {
		slog.Error("Error initializing query types from DB", "error", err)
	}

	slog.Info("Statistics initialized from database", "total", stats.TotalQueries, "blocked", stats.BlockedQueries)
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
		slog.Error("Error saving client UA", "ip", ip, "error", err)
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
			slog.Error("Error getting client UA", "ip", ip, "error", err)
		}
		return ""
	}
	return ua
}

func getDomainStats(domain string) (DomainStats, error) {
	var ds DomainStats
	if db == nil {
		return ds, fmt.Errorf("DB not initialized")
	}

	// 1. Total and Blocked (24h)
	row := db.QueryRow(`
		SELECT 
			COUNT(*), 
			COALESCE(SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END), 0)
		FROM queries 
		WHERE domain = ? AND timestamp > datetime('now', '-24 hours')
	`, domain)
	if err := row.Scan(&ds.Total, &ds.Blocked); err != nil {
		return ds, err
	}

	// 2. Count Unique Clients (24h)
	row = db.QueryRow(`
		SELECT COUNT(DISTINCT client_ip)
		FROM queries
		WHERE domain = ? AND timestamp > datetime('now', '-24 hours')
	`, domain)
	row.Scan(&ds.ClientsCount)

	return ds, nil
}

func getDomainClients(domain string, limit int) ([]ClientCount, error) {
	var results []ClientCount
	if db == nil {
		return results, fmt.Errorf("DB not initialized")
	}

	rows, err := db.Query(`
		SELECT client_ip, COUNT(*) as c
		FROM queries
		WHERE domain = ? AND timestamp > datetime('now', '-24 hours')
		GROUP BY client_ip
		ORDER BY c DESC
		LIMIT ?
	`, domain, limit)

	if err != nil {
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		var cc ClientCount
		if err := rows.Scan(&cc.IP, &cc.Count); err == nil {
			results = append(results, cc)
		}
	}

	return results, nil
}

func getAllClients() ([]map[string]interface{}, error) {
	var results []map[string]interface{}
	if db == nil {
		return results, fmt.Errorf("DB not initialized")
	}

	rows, err := db.Query("SELECT ip, user_agent, last_seen FROM clients ORDER BY last_seen DESC")
	if err != nil {
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		var ip, ua, lastSeen string
		if err := rows.Scan(&ip, &ua, &lastSeen); err == nil {
			results = append(results, map[string]interface{}{
				"ip":         ip,
				"user_agent": ua,
				"last_seen":  lastSeen,
			})
		}
	}

	return results, nil
}
