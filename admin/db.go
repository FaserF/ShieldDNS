package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
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

	// Performance Tuning: SQLite handles multiple readers in WAL mode,
	// but is limited to a single writer. For ShieldDNS, we use a single
	// open connection to eliminate SQLITE_BUSY contention across goroutines.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(1 * time.Hour)

	_, err = db.Exec(`
		PRAGMA busy_timeout=10000;
		PRAGMA journal_mode=WAL;
		PRAGMA synchronous=NORMAL;
		PRAGMA auto_vacuum=INCREMENTAL;
		CREATE TABLE IF NOT EXISTS queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME,
			domain TEXT,
			type TEXT,
			status TEXT,
			client_ip TEXT,
			is_cache_hit BOOLEAN DEFAULT 0,
			duration_ms REAL DEFAULT 0,
			country_code TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON queries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_status ON queries(status);
		CREATE INDEX IF NOT EXISTS idx_client ON queries(client_ip);
		CREATE INDEX IF NOT EXISTS idx_domain ON queries(domain);
		CREATE INDEX IF NOT EXISTS idx_timestamp_status ON queries(timestamp, status);
		CREATE INDEX IF NOT EXISTS idx_queries_client_ts ON queries(client_ip, timestamp);
		CREATE INDEX IF NOT EXISTS idx_queries_ts_client ON queries(timestamp, client_ip);
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
	addColumnIfNotExists("queries", "country_code", "TEXT")
}

// isValidSQLName checks if a string is a valid SQL table or column name.
func isValidSQLName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func addColumnIfNotExists(table, column, definition string) {
	if !isValidSQLName(table) || !isValidSQLName(column) {
		slog.Error("Database Migration: Invalid SQL name for migration", "table", table, "column", column)
		return
	}

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
		// table and column are validated above to be alphanum+_ only
		alterQuery := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
		_, err := db.Exec(alterQuery)
		if err != nil {
			slog.Error("Error adding column", "table", table, "column", column, "error", err)
		} else {
			slog.Info("Database Migration: Added column", "table", table, "column", column)
		}
	}
}

func startDBWorker(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	cleanup := func() {
		configLock.RLock()
		days := config.RetentionDays
		configLock.RUnlock()

		if db != nil {
			// 1. Regular TTL purge based on RetentionDays
			res, err := db.ExecContext(ctx, "DELETE FROM queries WHERE timestamp < datetime('now', ?)", fmt.Sprintf("-%d days", days))
			if err != nil {
				slog.Error("Error purging old queries", "error", err)
			} else {
				deleted, _ := res.RowsAffected()
				slog.Info("Database maintenance: TTL purge complete", "days_retained", days, "rows_deleted", deleted)
			}

			// 2. Resource Safety: Hard cap on total queries (max 500k rows)
			var totalRows int
			if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM queries").Scan(&totalRows); err == nil && totalRows > 500000 {
				overage := totalRows - 500000 + 50000
				res, err = db.ExecContext(ctx, "DELETE FROM queries WHERE id IN (SELECT id FROM queries ORDER BY timestamp ASC LIMIT ?)", overage)
				if err != nil {
					slog.Error("Database maintenance: Error during emergency row prune", "error", err)
				} else {
					deleted, _ := res.RowsAffected()
					slog.Warn("Database maintenance: Row cap exceeded, emergency prune performed", "total_before", totalRows, "deleted", deleted)
				}
			}

			// 3. Reclaim space incrementally
			_, err = db.ExecContext(ctx, "PRAGMA incremental_vacuum(5000)")
			if err != nil {
				slog.Error("Error running incremental vacuum", "error", err)
			}
		}
	}

	go cleanup() // Initial cleanup

	// Start hourly aggregation ticker
	aggTicker := time.NewTicker(1 * time.Hour)
	defer aggTicker.Stop()
	go func() {
		// Catch-up: Aggregate missing hours from the last 24h
		slog.Info("Starting hourly stats catch-up...")
		for i := 24; i >= 1; i-- {
			targetHour := time.Now().UTC().Add(time.Duration(-i) * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
			aggregateHourlyStats(ctx, targetHour)
		}
		slog.Info("Hourly stats catch-up complete")

		for {
			select {
			case <-ctx.Done():
				return
			case <-aggTicker.C:
				targetHour := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
				aggregateHourlyStats(ctx, targetHour)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func aggregateHourlyStats(ctx context.Context, targetHour string) {
	if db == nil {
		return
	}

	if targetHour == "" {
		targetHour = time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
	}

	slog.Debug("Starting hourly aggregation", "hour", targetHour)

	_, err := db.ExecContext(ctx, `
		INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits)
		SELECT 
			datetime(timestamp, 'start of hour') as hr,
			COUNT(*),
			SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END),
			SUM(CASE WHEN is_cache_hit = 1 THEN 1 ELSE 0 END)
		FROM queries
		WHERE timestamp >= datetime(?, 'start of hour') 
		  AND timestamp < datetime(?, 'start of hour', '+1 hour')
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

func startLogWorker(ctx context.Context) {
	// Periodically flush buffered queries to SQLite
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final flush is handled in main.go during shutdown
			return
		case <-ticker.C:
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
}

func flushLogs(toFlush []Query) {
	if db == nil {
		slog.Warn("Log flush skipped: database connection is closed")
		return
	}

	tx, err := db.Begin()
	if err != nil {
		slog.Error("Error starting log transaction", "error", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO queries (timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		slog.Error("Error preparing log statement", "error", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, q := range toFlush {
		// Use standard SQLite format for storage to ensure consistency
		_, err = stmt.Exec(q.Time.UTC().Format("2006-01-02 15:04:05"), q.Domain, q.Type, q.Status, q.ClientIP, q.IsCacheHit, q.DurationMs, q.CountryCode)
		if err != nil {
			slog.Error("Error executing log statement", "domain", q.Domain, "error", err)
		}
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

	atomic.StoreInt64(&stats.TotalQueries, total+curTotal)
	atomic.StoreInt64(&stats.BlockedQueries, blocked+curBlocked)
	atomic.StoreInt64(&stats.CacheHits, cacheHits+curCacheHits)
	stats.AverageLatency = avgLatency
	stats.LastUpdate = time.Now()

	// 2. Query Types (last 24h)
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

	// 3. Top Countries (last 24h)
	if stats.TopCountries == nil {
		stats.TopCountries = make(map[string]int64)
	}
	cRows, err := db.QueryContext(ctx, `
		SELECT country_code, COUNT(*) 
		FROM queries 
		WHERE timestamp > datetime('now', '-24 hours') AND country_code IS NOT NULL AND country_code != ''
		GROUP BY country_code
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`)
	if err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var cc string
			var count int64
			if err := cRows.Scan(&cc, &count); err == nil {
				stats.TopCountries[cc] = count
			}
		}
	} else {
		slog.Error("Error initializing country stats from DB", "error", err)
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

func ClearQueryLogs() error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := db.Exec("DELETE FROM queries")
	if err != nil {
		slog.Error("Failed to clear query logs", "error", err)
		return err
	}
	// Also run VACUUM to reclaim space
	_, _ = db.Exec("VACUUM")
	slog.Info("All query logs cleared manually")
	return nil
}
func ParseFlexibleTime(ts string) (time.Time, error) {
	// 1. Try RFC3339 (modern Go/SQLite storage format)
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t, nil
	}
	// 2. Try SQLite native format (no T, no timezone)
	if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return t, nil
	}
	// 3. Fallback to ISO-8601 without timezone
	return time.Parse("2006-01-02T15:04:05", ts)
}
