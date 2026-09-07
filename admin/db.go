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
		PRAGMA cache_size=-16384;
		PRAGMA mmap_size=67108864;
		PRAGMA temp_store=MEMORY;
		CREATE TABLE IF NOT EXISTS queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME,
			domain TEXT,
			type TEXT,
			status TEXT,
			client_ip TEXT,
			is_cache_hit BOOLEAN DEFAULT 0,
			duration_ms REAL DEFAULT 0,
			country_code TEXT,
			node_name TEXT DEFAULT ''
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
	addColumnIfNotExists("queries", "node_name", "TEXT DEFAULT ''")
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
	if testMode {
		return
	}
	// 1. Initial 24h Stats Catch-up (One-time on boot)
	slog.Info("Starting initial statistics catch-up...")
	for i := 1; i <= 24; i++ {
		targetHour := time.Now().UTC().Add(time.Duration(-i) * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
		aggregateHourlyStats(ctx, targetHour)
	}
	slog.Info("Initial statistics catch-up complete")

	ticker := time.NewTicker(1 * time.Hour)
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
				if deleted > 0 {
					slog.Info("Database maintenance: TTL purge complete", "days_retained", days, "rows_deleted", deleted)
				}
			}

			// 2. Resource Safety: Hard cap on total queries (max 500k rows)
			var totalRows int
			err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM queries").Scan(&totalRows)
			if err == nil && totalRows > 500000 {
				overage := totalRows - 500000 + 50000
				res, err = db.ExecContext(ctx, "DELETE FROM queries WHERE id IN (SELECT id FROM queries ORDER BY timestamp ASC LIMIT ?)", overage)
				if err != nil {
					slog.Error("Database maintenance: Error during row prune", "error", err)
				} else {
					deleted, _ := res.RowsAffected()
					slog.Info("Database maintenance: Row cap prune complete", "total_before", totalRows, "deleted", deleted)
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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func startLogWorker(ctx context.Context) {
	// 1. Log Flusher (Every 5 seconds)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
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
				flushLogs(toFlush)
			}
		}
	}()

	// 2. Stats Aggregator (Every hour) - Lightweight update
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Only aggregate the most recent full hour
				targetHour := time.Now().UTC().Add(-1 * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
				aggregateHourlyStats(ctx, targetHour)
			}
		}
	}()

	// 3. Stats Refresher (Every minute) - Quiet update
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refreshStats()
			}
		}
	}()
}

func flushLogs(queries []Query) {
	if db == nil {
		return
	}

	tx, err := db.Begin()
	if err != nil {
		slog.Error("Error starting log transaction", "error", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO queries (timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		slog.Error("Error preparing log statement", "error", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	configLock.RLock()
	localNodeName := config.ClusterNodeName
	configLock.RUnlock()

	for _, q := range queries {
		nodeName := q.NodeName
		if nodeName == "" {
			nodeName = localNodeName
		}
		_, err = stmt.Exec(q.Time.UTC().Format("2006-01-02 15:04:05"), q.Domain, q.Type, q.Status, q.ClientIP, q.IsCacheHit, q.DurationMs, q.CountryCode, nodeName)
		if err != nil {
			slog.Error("Error executing log statement", "domain", q.Domain, "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("Error committing log transaction", "error", err)
	}
}

func aggregateHourlyStats(ctx context.Context, targetHour string) {
	// targetHour is expected in "2006-01-02 15:04:05" (UTC)
	// This function now uses a slightly wider window to ensure we don't miss queries
	// that were flushed slightly before/after the hour boundary.

	_, err := db.ExecContext(ctx, `
		INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits)
		SELECT 
			strftime('%Y-%m-%d %H:00:00', timestamp) as hr,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_cache_hit = 1 THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE timestamp >= datetime(?, '-1 hour') AND timestamp < datetime(?, '+1 hour')
		GROUP BY hr
		ON CONFLICT(timestamp) DO UPDATE SET
			total = excluded.total,
			blocked = excluded.blocked,
			cache_hits = excluded.cache_hits
	`, targetHour, targetHour)

	if err != nil {
		slog.Error("Aggregation error", "hour", targetHour, "error", err)
	} else {
		slog.Debug("Successfully aggregated hourly stats", "hour", targetHour)
	}
}

func initializeStatsFromDB() {
	if db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	aggregateHourlyStats(ctx, time.Now().UTC().Add(-1*time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05"))

	// Run full catch-up in background
	slog.Info("Starting initial stats catch-up...")
	for i := 1; i <= 24; i++ {
		targetHour := time.Now().UTC().Add(time.Duration(-i) * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
		aggregateHourlyStats(ctx, targetHour)
	}

	total, blocked, cacheHits, err := Get24hStats()
	if err != nil {
		slog.Error("Failed to initialize stats from DB", "error", err)
		return
	}

	statsLock.Lock()
	defer statsLock.Unlock()

	atomic.StoreInt64(&stats.TotalQueries, total)
	atomic.StoreInt64(&stats.BlockedQueries, blocked)
	atomic.StoreInt64(&stats.CacheHits, cacheHits)

	slog.Info("Stats initialized from DB (Rolling 24h Window)",
		"total", total,
		"blocked", blocked,
		"cache_hits", cacheHits)

	// 2. Query Types (last 24h)
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

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
			err = tRows.Scan(&qt, &count)
			if err == nil {
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
		WHERE timestamp > datetime('now', '-24 hours')
		  AND country_code IS NOT NULL
		  AND country_code != ''
		  AND country_code != '-'
		  AND country_code != 'geo'
		GROUP BY country_code
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`)
	if err == nil {
		defer cRows.Close()
		for cRows.Next() {
			var cc string
			var count int64
			err = cRows.Scan(&cc, &count)
			if err == nil {
				stats.TopCountries[cc] = count
			}
		}
	} else {
		slog.Error("Error initializing country stats from DB", "error", err)
	}

	slog.Info("Statistics initialized from database", "total", stats.TotalQueries, "blocked", stats.BlockedQueries)
}

func refreshStats() {
	if db == nil {
		return
	}

	total, blocked, cacheHits, err := Get24hStats()
	if err != nil {
		return
	}

	statsLock.Lock()
	defer statsLock.Unlock()

	atomic.StoreInt64(&stats.TotalQueries, total)
	atomic.StoreInt64(&stats.BlockedQueries, blocked)
	atomic.StoreInt64(&stats.CacheHits, cacheHits)

	// Update Query Types quietly
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
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
			err = tRows.Scan(&qt, &count)
			if err == nil {
				stats.QueryTypes[qt] = count
			}
		}
	}
}

