package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lib/pq"
	_ "modernc.org/sqlite"
)

var (
	db       *sql.DB
	dbDriver = "sqlite" // "sqlite" or "postgres"
)

func closeDB() {
	if db != nil {
		db.Close()
		db = nil
	}
}

// formatQuery transforms SQL queries into the target database dialect (SQLite or PostgreSQL).
func formatQuery(query string) string {
	if dbDriver != "postgres" {
		return query
	}
	query = strings.ReplaceAll(query, "datetime('now', '-24 hours')", "(NOW() - INTERVAL '24 hours')")
	query = strings.ReplaceAll(query, "datetime('now')", "NOW()")
	query = strings.ReplaceAll(query, "strftime('%Y-%m-%d %H:00:00', timestamp) as hr", "date_trunc('hour', timestamp) as hr")
	query = strings.ReplaceAll(query, "strftime('%Y-%m-%d %H:00:00', timestamp)", "to_char(timestamp, 'YYYY-MM-DD HH24:00:00')")
	query = strings.ReplaceAll(query, "datetime(?, '-1 hour')", "(?::TIMESTAMP - INTERVAL '1 hour')")
	query = strings.ReplaceAll(query, "datetime(?, '+1 hour')", "(?::TIMESTAMP + INTERVAL '1 hour')")
	query = strings.ReplaceAll(query, "datetime('now', ?)", "(NOW() + (?)::INTERVAL)")
	return rebind(query)
}

// rebind replaces '?' parameter placeholders with PostgreSQL '$1', '$2', ... placeholders.
func rebind(query string) string {
	if dbDriver != "postgres" {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 20)
	paramIdx := 1
	inQuote := false
	var quoteChar rune

	for i, r := range query {
		if inQuote {
			b.WriteRune(r)
			if r == quoteChar {
				if quoteChar == '\'' && i+1 < len(query) && rune(query[i+1]) == '\'' {
					// escaped quote
				} else {
					inQuote = false
				}
			}
			continue
		}

		if r == '\'' || r == '"' {
			inQuote = true
			quoteChar = r
			b.WriteRune(r)
		} else if r == '?' {
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(paramIdx))
			paramIdx++
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func dbQuery(query string, args ...interface{}) (*sql.Rows, error) {
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return db.Query(formatQuery(query), args...)
}

func dbQueryRow(query string, args ...interface{}) *sql.Row {
	if db == nil {
		return nil
	}
	return db.QueryRow(formatQuery(query), args...)
}

func dbExec(query string, args ...interface{}) (sql.Result, error) {
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return db.Exec(formatQuery(query), args...)
}

func dbQueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error) {
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return db.QueryContext(ctx, formatQuery(query), args...)
}

func dbQueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row {
	if db == nil {
		return nil
	}
	return db.QueryRowContext(ctx, formatQuery(query), args...)
}

func dbExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	return db.ExecContext(ctx, formatQuery(query), args...)
}

func initDB() {
	var err error

	// 1. Determine database driver and connection target
	dbURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if dbURL == "" {
		dbURL = strings.TrimSpace(os.Getenv("SHIELDDNS_DATABASE_URL"))
	}
	if dbURL == "" {
		dbURL = strings.TrimSpace(config.DatabaseURL)
	}

	if strings.HasPrefix(dbURL, "postgres://") || strings.HasPrefix(dbURL, "postgresql://") {
		dbDriver = "postgres"
		slog.Info("Initializing PostgreSQL database backend", "driver", "postgres")
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			slog.Error("Could not open PostgreSQL database", "error", err)
			os.Exit(1)
		}

		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(10)
		db.SetConnMaxLifetime(10 * time.Minute)

		if err = db.Ping(); err != nil {
			slog.Error("Failed to connect to PostgreSQL database", "error", err)
			os.Exit(1)
		}

		_, err = db.Exec(`
			CREATE TABLE IF NOT EXISTS queries (
				id BIGSERIAL PRIMARY KEY,
				timestamp TIMESTAMP WITH TIME ZONE,
				domain TEXT,
				type TEXT,
				status TEXT,
				client_ip TEXT,
				is_cache_hit BOOLEAN DEFAULT FALSE,
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
			CREATE INDEX IF NOT EXISTS idx_queries_hourly_agg ON queries(timestamp, status, is_cache_hit);
			CREATE INDEX IF NOT EXISTS idx_queries_ts_type ON queries(timestamp, type);
			CREATE INDEX IF NOT EXISTS idx_queries_ts_country ON queries(timestamp, country_code);

			CREATE TABLE IF NOT EXISTS clients (
				ip TEXT PRIMARY KEY,
				user_agent TEXT,
				last_seen TIMESTAMP WITH TIME ZONE
			);
			CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip);

			CREATE TABLE IF NOT EXISTS hourly_stats (
				timestamp TIMESTAMP WITH TIME ZONE PRIMARY KEY,
				total BIGINT DEFAULT 0,
				blocked BIGINT DEFAULT 0,
				cache_hits BIGINT DEFAULT 0
			);
		`)
		if err != nil {
			slog.Error("Could not initialize PostgreSQL schema", "error", err)
			os.Exit(1)
		}

		slog.Info("PostgreSQL database initialized successfully")

		// Automatic zero-downtime migration if SQLite database exists and PostgreSQL is empty
		if _, statErr := os.Stat(DBPath); statErr == nil {
			var pgCount int64
			if err := db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&pgCount); err == nil && pgCount == 0 {
				slog.Info("PostgreSQL is empty; SQLite database detected. Starting seamless migration...", "sqlite_path", DBPath)
				if err := autoMigrateFromSQLite(DBPath, db); err != nil {
					slog.Error("Migration from SQLite to PostgreSQL failed", "error", err)
				} else {
					slog.Info("Automatic migration from SQLite to PostgreSQL completed successfully! All records preserved.")
				}
			}
		}

	} else {
		dbDriver = "sqlite"
		os.MkdirAll(filepath.Dir(DBPath), 0755)
		db, err = sql.Open("sqlite", DBPath+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)")
		if err != nil {
			slog.Error("Could not open database", "path", DBPath, "error", err)
			os.Exit(1)
		}

		// Performance Tuning: SQLite handles concurrent readers efficiently in WAL mode.
		// A pool of up to 10 connections allows UI and stats reads without blocking write batches.
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
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
			CREATE INDEX IF NOT EXISTS idx_queries_hourly_agg ON queries(timestamp, status, is_cache_hit);
			CREATE INDEX IF NOT EXISTS idx_queries_ts_type ON queries(timestamp, type);
			CREATE INDEX IF NOT EXISTS idx_queries_ts_country ON queries(timestamp, country_code);
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

	var exists bool
	if dbDriver == "postgres" {
		query := "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2)"
		if err := db.QueryRow(query, table, column).Scan(&exists); err != nil {
			slog.Error("Error checking table column in postgres", "table", table, "column", column, "error", err)
			return
		}
	} else {
		query := fmt.Sprintf("PRAGMA table_info(%s)", table)
		rows, err := db.Query(query)
		if err != nil {
			slog.Error("Error checking table info", "table", table, "error", err)
			return
		}
		defer rows.Close()

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

func startDBWorker(ctx context.Context) {
	if testMode {
		return
	}

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	cleanup := func() {
		configLock.RLock()
		days := config.RetentionDays
		configLock.RUnlock()

		if db != nil {
			// 1. Regular TTL purge based on RetentionDays
			res, err := dbExecContext(ctx, "DELETE FROM queries WHERE timestamp < datetime('now', ?)", fmt.Sprintf("-%d days", days))
			if err != nil {
				slog.Error("Error purging old queries", "error", err)
			} else {
				deleted, _ := res.RowsAffected()
				if deleted > 0 {
					slog.Info("Database maintenance: TTL purge complete", "days_retained", days, "rows_deleted", deleted)
				}
			}

			// 2. Resource Safety: Hard cap on total queries (max 500k rows) in non-blocking chunks
			var totalRows int
			err = dbQueryRowContext(ctx, "SELECT COUNT(*) FROM queries").Scan(&totalRows)
			if err == nil && totalRows > 500000 {
				overage := totalRows - 500000 + 50000
				deletedTotal := 0
				for remaining := overage; remaining > 0; remaining -= 5000 {
					batchLimit := remaining
					if batchLimit > 5000 {
						batchLimit = 5000
					}
					delCtx, delCancel := context.WithTimeout(ctx, 10*time.Second)
					res, delErr := dbExecContext(delCtx, "DELETE FROM queries WHERE id IN (SELECT id FROM queries ORDER BY timestamp ASC LIMIT ?)", batchLimit)
					delCancel()
					if delErr != nil {
						slog.Error("Database maintenance: Error during row prune batch", "error", delErr)
						break
					}
					rows, _ := res.RowsAffected()
					deletedTotal += int(rows)
					if rows == 0 {
						break
					}
					time.Sleep(50 * time.Millisecond) // Yield lock to allow flushes and queries
				}
				slog.Info("Database maintenance: Row cap prune complete", "total_before", totalRows, "deleted", deletedTotal)
			}

			// 3. Reclaim space incrementally (SQLite only)
			if dbDriver == "sqlite" {
				_, err = db.ExecContext(ctx, "PRAGMA incremental_vacuum(5000)")
				if err != nil {
					slog.Error("Error running incremental vacuum", "error", err)
				}
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
	if db == nil || len(queries) == 0 {
		return
	}

	tx, err := db.Begin()
	if err != nil {
		slog.Error("Error starting log transaction", "error", err)
		return
	}

	configLock.RLock()
	localNodeName := config.ClusterNodeName
	configLock.RUnlock()

	batchSize := 100
	for k := 0; k < len(queries); k += batchSize {
		end := k + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		batch := queries[k:end]

		valueStrings := make([]string, 0, len(batch))
		valueArgs := make([]interface{}, 0, len(batch)*9)

		for _, q := range batch {
			nodeName := q.NodeName
			if nodeName == "" {
				nodeName = localNodeName
			}
			valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?, ?, ?, ?)")
			valueArgs = append(valueArgs, q.Time.UTC().Format("2006-01-02 15:04:05"), q.Domain, q.Type, q.Status, q.ClientIP, q.IsCacheHit, q.DurationMs, q.CountryCode, nodeName)
		}

		query := "INSERT INTO queries (timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name) VALUES " +
			strings.Join(valueStrings, ",")

		_, err = tx.Exec(formatQuery(query), valueArgs...)
		if err != nil {
			slog.Error("Error executing log batch statement", "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("Error committing log transaction", "error", err)
	}
}

