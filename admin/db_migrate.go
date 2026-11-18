package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lib/pq"
)

func autoMigrateFromSQLite(sqlitePath string, targetDB *sql.DB, since time.Time) error {
	srcDB, err := sql.Open("sqlite", sqlitePath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("failed to open source sqlite db: %w", err)
	}
	defer srcDB.Close()

	// 1. Migrate clients table
	cRows, err := srcDB.Query("SELECT ip, user_agent, last_seen FROM clients")
	if err == nil {
		defer cRows.Close()
		cTx, err := targetDB.Begin()
		if err == nil {
			clientUpsert := `
				INSERT INTO clients (ip, user_agent, last_seen) VALUES ($1, $2, $3)
				ON CONFLICT(ip) DO UPDATE SET user_agent = EXCLUDED.user_agent, last_seen = EXCLUDED.last_seen
			`
			if dbDriver == "mysql" {
				clientUpsert = `
					INSERT INTO clients (ip, user_agent, last_seen) VALUES (?, ?, ?)
					ON DUPLICATE KEY UPDATE user_agent = VALUES(user_agent), last_seen = VALUES(last_seen)
				`
			}
			cStmt, err := cTx.Prepare(clientUpsert)
			if err == nil {
				var count int
				for cRows.Next() {
					var ip, ua, lastSeen string
					if err := cRows.Scan(&ip, &ua, &lastSeen); err == nil {
						t, _ := ParseFlexibleTime(lastSeen)
						cStmt.Exec(ip, ua, t)
						count++
					}
				}
				cStmt.Close()
				cTx.Commit()
				slog.Info("Migrated clients table", "target_driver", dbDriver, "count", count)
			} else {
				cTx.Rollback()
			}
		}
	}

	// 2. Migrate hourly_stats table
	hRows, err := srcDB.Query("SELECT timestamp, total, blocked, cache_hits FROM hourly_stats")
	if err == nil {
		defer hRows.Close()
		hTx, err := targetDB.Begin()
		if err == nil {
			hourlyUpsert := `
				INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits) VALUES ($1, $2, $3, $4)
				ON CONFLICT(timestamp) DO UPDATE SET total = EXCLUDED.total, blocked = EXCLUDED.blocked, cache_hits = EXCLUDED.cache_hits
			`
			if dbDriver == "mysql" {
				hourlyUpsert = `
					INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits) VALUES (?, ?, ?, ?)
					ON DUPLICATE KEY UPDATE total = VALUES(total), blocked = VALUES(blocked), cache_hits = VALUES(cache_hits)
				`
			}
			hStmt, err := hTx.Prepare(hourlyUpsert)
			if err == nil {
				var count int
				for hRows.Next() {
					var ts string
					var total, blocked, cacheHits int64
					if err := hRows.Scan(&ts, &total, &blocked, &cacheHits); err == nil {
						t, _ := ParseFlexibleTime(ts)
						hStmt.Exec(t, total, blocked, cacheHits)
						count++
					}
				}
				hStmt.Close()
				hTx.Commit()
				slog.Info("Migrated hourly_stats table", "target_driver", dbDriver, "count", count)
			} else {
				hTx.Rollback()
			}
		}
	}

	// 3. Migrate queries table
	var qRows *sql.Rows
	if !since.IsZero() {
		qRows, err = srcDB.Query("SELECT timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name FROM queries WHERE timestamp > ? ORDER BY id ASC", since.Format(time.RFC3339))
	} else {
		qRows, err = srcDB.Query("SELECT timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name FROM queries ORDER BY id ASC")
	}
	if err != nil {
		return fmt.Errorf("failed to query source queries: %w", err)
	}
	defer qRows.Close()

	if dbDriver == "mysql" {
		totalMigrated, err := migrateQueriesMySQL(targetDB, qRows)
		if err != nil {
			return err
		}
		slog.Info("Migrated queries table to MariaDB/MySQL", "total_rows", totalMigrated)
		return nil
	}

	qTx, err := targetDB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	stmt, err := qTx.Prepare(pq.CopyIn("queries", "timestamp", "domain", "type", "status", "client_ip", "is_cache_hit", "duration_ms", "country_code", "node_name"))
	if err != nil {
		qTx.Rollback()
		return fmt.Errorf("failed to prepare pq.CopyIn: %w", err)
	}

	var totalMigrated int64
	for qRows.Next() {
		var ts string
		var domain, qType, status, clientIP string
		var isCacheHit bool
		var durationMs float64
		var countryCode, nodeName *string

		if err := qRows.Scan(&ts, &domain, &qType, &status, &clientIP, &isCacheHit, &durationMs, &countryCode, &nodeName); err != nil {
			continue
		}
		t, _ := ParseFlexibleTime(ts)
		cc := ""
		if countryCode != nil {
			cc = *countryCode
		}
		nn := ""
		if nodeName != nil {
			nn = *nodeName
		}
		if _, err := stmt.Exec(t, domain, qType, status, clientIP, isCacheHit, durationMs, cc, nn); err != nil {
			continue
		}
		totalMigrated++
	}

	if _, err := stmt.Exec(); err != nil {
		qTx.Rollback()
		return fmt.Errorf("failed to finalize pq.CopyIn: %w", err)
	}
	if err := stmt.Close(); err != nil {
		qTx.Rollback()
		return fmt.Errorf("failed to close stmt: %w", err)
	}
	if err := qTx.Commit(); err != nil {
		return fmt.Errorf("failed to commit pq.CopyIn transaction: %w", err)
	}

	slog.Info("Migrated queries table to PostgreSQL", "total_rows", totalMigrated)
	return nil
}

func migrateQueriesMySQL(targetDB *sql.DB, qRows *sql.Rows) (int64, error) {
	const batchSize = 500
	var totalMigrated int64

	valueStrings := make([]string, 0, batchSize)
	valueArgs := make([]interface{}, 0, batchSize*9)

	flushBatch := func() error {
		if len(valueStrings) == 0 {
			return nil
		}
		query := "INSERT INTO queries (timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name) VALUES " +
			strings.Join(valueStrings, ",")
		if _, err := targetDB.Exec(query, valueArgs...); err != nil {
			return err
		}
		totalMigrated += int64(len(valueStrings))
		valueStrings = valueStrings[:0]
		valueArgs = valueArgs[:0]
		return nil
	}

	for qRows.Next() {
		var ts string
		var domain, qType, status, clientIP string
		var isCacheHit bool
		var durationMs float64
		var countryCode, nodeName *string

		if err := qRows.Scan(&ts, &domain, &qType, &status, &clientIP, &isCacheHit, &durationMs, &countryCode, &nodeName); err != nil {
			continue
		}
		t, _ := ParseFlexibleTime(ts)
		cc := ""
		if countryCode != nil {
			cc = *countryCode
		}
		nn := ""
		if nodeName != nil {
			nn = *nodeName
		}
		valueStrings = append(valueStrings, "(?, ?, ?, ?, ?, ?, ?, ?, ?)")
		valueArgs = append(valueArgs, t.UTC().Format("2006-01-02 15:04:05"), domain, qType, status, clientIP, isCacheHit, durationMs, cc, nn)

		if len(valueStrings) >= batchSize {
			if err := flushBatch(); err != nil {
				return totalMigrated, fmt.Errorf("failed to insert mysql migration batch: %w", err)
			}
		}
	}

	if err := flushBatch(); err != nil {
		return totalMigrated, fmt.Errorf("failed to insert final mysql migration batch: %w", err)
	}
	return totalMigrated, nil
}
