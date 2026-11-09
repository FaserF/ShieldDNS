package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

func aggregateHourlyStats(ctx context.Context, targetHour string) {
	_, err := dbExecContext(ctx, `
		INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits)
		SELECT 
			strftime('%Y-%m-%d %H:00:00', timestamp) as hr,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_cache_hit IS TRUE THEN 1 ELSE 0 END), 0)
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

	// 1. Run full 24h catch-up in a single efficient batch query
	slog.Info("Starting initial stats catch-up...")
	catchCtx, catchCancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, catchErr := dbExecContext(catchCtx, `
		INSERT INTO hourly_stats (timestamp, total, blocked, cache_hits)
		SELECT 
			strftime('%Y-%m-%d %H:00:00', timestamp) as hr,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_cache_hit IS TRUE THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE timestamp >= datetime('now', '-24 hours')
		GROUP BY hr
		ON CONFLICT(timestamp) DO UPDATE SET
			total = excluded.total,
			blocked = excluded.blocked,
			cache_hits = excluded.cache_hits
	`)
	catchCancel()
	if catchErr != nil {
		slog.Warn("Initial stats catch-up query notice", "error", catchErr)
	}

	total, blocked, cacheHits, err := Get24hStats()
	if err != nil {
		slog.Error("Failed to initialize stats from DB", "error", err)
		return
	}

	// 2. Query Types (last 24h)
	tCtx, tCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer tCancel()

	queryTypes := make(map[string]int64)
	tRows, err := dbQueryContext(tCtx, `
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
			if err = tRows.Scan(&qt, &count); err == nil {
				queryTypes[qt] = count
			}
		}
	} else {
		slog.Error("Error initializing query types from DB", "error", err)
	}

	// 3. Top Countries (last 24h)
	cCtx, cCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cCancel()

	topCountries := make(map[string]int64)
	cRows, err := dbQueryContext(cCtx, `
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
			if err = cRows.Scan(&cc, &count); err == nil {
				topCountries[cc] = count
			}
		}
	} else {
		slog.Error("Error initializing country stats from DB", "error", err)
	}

	statsLock.Lock()
	defer statsLock.Unlock()

	atomic.StoreInt64(&stats.TotalQueries, total)
	atomic.StoreInt64(&stats.BlockedQueries, blocked)
	atomic.StoreInt64(&stats.CacheHits, cacheHits)
	stats.QueryTypes = queryTypes
	stats.TopCountries = topCountries

	slog.Info("Statistics initialized from database", "total", total, "blocked", blocked, "cache_hits", cacheHits)
}

func refreshStats() {
	if db == nil {
		return
	}

	total, blocked, cacheHits, err := Get24hStats()
	if err != nil {
		return
	}

	// Update Query Types quietly before acquiring statsLock
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	queryTypes := make(map[string]int64)
	if err := db.PingContext(ctx); err == nil {
		tRows, err := dbQueryContext(ctx, `
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
				if err = tRows.Scan(&qt, &count); err == nil {
					queryTypes[qt] = count
				}
			}
		}
	}

	statsLock.Lock()
	defer statsLock.Unlock()

	atomic.StoreInt64(&stats.TotalQueries, total)
	atomic.StoreInt64(&stats.BlockedQueries, blocked)
	atomic.StoreInt64(&stats.CacheHits, cacheHits)
	if len(queryTypes) > 0 {
		stats.QueryTypes = queryTypes
	}
}
