package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	statsFreshTTL        = 15 * time.Second
	statsStaleMaxAge     = 5 * time.Minute
	avgLatencyFreshTTL   = 1 * time.Minute
	uniqueClientFreshTTL = 1 * time.Minute
	dbSizeFreshTTL       = 5 * time.Minute
	topStatsFreshTTL     = 30 * time.Second
	topStatsStaleMaxAge  = 5 * time.Minute
	dbCacheQueryTimeout  = 20 * time.Second
)

var (
	avgLatencyMu         sync.RWMutex
	cachedAvgLatency     float64
	lastAvgLatencyUpdate time.Time
	avgLatencyRefreshing atomic.Bool
	avgLatencyFlightMu   sync.Mutex

	uniqueClientsMu         sync.RWMutex
	cachedUniqueClients     int
	lastUniqueUpdate        time.Time
	uniqueClientsRefreshing atomic.Bool
	uniqueClientsFlightMu   sync.Mutex

	dbSizeMu         sync.RWMutex
	cachedDBSize     int64
	lastDBSizeUpdate time.Time
	dbSizeRefreshing atomic.Bool
	dbSizeFlightMu   sync.Mutex

	statsRefreshing atomic.Bool
	statsFlightMu   sync.Mutex

	topBlockedMu         sync.RWMutex
	topBlockedCache      []map[string]interface{}
	topBlockedCacheTime  time.Time
	topBlockedRefreshing atomic.Bool
	topBlockedFlightMu   sync.Mutex

	topClientsMu         sync.RWMutex
	topClientsCache      []map[string]interface{}
	topClientsCacheTime  time.Time
	topClientsRefreshing atomic.Bool
	topClientsFlightMu   sync.Mutex
)

func refreshAverageLatencyCache() float64 {
	if db == nil {
		return 0
	}
	avgLatencyFlightMu.Lock()
	defer avgLatencyFlightMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dbCacheQueryTimeout)
	defer cancel()

	var avg float64
	err := dbQueryRowContext(
		ctx,
		"SELECT COALESCE(AVG(duration_ms), 0) FROM queries WHERE timestamp > datetime('now', '-24 hours')",
	).Scan(&avg)
	if err != nil {
		avgLatencyMu.RLock()
		fallback := cachedAvgLatency
		avgLatencyMu.RUnlock()
		return fallback
	}

	avgLatencyMu.Lock()
	cachedAvgLatency = avg
	lastAvgLatencyUpdate = time.Now()
	avgLatencyMu.Unlock()
	return avg
}

func getCachedAverageLatency() float64 {
	if db == nil {
		return 0
	}
	if testMode {
		avg, err := GetAverageLatency()
		if err == nil {
			return avg
		}
		return 0
	}

	avgLatencyMu.RLock()
	val := cachedAvgLatency
	updated := lastAvgLatencyUpdate
	avgLatencyMu.RUnlock()

	if !updated.IsZero() {
		if time.Since(updated) < avgLatencyFreshTTL {
			return val
		}
		if avgLatencyRefreshing.CompareAndSwap(false, true) {
			go func() {
				defer avgLatencyRefreshing.Store(false)
				refreshAverageLatencyCache()
			}()
		}
		return val
	}

	return refreshAverageLatencyCache()
}

func refreshUniqueClientsCache() int {
	if db == nil {
		return 0
	}
	uniqueClientsFlightMu.Lock()
	defer uniqueClientsFlightMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), dbCacheQueryTimeout)
	defer cancel()

	var uc int
	err := dbQueryRowContext(
		ctx,
		"SELECT COUNT(DISTINCT client_ip) FROM queries WHERE timestamp > datetime('now', '-24 hours') AND client_ip != 'DoH Proxy'",
	).Scan(&uc)
	if err != nil {
		uniqueClientsMu.RLock()
		fallback := cachedUniqueClients
		uniqueClientsMu.RUnlock()
		return fallback
	}

	uniqueClientsMu.Lock()
	cachedUniqueClients = uc
	lastUniqueUpdate = time.Now()
	uniqueClientsMu.Unlock()
	return uc
}

func getCachedUniqueClients() int {
	if db == nil {
		return 0
	}

	uniqueClientsMu.RLock()
	val := cachedUniqueClients
	updated := lastUniqueUpdate
	uniqueClientsMu.RUnlock()

	if !updated.IsZero() {
		if time.Since(updated) < uniqueClientFreshTTL {
			return val
		}
		if !testMode {
			if uniqueClientsRefreshing.CompareAndSwap(false, true) {
				go func() {
					defer uniqueClientsRefreshing.Store(false)
					refreshUniqueClientsCache()
				}()
			}
			return val
		}
	}

	return refreshUniqueClientsCache()
}

func refreshDBSizeCache() int64 {
	dbSizeFlightMu.Lock()
	defer dbSizeFlightMu.Unlock()

	size := getDBSizeBytes()
	dbSizeMu.Lock()
	cachedDBSize = size
	lastDBSizeUpdate = time.Now()
	dbSizeMu.Unlock()
	return size
}

func getCachedDBSizeBytes() int64 {
	if db == nil || testMode {
		return getDBSizeBytes()
	}

	dbSizeMu.RLock()
	val := cachedDBSize
	updated := lastDBSizeUpdate
	dbSizeMu.RUnlock()

	if !updated.IsZero() {
		if time.Since(updated) < dbSizeFreshTTL {
			return val
		}
		if dbSizeRefreshing.CompareAndSwap(false, true) {
			go func() {
				defer dbSizeRefreshing.Store(false)
				refreshDBSizeCache()
			}()
		}
		return val
	}

	return refreshDBSizeCache()
}

func refreshStatsCache() Stats {
	statsFlightMu.Lock()
	defer statsFlightMu.Unlock()

	s := getStatsData()
	statsCacheMu.Lock()
	statsCache = s
	statsCacheTime = time.Now()
	statsCacheMu.Unlock()
	return s
}

func getCachedStatsResponse() Stats {
	statsCacheMu.Lock()
	cached := statsCache
	cachedAt := statsCacheTime
	statsCacheMu.Unlock()

	if !cachedAt.IsZero() {
		age := time.Since(cachedAt)
		if age < statsFreshTTL {
			return cached
		}
		if age < statsStaleMaxAge && !testMode {
			if statsRefreshing.CompareAndSwap(false, true) {
				go func() {
					defer statsRefreshing.Store(false)
					refreshStatsCache()
				}()
			}
			return cached
		}
	}

	statsFlightMu.Lock()
	defer statsFlightMu.Unlock()

	statsCacheMu.Lock()
	cached = statsCache
	cachedAt = statsCacheTime
	statsCacheMu.Unlock()
	if !cachedAt.IsZero() && time.Since(cachedAt) < statsFreshTTL {
		return cached
	}

	s := getStatsData()
	statsCacheMu.Lock()
	statsCache = s
	statsCacheTime = time.Now()
	statsCacheMu.Unlock()
	return s
}

func fetchTopBlocked() ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbCacheQueryTimeout)
	defer cancel()

	rows, err := dbQueryContext(ctx, `
		SELECT domain, COUNT(*) as count
		FROM queries
		WHERE status LIKE 'Blocked%' AND timestamp > datetime('now', '-24 hours')
		GROUP BY domain
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var domain string
		var count int
		if err := rows.Scan(&domain, &count); err == nil {
			result = append(result, map[string]interface{}{"domain": domain, "count": count})
		}
	}
	return result, nil
}

func refreshTopBlockedCache() ([]map[string]interface{}, error) {
	topBlockedFlightMu.Lock()
	defer topBlockedFlightMu.Unlock()

	res, err := fetchTopBlocked()
	if err != nil {
		return nil, err
	}
	topBlockedMu.Lock()
	topBlockedCache = res
	topBlockedCacheTime = time.Now()
	topBlockedMu.Unlock()
	return res, nil
}

func getCachedTopBlocked() ([]map[string]interface{}, error) {
	if testMode {
		return fetchTopBlocked()
	}

	topBlockedMu.RLock()
	cached := topBlockedCache
	cachedAt := topBlockedCacheTime
	topBlockedMu.RUnlock()

	if !cachedAt.IsZero() {
		age := time.Since(cachedAt)
		if age < topStatsFreshTTL {
			return cached, nil
		}
		if age < topStatsStaleMaxAge {
			if topBlockedRefreshing.CompareAndSwap(false, true) {
				go func() {
					defer topBlockedRefreshing.Store(false)
					_, _ = refreshTopBlockedCache()
				}()
			}
			return cached, nil
		}
	}

	topBlockedFlightMu.Lock()
	defer topBlockedFlightMu.Unlock()

	topBlockedMu.RLock()
	cached = topBlockedCache
	cachedAt = topBlockedCacheTime
	topBlockedMu.RUnlock()
	if !cachedAt.IsZero() && time.Since(cachedAt) < topStatsFreshTTL {
		return cached, nil
	}

	res, err := fetchTopBlocked()
	if err != nil {
		return nil, err
	}
	topBlockedMu.Lock()
	topBlockedCache = res
	topBlockedCacheTime = time.Now()
	topBlockedMu.Unlock()
	return res, nil
}

func fetchTopClients() ([]map[string]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbCacheQueryTimeout)
	defer cancel()

	rows, err := dbQueryContext(ctx, `
		SELECT client_ip, COUNT(*) as count
		FROM queries
		WHERE timestamp > datetime('now', '-24 hours') AND client_ip != 'DoH Proxy'
		GROUP BY client_ip
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	configLock.RLock()
	aliases := config.ClientAliases
	configLock.RUnlock()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var clientIP string
		var count int
		if err := rows.Scan(&clientIP, &count); err != nil {
			continue
		}
		if clientIP == "" {
			clientIP = "Unknown"
		}
		alias := ""
		if aliases != nil {
			alias = aliases[clientIP]
		}
		countryCode := ""
		if val, ok := ipInfoCache.Load(clientIP); ok {
			countryCode = val.(IPInfo).CountryCode
		}
		if countryCode == "" || countryCode == "-" || countryCode == "geo" {
			countryCode = GetCountryCodeCached(clientIP)
		}
		if countryCode == "geo" || countryCode == "-" {
			countryCode = ""
		}
		result = append(result, map[string]interface{}{
			"client_ip":    clientIP,
			"client_alias": alias,
			"count":        count,
			"country_code": strings.ToLower(countryCode),
		})
	}
	return result, nil
}

func refreshTopClientsCache() ([]map[string]interface{}, error) {
	topClientsFlightMu.Lock()
	defer topClientsFlightMu.Unlock()

	res, err := fetchTopClients()
	if err != nil {
		return nil, err
	}
	topClientsMu.Lock()
	topClientsCache = res
	topClientsCacheTime = time.Now()
	topClientsMu.Unlock()
	return res, nil
}

func getCachedTopClients() ([]map[string]interface{}, error) {
	if testMode {
		return fetchTopClients()
	}

	topClientsMu.RLock()
	cached := topClientsCache
	cachedAt := topClientsCacheTime
	topClientsMu.RUnlock()

	if !cachedAt.IsZero() {
		age := time.Since(cachedAt)
		if age < topStatsFreshTTL {
			return cached, nil
		}
		if age < topStatsStaleMaxAge {
			if topClientsRefreshing.CompareAndSwap(false, true) {
				go func() {
					defer topClientsRefreshing.Store(false)
					_, _ = refreshTopClientsCache()
				}()
			}
			return cached, nil
		}
	}

	topClientsFlightMu.Lock()
	defer topClientsFlightMu.Unlock()

	topClientsMu.RLock()
	cached = topClientsCache
	cachedAt = topClientsCacheTime
	topClientsMu.RUnlock()
	if !cachedAt.IsZero() && time.Since(cachedAt) < topStatsFreshTTL {
		return cached, nil
	}

	res, err := fetchTopClients()
	if err != nil {
		return nil, err
	}
	topClientsMu.Lock()
	topClientsCache = res
	topClientsCacheTime = time.Now()
	topClientsMu.Unlock()
	return res, nil
}

func ensurePerformanceIndexes() {
	if testMode || db == nil || DBPath == ":memory:" {
		return
	}

	// Small delay so startup DB connections settle cleanly
	time.Sleep(2 * time.Second)
	if testMode || db == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	switch dbDriver {
	case "postgres":
		stmts := []string{
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_queries_ts_duration ON queries(timestamp, duration_ms)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_queries_blocked_ts_domain ON queries(timestamp, domain) WHERE status LIKE 'Blocked%'",
		}
		for _, stmt := range stmts {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				slog.Warn("Performance index creation notice", "driver", "postgres", "error", err)
			}
		}
	case "mysql":
		indexes := []struct {
			name string
			cols string
		}{
			{"idx_queries_ts_duration", "(timestamp, duration_ms)"},
			{"idx_queries_ts_status_domain", "(timestamp, status, domain)"},
		}
		for _, idx := range indexes {
			var count int
			err := db.QueryRowContext(
				ctx,
				"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'queries' AND index_name = ?",
				idx.name,
			).Scan(&count)
			if err != nil || count > 0 {
				continue
			}
			stmt := fmt.Sprintf("CREATE INDEX %s ON queries%s", idx.name, idx.cols)
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				slog.Warn("Performance index creation notice", "driver", "mysql", "index", idx.name, "error", err)
			}
		}
	case "sqlite":
		stmts := []string{
			"CREATE INDEX IF NOT EXISTS idx_queries_ts_duration ON queries(timestamp, duration_ms)",
			"CREATE INDEX IF NOT EXISTS idx_queries_blocked_ts_domain ON queries(timestamp, domain) WHERE status LIKE 'Blocked%'",
		}
		for _, stmt := range stmts {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				slog.Warn("Performance index creation notice", "driver", "sqlite", "error", err)
			}
		}
	}
}
