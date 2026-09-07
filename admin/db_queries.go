package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

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
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0)
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
			err = rows.Scan(&qType, &count)
			if err == nil {
				cs.QueryTypes[qType] = count
			}
		}
	}

	// 3. Timeline (24h)
	now := time.Now().UTC()
	for i := 0; i < 24; i++ {
		cs.Timeline[i] = HourStats{
			Time: now.Add(time.Duration(i-23) * time.Hour).Truncate(time.Hour),
		}
	}

	tRows, err := db.Query(`
		SELECT 
			strftime('%Y-%m-%d %H:00:00', timestamp) as hr,
			COUNT(*),
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE client_ip = ? AND timestamp > datetime('now', '-24 hours')
		GROUP BY hr
	`, ip)
	if err == nil {
		defer tRows.Close()
		aggMap := make(map[string]struct{ total, blocked int64 })
		for tRows.Next() {
			var hr string
			var hTotal, hBlocked int64
			if err := tRows.Scan(&hr, &hTotal, &hBlocked); err == nil {
				aggMap[hr] = struct{ total, blocked int64 }{total: hTotal, blocked: hBlocked}
			}
		}

		for i := 0; i < 24; i++ {
			hrKey := cs.Timeline[i].Time.Format("2006-01-02 15:04:05")
			if a, ok := aggMap[hrKey]; ok {
				cs.Timeline[i].Total = a.total
				cs.Timeline[i].Blocked = a.blocked
				if cs.Timeline[i].Total < cs.Timeline[i].Blocked {
					cs.Timeline[i].Total = cs.Timeline[i].Blocked
				}
				cs.Timeline[i].Allowed = cs.Timeline[i].Total - cs.Timeline[i].Blocked
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
		WHERE client_ip = ? AND status LIKE 'Blocked%' AND timestamp > datetime('now', '-24 hours')
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
	if err != nil && !testMode {
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
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0)
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

func Get24hStats() (int64, int64, int64, error) {
	if db == nil {
		return 0, 0, 0, fmt.Errorf("DB not initialized")
	}

	var total, blocked, cacheHits int64
	now := time.Now().UTC()
	curHour := now.Truncate(time.Hour)
	curHourStr := curHour.Format("2006-01-02 15:04:05")

	// 1. Sum from hourly_stats (historical buckets)
	err := db.QueryRow(`
		SELECT COALESCE(SUM(total), 0), COALESCE(SUM(blocked), 0), COALESCE(SUM(cache_hits), 0)
		FROM hourly_stats 
		WHERE timestamp > datetime('now', '-24 hours') AND timestamp < ?
	`, curHourStr).Scan(&total, &blocked, &cacheHits)
	if err != nil {
		return 0, 0, 0, err
	}

	// 2. Add current hour from queries table (live data)
	var curTotal, curBlocked, curCacheHits int64
	err = db.QueryRow(`
		SELECT 
			COUNT(*), 
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN is_cache_hit = 1 THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE timestamp >= ?
	`, curHourStr).Scan(&curTotal, &curBlocked, &curCacheHits)
	if err != nil {
		return 0, 0, 0, err
	}

	return total + curTotal, blocked + curBlocked, cacheHits + curCacheHits, nil
}

func GetAverageLatency() (float64, error) {
	if db == nil {
		return 0, fmt.Errorf("DB not initialized")
	}
	var avg float64
	err := db.QueryRow("SELECT COALESCE(AVG(duration_ms), 0) FROM queries WHERE timestamp > datetime('now', '-24 hours')").Scan(&avg)
	return avg, err
}
