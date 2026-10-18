package main

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func BenchmarkFlushLogs(b *testing.B) {
	os.Remove("bench_final.db")
	dbFinal, err := sql.Open("sqlite", "bench_final.db")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove("bench_final.db")
	defer dbFinal.Close()

	// Assign the global variable to point to our test db instance
	db = dbFinal

	_, err = dbFinal.Exec(`
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
	`)
	if err != nil {
		b.Fatal(err)
	}

	queries := make([]Query, 1000)
	for i := 0; i < 1000; i++ {
		queries[i] = Query{
			Time:        time.Now(),
			Domain:      "example.com",
			Type:        "A",
			Status:      "OK",
			ClientIP:    "192.168.1.1",
			IsCacheHit:  false,
			DurationMs:  1.5,
			CountryCode: "US",
			NodeName:    "node1",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		flushLogs(queries)
	}
}
