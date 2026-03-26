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
			client_ip TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON queries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_status ON queries(status);
		CREATE INDEX IF NOT EXISTS idx_client ON queries(client_ip);
	`)
	if err != nil {
		log.Fatalf("Fatal: Could not initialize database schema: %v", err)
	}
}

func startRetentionWorker() {
	ticker := time.NewTicker(12 * time.Hour)
	for range ticker.C {
		configLock.RLock()
		days := config.RetentionDays
		if days <= 0 {
			days = 30
		}
		configLock.RUnlock()

		if db != nil {
			_, err := db.Exec("DELETE FROM queries WHERE timestamp < datetime('now', ?)", fmt.Sprintf("-%d days", days))
			if err != nil {
				log.Printf("Error cleaning up old queries: %v", err)
			} else {
				log.Printf("Cleaned up queries older than %d days", days)
			}
		}
	}
}

func startDBWorker() {
	// Periodic cleanup of old queries (30 days default if retention disabled somehow)
	ticker := time.NewTicker(24 * time.Hour)
	cleanup := func() {
		_, err := db.Exec("DELETE FROM queries WHERE timestamp < datetime('now', '-30 days')")
		if err != nil {
			log.Printf("Error purging old queries: %v", err)
		} else {
			log.Println("Database maintenance: Old queries purged.")
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

	stmt, err := tx.Prepare("INSERT INTO queries (timestamp, domain, type, status, client_ip) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("Error preparing log statement: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, q := range toFlush {
		_, err = stmt.Exec(q.Time.Format(time.RFC3339), q.Domain, q.Type, q.Status, q.ClientIP)
		if err != nil {
			log.Printf("Error executing log statement: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing log transaction: %v", err)
	}
}
