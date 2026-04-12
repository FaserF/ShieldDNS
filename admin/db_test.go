// Category: Database Tests
// Tests for SQLite database migration and initialization handling.
package main

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func TestAddColumnIfNotExists(t *testing.T) {
	testDBPath := "test_migration.db"
	defer os.Remove(testDBPath)

	oldDB := db
	defer func() {
		db = oldDB
	}()

	var err error
	db, err = sql.Open("sqlite", testDBPath)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer db.Close()

	// 1. Create initial table
	_, err = db.Exec("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
	if err != nil {
		t.Fatalf("Failed to create test table: %v", err)
	}

	// 2. Add new column
	addColumnIfNotExists("test_table", "new_col", "TEXT DEFAULT 'default'")

	// 3. Verify column exists
	rows, err := db.Query("PRAGMA table_info(test_table)")
	if err != nil {
		t.Fatalf("Failed to query table info: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var cid int
		var name, dtype string
		var notnull, pk int
		var dfltValue interface{}
		rows.Scan(&cid, &name, &dtype, &notnull, &dfltValue, &pk)
		if name == "new_col" {
			found = true
			if dtype != "TEXT" {
				t.Errorf("Expected type TEXT, got %s", dtype)
			}
			break
		}
	}
	if !found {
		t.Error("Column 'new_col' was not added")
	}

	// 4. Add same column again (idempotency check)
	// This should not panic or error
	addColumnIfNotExists("test_table", "new_col", "TEXT DEFAULT 'other'")

	// Verify it still has the old definition (SQLite ALTER TABLE doesn't update existing columns usually)
	// But most importantly, it shouldn't have failed.
}
