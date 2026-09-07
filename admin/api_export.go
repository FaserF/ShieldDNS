package main

import (
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

func handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	search := r.URL.Query().Get("search")
	statusFilter := r.URL.Query().Get("status")
	fromTime := r.URL.Query().Get("from_time")
	toTime := r.URL.Query().Get("to_time")

	query := "SELECT timestamp, domain, type, status, client_ip, node_name FROM queries WHERE 1=1"
	var args []interface{}

	if search != "" {
		query += " AND (domain LIKE ? OR client_ip LIKE ? OR node_name LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%", "%"+search+"%")
	}
	if statusFilter != "" {
		if statusFilter == "Blocked" {
			query += " AND status LIKE ?"
			args = append(args, StatusBlocked+"%")
		} else {
			query += " AND status = ?"
			args = append(args, statusFilter)
		}
	}
	if fromTime != "" {
		query += " AND timestamp >= ?"
		args = append(args, strings.ReplaceAll(fromTime, "T", " "))
	}
	if toTime != "" {
		query += " AND timestamp <= ?"
		args = append(args, strings.ReplaceAll(toTime, "T", " "))
	}

	query += " ORDER BY timestamp DESC LIMIT 50000"

	rows, err := db.Query(query, args...)
	if err != nil {
		slog.Error("Export failed: DB query error", "error", err, "query", query)
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.csv")

		writer := csv.NewWriter(w)
		defer writer.Flush()

		// Header
		writer.Write([]string{"Timestamp", "Domain", "Type", "Status", "ClientIP", "NodeName"})

		for rows.Next() {
			var ts, domain, qtype, status, ip string
			var node *string
			if err := rows.Scan(&ts, &domain, &qtype, &status, &ip, &node); err == nil {
				nodeStr := ""
				if node != nil {
					nodeStr = *node
				}
				writer.Write([]string{ts, domain, qtype, status, ip, nodeStr})
			}
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.json")

		// Use a streaming JSON encoder
		enc := json.NewEncoder(w)
		w.Write([]byte("["))

		first := true
		for rows.Next() {
			var ts, domain, qtype, status, ip string
			var node *string
			if err := rows.Scan(&ts, &domain, &qtype, &status, &ip, &node); err == nil {
				if !first {
					w.Write([]byte(","))
				}
				first = false
				nodeStr := ""
				if node != nil {
					nodeStr = *node
				}
				enc.Encode(map[string]string{
					"timestamp": ts,
					"domain":    domain,
					"type":      qtype,
					"status":    status,
					"client_ip": ip,
					"node_name": nodeStr,
				})
			}
		}
		w.Write([]byte("]"))
	}
}
