//go:build !linux

package main

import (
	"runtime"
	"time"
)

var startupTime = time.Now()

func fillCPUStats(stats map[string]interface{}) {
	stats["cpu_load"] = []float64{0.0, 0.0, 0.0}
	stats["cpu_model"] = runtime.GOOS + " " + runtime.GOARCH + " (No Load Avg support)"
}

func fillRAMStats(stats map[string]interface{}) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// We just show process memory usage as a mockup on Windows
	stats["ram"] = map[string]interface{}{
		"total": 16 * 1024 * 1024 * 1024.0, // mock 16GB
		"used":  float64(m.Sys),
		"free":  16*1024*1024*1024.0 - float64(m.Sys),
	}
}

func fillUptimeStats(stats map[string]interface{}) {
	stats["uptime_seconds"] = int64(time.Since(startupTime).Seconds())
}

func fillDiskStats(stats map[string]interface{}) {
	// Disk stats not implemented for non-Linux OS without cgo/wmi dependencies
	stats["disk"] = map[string]interface{}{
		"total": 100 * 1024 * 1024 * 1024.0, // mock 100GB
		"used":  0.0,
		"free":  100 * 1024 * 1024 * 1024.0,
	}
}
