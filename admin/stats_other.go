//go:build !linux && !windows

package main

import (
	"fmt"
	"runtime"
	"time"
)

var startupTime = time.Now()

func fillCPUStats(stats map[string]interface{}) {
	stats["cpu_load"] = []float64{0.00, 0.00, 0.00}
	stats["cpu_model"] = fmt.Sprintf("%s %s (%d Cores)", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	stats["cpu_cores"] = runtime.NumCPU()
}

func fillRAMStats(stats map[string]interface{}) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	total := uint64(16 * 1024 * 1024 * 1024) // 16GB Mock
	used := m.Sys

	stats["ram"] = map[string]interface{}{
		"total": total / 1024,
		"used":  used / 1024,
	}
}

func fillUptimeStats(stats map[string]interface{}) {
	stats["uptime_seconds"] = int64(time.Since(startupTime).Seconds())
}

func fillDiskStats(stats map[string]interface{}) {
	stats["disk"] = map[string]interface{}{
		"total": uint64(100 * 1024 * 1024 * 1024),
		"used":  uint64(0),
	}
}

func getWindowsDiskStats() (total, free, used uint64, err error) {
	// We use a separate helper or syscall directly
	// This part is only called when GOOS == windows
	return 0, 0, 0, fmt.Errorf("not implemented")
}
