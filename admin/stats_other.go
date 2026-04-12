//go:build !linux && !windows

package main

import (
	"runtime"
	"time"
    "fmt"
)

var startupTime = time.Now()

func fillCPUStats(stats map[string]interface{}) {
	stats["cpu_load"] = []string{"0.00", "0.00", "0.00"}
	stats["cpu_model"] = fmt.Sprintf("%s %s (%d Cores)", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
    stats["cpu_cores"] = runtime.NumCPU()
}

func fillRAMStats(stats map[string]interface{}) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
    
    // On non-linux, we show the process memory as "used" 
    // and a large mock as "total" to prevent UI from showing 0
    total := uint64(16 * 1024 * 1024 * 1024) // 16GB Mock
    used := m.Sys
    
	stats["ram_total_mb"] = int64(total / (1024 * 1024))
	stats["ram_used_mb"] = int64(used / (1024 * 1024))
    stats["ram_percent"] = float64(used) / float64(total) * 100
}

func fillUptimeStats(stats map[string]interface{}) {
	stats["uptime_seconds"] = int64(time.Since(startupTime).Seconds())
}

func fillDiskStats(stats map[string]interface{}) {
    // Attempt real disk stats on Windows
    if runtime.GOOS == "windows" {
        total, _, used, err := getWindowsDiskStats()
        if err == nil {
            stats["disk_total_gb"] = float64(total) / (1024 * 1024 * 1024)
            stats["disk_used_gb"] = float64(used) / (1024 * 1024 * 1024)
            stats["disk_percent"] = float64(used) / float64(total) * 100
            return
        }
    }

	stats["disk_total_gb"] = 100.0
	stats["disk_used_gb"] = 0.0
	stats["disk_percent"] = 0.0
}

func getWindowsDiskStats() (total, free, used uint64, err error) {
    // We use a separate helper or syscall directly
    // This part is only called when GOOS == windows
    return 0, 0, 0, fmt.Errorf("not implemented")
}
