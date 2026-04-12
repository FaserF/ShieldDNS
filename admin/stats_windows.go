//go:build windows

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

var startupTime = time.Now()

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procGetDiskFreeSpace = kernel32.NewProc("GetDiskFreeSpaceExW")
)

func fillCPUStats(stats map[string]interface{}) {
	stats["cpu_load"] = []string{"0.00", "0.00", "0.00"}
	stats["cpu_model"] = fmt.Sprintf("%s %s (%d Cores)", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	stats["cpu_cores"] = runtime.NumCPU()
}

func fillRAMStats(stats map[string]interface{}) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
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
	total, _, used, err := getWindowsDiskStats()
	if err == nil {
		stats["disk_total_gb"] = float64(total) / (1024 * 1024 * 1024)
		stats["disk_used_gb"] = float64(used) / (1024 * 1024 * 1024)
		stats["disk_percent"] = float64(used) / float64(total) * 100
		return
	}

	stats["disk_total_gb"] = 100.0
	stats["disk_used_gb"] = 0.0
	stats["disk_percent"] = 0.0
}

func getWindowsDiskStats() (total, free, used uint64, err error) {
	var lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes uint64
	path, _ := syscall.UTF16PtrFromString(".")
	r, _, err := procGetDiskFreeSpace.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)),
	)
	if r == 0 {
		return 0, 0, 0, err
	}

	return lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes, lpTotalNumberOfBytes - lpTotalNumberOfFreeBytes, nil
}
