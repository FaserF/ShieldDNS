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
		"total": total / 1024, // in KB
		"used":  used / 1024,  // in KB
	}
}

func fillUptimeStats(stats map[string]interface{}) {
	stats["uptime_seconds"] = int64(time.Since(startupTime).Seconds())
}

func fillDiskStats(stats map[string]interface{}) {
	total, _, used, err := getWindowsDiskStats()
	if err != nil {
		total = 100 * 1024 * 1024 * 1024
		used = 0
	}

	stats["disk"] = map[string]interface{}{
		"total": total, // in Bytes
		"used":  used,  // in Bytes
	}
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
