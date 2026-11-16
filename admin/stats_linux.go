//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
)

func fillCPUStats(stats map[string]interface{}) {
	// CPU Load
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			l1, _ := strconv.ParseFloat(fields[0], 64)
			l5, _ := strconv.ParseFloat(fields[1], 64)
			l15, _ := strconv.ParseFloat(fields[2], 64)
			stats["cpu_load"] = []float64{l1, l5, l15}
		}
	}

	// CPU Info - check multiple potential prefixes for different architectures
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		foundModel := false
		for _, prefix := range []string{"model name", "Hardware", "Model", "Processor"} {
			for _, line := range lines {
				if strings.HasPrefix(strings.ToLower(line), strings.ToLower(prefix)) {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						stats["cpu_model"] = strings.TrimSpace(parts[1])
						foundModel = true
						break
					}
				}
			}
			if foundModel {
				break
			}
		}
		// Count cores
		cores := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "processor") {
				cores++
			}
		}
		stats["cpu_cores"] = cores
	}
}

func readCgroupMemory() (limitBytes int64, usageBytes int64) {
	// Cgroup v2
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" && s != "max" {
			limitBytes, _ = strconv.ParseInt(s, 10, 64)
		}
	}
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.current"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			usageBytes, _ = strconv.ParseInt(s, 10, 64)
		}
	}
	// Fallback to Cgroup v1 if v2 wasn't set or was max
	if limitBytes <= 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
			s := strings.TrimSpace(string(data))
			if s != "" {
				l, _ := strconv.ParseInt(s, 10, 64)
				// Linux sets an astronomical number (~9e18) if no limit in v1
				if l > 0 && l < 1<<60 {
					limitBytes = l
				}
			}
		}
	}
	if usageBytes <= 0 {
		if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.usage_in_bytes"); err == nil {
			s := strings.TrimSpace(string(data))
			if s != "" {
				usageBytes, _ = strconv.ParseInt(s, 10, 64)
			}
		}
	}
	return limitBytes, usageBytes
}

func fillRAMStats(stats map[string]interface{}) {
	var hostTotal, hostAvailable int64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseInt(fields[1], 10, 64)
			if fields[0] == "MemTotal:" {
				hostTotal = val
			} else if fields[0] == "MemAvailable:" {
				hostAvailable = val
			}
		}
	}

	cgLimit, cgUsage := readCgroupMemory()
	finalTotal := hostTotal
	finalAvailable := hostAvailable

	if cgLimit > 0 {
		cgLimitKB := cgLimit / 1024
		if hostTotal == 0 || cgLimitKB < hostTotal {
			finalTotal = cgLimitKB
		}
	}

	if cgUsage > 0 && cgLimit > 0 {
		cgAvailKB := (cgLimit - cgUsage) / 1024
		if cgAvailKB < 0 {
			cgAvailKB = 0
		}
		if hostAvailable == 0 || cgAvailKB < hostAvailable {
			finalAvailable = cgAvailKB
		}
	}

	if finalTotal > 0 {
		used := finalTotal - finalAvailable
		if used < 0 {
			used = 0
		}
		stats["ram"] = map[string]interface{}{
			"total":          finalTotal,
			"used":           used,
			"available":      finalAvailable,
			"host_total":     hostTotal,
			"host_available": hostAvailable,
		}
	}
}

func fillUptimeStats(stats map[string]interface{}) {
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptimeSeconds, _ := strconv.ParseFloat(fields[0], 64)
			stats["uptime_seconds"] = int64(uptimeSeconds)
		}
	}
}

func fillDiskStats(stats map[string]interface{}) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err == nil {
		total := fs.Blocks * uint64(fs.Bsize)
		free := fs.Bfree * uint64(fs.Bsize)
		used := total - free
		stats["disk"] = map[string]interface{}{
			"total": total, // in Bytes
			"used":  used,  // in Bytes
		}
	}
}
