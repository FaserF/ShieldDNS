//go:build !linux

package main

func fillCPUStats(stats map[string]interface{}) {
	// N/A on Windows
}

func fillRAMStats(stats map[string]interface{}) {
	// N/A on Windows
}

func fillUptimeStats(stats map[string]interface{}) {
	// N/A on Windows
}

func fillDiskStats(stats map[string]interface{}) {
	// Disk stats not implemented for non-Linux OS
}
