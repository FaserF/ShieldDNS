package main

import (
	"context"
	"log/slog"
	"net"
	"time"
)

// startDNSWatchdog periodically checks if CoreDNS is actually responding to queries.
func startDNSWatchdog() {
	ticker := time.NewTicker(2 * time.Minute)
	failureCount := 0

	slog.Info("DNS Health Watchdog started")

	for range ticker.C {
		// Create a resolver that specifically targets the local DNS server
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", "127.0.0.1:53")
			},
		}

		// Try to resolve our built-in test domain to verify filtering is active
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := r.LookupHost(ctx, "shielddns-maleware.test")
		cancel()

		if err != nil {
			failureCount++
			slog.Warn("DNS health check failed", "error", err, "failures", failureCount)
			
			// Critical failure: CoreDNS might be hung or crashed
			if failureCount >= 3 {
				slog.Error("DNS health check failed 3 consecutive times. Initiating CoreDNS restart...")
				restartCoreDNS()
				failureCount = 0 // Reset after restart attempt
				
				// Extra wait to allow restart to settle
				time.Sleep(10 * time.Second)
			}
		} else {
			if failureCount > 0 {
				slog.Info("DNS health check recovered")
			}
			failureCount = 0
		}
	}
}
