package main

import (
	"context"
	"log/slog"
	"net"
	"time"
)

// startDNSWatchdog periodically checks if CoreDNS is actually responding to queries.
func startDNSWatchdog(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	failureCount := 0

	slog.Info("DNS Health Watchdog started")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Create a resolver that specifically targets the local DNS server
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{Timeout: 5 * time.Second}
					return d.DialContext(dialCtx, "udp", "127.0.0.1:53")
				},
			}

			// Try to resolve a known stable domain to verify connectivity.
			// Using a malware domain for health checks is risky because a successful block
			// (NXDOMAIN) would be interpreted as a failure by LookupHost.
			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, err := r.LookupHost(checkCtx, "google.com")
			cancel()

			if err != nil {
				failureCount++
				slog.Warn("DNS health check failed", "error", err, "failures", failureCount)

				// Critical failure: CoreDNS might be hung or crashed
				if failureCount >= 3 {
					statsLock.Lock()
					stats.CoreDNSAlive = false
					statsLock.Unlock()

					slog.Error("DNS health check failed 3 consecutive times. Initiating CoreDNS restart...")
					restartCoreDNS()
					failureCount = 0 // Reset after restart attempt

					// Extra wait to allow restart to settle
					select {
					case <-ctx.Done():
						return
					case <-time.After(10 * time.Second):
					}
				}
			} else {
				if failureCount > 0 {
					slog.Info("DNS health check recovered")
				}
				failureCount = 0

				statsLock.Lock()
				stats.CoreDNSAlive = true
				statsLock.Unlock()
			}
		}
	}
}
