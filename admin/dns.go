package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

type CorefileData struct {
	DNSPort          string
	DOTPort          string
	InternalDOHPort  string
	DNSSEC           bool
	ServeStale       bool
	Upstreams        string
	TLSServerName    string
	Policy           string
	HostsPath        string
	GeoACLRules      string
	CertFile         string
	KeyFile          string
	FilteringEnabled bool
	HasCerts         bool
	RateLimitRate    int
	RateLimitBurst   int
	RoutingBlocks    string
}

const CorefileTemplate = `{{.RoutingBlocks}}
.:{{.DNSPort}} {
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    health 127.0.0.1:8082
    reload 5s
    {{if .FilteringEnabled}}
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{end}}
    cache 3600 {
        success 50000
        denial 30000
        prefetch 5 1m 10%
        serve_stale 1h
    }
    forward . {{.Upstreams}} {
        health_check 5s
        max_fails 2
        expire 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

{{if .HasCerts}}
tls://.:{{.DOTPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    reload 5s
    {{if .FilteringEnabled}}
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{end}}
    cache 3600 {
        success 50000
        denial 30000
        prefetch 5 1m 10%
        serve_stale 1h
    }
    forward . {{.Upstreams}} {
        health_check 5s
        max_fails 2
        expire 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

https://.:{{.InternalDOHPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    reload 5s
    {{if .FilteringEnabled}}
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{end}}
    cache 3600 {
        success 50000
        denial 30000
        prefetch 5 1m 10%
        serve_stale 1h
    }
    forward . {{.Upstreams}} {
        health_check 5s
        max_fails 2
        expire 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

quic://.:{{.DOTPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    quic {
        max_streams 50
        worker_pool_size 256
    }
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    reload 5s
    {{if .FilteringEnabled}}
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{end}}
    cache 3600 {
        success 50000
        denial 30000
        prefetch 5 1m 10%
        serve_stale 1h
    }
    forward . {{.Upstreams}} {
        health_check 5s
        max_fails 2
        expire 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}
{{end}}
`


type querySignature struct {
	ip   string
	time time.Time
}

type cacheEntry struct {
	ip        string
	expiresAt time.Time
}

var (
	recentQueries     = make(map[string]querySignature)
	recentQueriesLock sync.Mutex
	sseChan           = make(chan Query, 1024)
	logQueue          = make(chan string, 10000)

	resolveCache     = make(map[string]cacheEntry)
	resolveCacheLock sync.Mutex
)

func startDNSWorkers(ctx context.Context) {
	// 1. Background cleanup for recent query signatures
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupRecentQueries()
			}
		}
	}()

	// 2. Central SSE Broadcaster
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case q := <-sseChan:
				broadcastSSE(q)
			}
		}
	}()

	// 3. Abuse Detection Analyzer
	go startAbuseAnalyzer(ctx)

	// 4. Log Parsing Worker Pool
	startLogParsers(ctx)
}

func startLogParsers(ctx context.Context) {
	numWorkers := 4 // Scale based on expected CPU cores if needed
	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case line := <-logQueue:
					parseLogLine(line)
				}
			}
		}()
	}
}

func broadcastSSE(query Query) {
	sseLock.Lock()
	if len(sseClients) == 0 {
		sseLock.Unlock()
		return
	}
	// Create a local copy of clients to broadcast outside the lock
	clients := make([]chan Query, 0, len(sseClients))
	for ch := range sseClients {
		clients = append(clients, ch)
	}
	sseLock.Unlock()

	for _, ch := range clients {
		select {
		case ch <- query:
		default:
			// Full channel, skip to avoid stalling the broadcaster
		}
	}
}

func cleanupRecentQueries() {
	now := time.Now()
	recentQueriesLock.Lock()
	defer recentQueriesLock.Unlock()

	// Keep if less than 10s old
	for k, v := range recentQueries {
		if now.Sub(v.time) > 10*time.Second {
			delete(recentQueries, k)
		}
	}
}

func resolveHost(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}

	resolveCacheLock.Lock()
	if entry, ok := resolveCache[host]; ok {
		if time.Now().Before(entry.expiresAt) {
			resolveCacheLock.Unlock()
			return entry.ip
		}
	}
	resolveCacheLock.Unlock()

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return host
	}

	// Prefer IPv4 for better compatibility in many networks/containers
	var ip string
	for _, i := range ips {
		if i.To4() != nil {
			ip = i.String()
			break
		}
	}
	if ip == "" {
		ip = ips[0].String()
	}

	resolveCacheLock.Lock()
	resolveCache[host] = cacheEntry{
		ip:        ip,
		expiresAt: time.Now().Add(1 * time.Hour), // 1 hour TTL
	}
	resolveCacheLock.Unlock()
	return ip
}

func startCoreDNS(ctx context.Context) {
	if testMode {
		return
	}
	for {
		select {
		case <-ctx.Done():
			dnsCmdLock.Lock()
			cmd := dnsCmd
			dnsCmdLock.Unlock()
			if cmd != nil && cmd.Process != nil {
				cmd.Process.Signal(os.Interrupt)
			}
			return
		default:
			dnsCmdLock.Lock()
			if dnsCmd != nil && dnsCmd.Process != nil {
				dnsCmdLock.Unlock()
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Second):
					continue
				}
			}

			slog.Info("Starting CoreDNS")
			cmd := exec.CommandContext(ctx, "coredns", "-conf", CorefilePath)
			stdout, _ := cmd.StdoutPipe()
			stderr, _ := cmd.StderrPipe()

			if err := cmd.Start(); err != nil {
				slog.Error("Error starting CoreDNS (executable missing or permission denied?)", "error", err)
				dnsCmdLock.Unlock()
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Second):
					continue
				}
			}

			dnsCmd = cmd
			dnsCmdLock.Unlock()

			go func(reader io.Reader) {
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					line := scanner.Text()
					configLock.RLock()
					debug := config.DebugMode
					configLock.RUnlock()
					if debug {
						slog.Info(line, "source", "coredns")
					}
					select {
					case logQueue <- line:
					default:
						// Queue full, drop log to avoid blocking CoreDNS under extreme load
						if debug {
							slog.Debug("Log queue full, dropping line", "source", "coredns")
						}
					}
				}
			}(stdout)

			go func(reader io.Reader) {
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					line := scanner.Text()
					slog.Error(line, "source", "coredns-err")
					AddSystemLog("[CoreDNS-ERR] " + line)
				}
			}(stderr)

			cmd.Wait()

			dnsCmdLock.Lock()
			dnsCmd = nil
			dnsCmdLock.Unlock()

			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("CoreDNS exited. Restarting...")
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func restartCoreDNS() {
	if testMode {
		return
	}
	dnsCmdLock.Lock()
	running := dnsCmd != nil && dnsCmd.Process != nil
	dnsCmdLock.Unlock()

	if running {
		slog.Info("CoreDNS config/lists updated. CoreDNS reloading in-place via reload plugin.")
		return
	}
	slog.Info("CoreDNS not running. Starting CoreDNS process...")
	go startCoreDNS(appCtx)
}

func forceRestartCoreDNS() {
	if testMode {
		return
	}
	dnsCmdLock.Lock()
	cmd := dnsCmd
	dnsCmdLock.Unlock()

	if cmd != nil && cmd.Process != nil {
		slog.Info("Force restarting CoreDNS process...")
		cmd.Process.Signal(os.Interrupt)
		go func(p *os.Process) {
			time.Sleep(2 * time.Second)
			p.Kill()
		}(cmd.Process)
		time.Sleep(500 * time.Millisecond)
	} else {
		go startCoreDNS(appCtx)
	}
}


