package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var coreDNSEverStarted atomic.Bool

type CorefileData struct {
	DNSPort            string
	DOTPort            string
	InternalDOHPort    string
	InternalEnginePort string
	InternalPolicyPort string
	DNSSEC             bool
	ServeStale         bool
	Upstreams          string
	TLSServerName      string
	Policy             string
	HostsPath          string
	GeoACLRules        string
	CertFile           string
	KeyFile            string
	FilteringEnabled   bool
	HasCerts           bool
	RateLimitRate      int
	RateLimitBurst     int
	RoutingBlocks      string
	TemplateBlocks     string
}

const CorefileTemplate = `{{.RoutingBlocks}}
.:{{.InternalEnginePort}} {
    bind 127.0.0.1
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    health 127.0.0.1:8082
    reload 10s
    {{if .FilteringEnabled}}
    hosts {{.HostsPath}} {
        reload 0
        fallthrough
    }
    {{end}}
{{.TemplateBlocks}}
    cache 3600 {
        success 50000
        denial 30000
        prefetch 5 1m 10%
        {{if .ServeStale}}serve_stale 1h{{end}}
    }
    forward . {{.Upstreams}} {
        health_check 5s
        max_fails 2
        expire 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    errors
}

.:{{.DNSPort}} {
    metadata
    reload 10s
    {{.GeoACLRules}}
    forward . 127.0.0.1:{{.InternalPolicyPort}} {
        expire 10s
    }
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

{{if .HasCerts}}
tls://.:{{.DOTPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    metadata
    reload 10s
    {{.GeoACLRules}}
    forward . 127.0.0.1:{{.InternalPolicyPort}} {
        expire 10s
    }
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

https://.:{{.InternalDOHPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    metadata
    {{.GeoACLRules}}
    forward . 127.0.0.1:{{.InternalPolicyPort}} {
        expire 10s
    }
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

quic://.:{{.DOTPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    quic {
        max_streams 50
        worker_pool_size 256
    }
    metadata
    reload 10s
    {{.GeoACLRules}}
    forward . 127.0.0.1:{{.InternalPolicyPort}} {
        expire 10s
    }
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

	resolveCache      = make(map[string]cacheEntry)
	resolveCacheLock  sync.Mutex
	resolveInflight   = make(map[string]*resolveCall)
	resolveInflightMu sync.Mutex
	coreDNSLoopActive atomic.Bool
	debugModeAtomic   atomic.Bool
	logDropCount      atomic.Int64
)

type resolveCall struct {
	wg  sync.WaitGroup
	val string
}

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
	defer sseLock.Unlock()
	for ch := range sseClients {
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

	now := time.Now()
	resolveCacheLock.Lock()
	if entry, ok := resolveCache[host]; ok {
		if now.Before(entry.expiresAt) {
			resolveCacheLock.Unlock()
			return entry.ip
		}
		delete(resolveCache, host)
	}
	if len(resolveCache) > 2048 {
		for k, v := range resolveCache {
			if !now.Before(v.expiresAt) {
				delete(resolveCache, k)
			}
		}
	}
	resolveCacheLock.Unlock()

	resolveInflightMu.Lock()
	if call, ok := resolveInflight[host]; ok {
		resolveInflightMu.Unlock()
		call.wg.Wait()
		return call.val
	}
	call := &resolveCall{}
	call.wg.Add(1)
	resolveInflight[host] = call
	resolveInflightMu.Unlock()

	defer func() {
		call.wg.Done()
		resolveInflightMu.Lock()
		delete(resolveInflight, host)
		resolveInflightMu.Unlock()
	}()

	ips := lookupHostViaConfiguredUpstreams(host)
	if len(ips) == 0 {
		ips, _ = net.LookupIP(host)
	}
	if len(ips) == 0 {
		call.val = host
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
	call.val = ip
	return ip
}

// lookupHostViaConfiguredUpstreams resolves host using the UI-configured plain DNS upstreams
// (skipping loopback/local/Tailnet self-IPs to prevent DNS self-resolution loops).
func lookupHostViaConfiguredUpstreams(host string) []net.IP {
	configLock.RLock()
	rawUpstreams := append([]string(nil), config.Upstreams...)
	configLock.RUnlock()

	for _, u := range rawUpstreams {
		uHost, uPort := splitAddr(strings.TrimSpace(u), "53")
		parsed := net.ParseIP(uHost)
		if parsed == nil || parsed.IsLoopback() || parsed.IsUnspecified() || IsPrivateOrTailnetIP(uHost) {
			continue
		}
		target := net.JoinHostPort(uHost, uPort)
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", target)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addrs, err := resolver.LookupIPAddr(ctx, host)
		cancel()
		if err == nil && len(addrs) > 0 {
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips
		}
	}
	return nil
}

func startCoreDNS(ctx context.Context) {
	if testMode {
		return
	}
	if !coreDNSLoopActive.CompareAndSwap(false, true) {
		return
	}
	defer coreDNSLoopActive.Store(false)
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
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				slog.Error("Error creating CoreDNS stdout pipe", "error", err)
				dnsCmdLock.Unlock()
				time.Sleep(1 * time.Second)
				continue
			}
			stderr, err := cmd.StderrPipe()
			if err != nil {
				slog.Error("Error creating CoreDNS stderr pipe", "error", err)
				dnsCmdLock.Unlock()
				time.Sleep(1 * time.Second)
				continue
			}

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
			coreDNSEverStarted.Store(true)
			dnsCmdLock.Unlock()

			var pipeWG sync.WaitGroup
			pipeWG.Add(2)

			go func(reader io.Reader) {
				defer pipeWG.Done()
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					line := scanner.Text()
					debug := debugModeAtomic.Load()
					if debug {
						slog.Info(line, "source", "coredns")
					}
					select {
					case logQueue <- line:
					default:
						// Queue full, drop log to avoid blocking CoreDNS under extreme load
						if dropped := logDropCount.Add(1); dropped%1000 == 1 {
							slog.Warn("CoreDNS log queue full, dropping lines", "total_dropped", dropped)
						}
					}
				}
			}(stdout)

			go func(reader io.Reader) {
				defer pipeWG.Done()
				scanner := bufio.NewScanner(reader)
				for scanner.Scan() {
					line := scanner.Text()
					slog.Error(line, "source", "coredns-err")
					AddSystemLog("[CoreDNS-ERR] " + line)
				}
			}(stderr)

			pipeWG.Wait()
			_ = cmd.Wait()

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
		_ = cmd.Process.Signal(os.Interrupt)
		go func(c *exec.Cmd) {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				dnsCmdLock.Lock()
				stillSame := dnsCmd == c
				dnsCmdLock.Unlock()
				if !stillSame {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			dnsCmdLock.Lock()
			stillSame := dnsCmd == c
			dnsCmdLock.Unlock()
			if stillSame && c.Process != nil {
				_ = c.Process.Kill()
			}
		}(cmd)
	} else {
		go startCoreDNS(appCtx)
	}
}
