package main

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

var (
	mdnsLock      sync.RWMutex
	mdnsHostnames = make(map[string]string) // IP -> hostname
)

// GetMDNSHostname returns a passively discovered .local hostname for the given IP if known.
func GetMDNSHostname(ip string) string {
	mdnsLock.RLock()
	defer mdnsLock.RUnlock()
	return mdnsHostnames[ip]
}

// StartPassiveMDNSListener listens on 224.0.0.251:5353 for mDNS announcements to enrich device names.
func StartPassiveMDNSListener(ctx context.Context) {
	go func() {
		addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
		if err != nil {
			return
		}
		conn, err := net.ListenMulticastUDP("udp4", nil, addr)
		if err != nil {
			slog.Debug("Passive mDNS listener unavailable", "error", err)
			return
		}
		defer conn.Close()
		slog.Info("Passive mDNS device discovery started", "addr", "224.0.0.251:5353")

		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()

		buf := make([]byte, 4096)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var msg dns.Msg
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}
			for _, rr := range append(msg.Answer, msg.Extra...) {
				switch v := rr.(type) {
				case *dns.A:
					host := strings.TrimSuffix(strings.ToLower(v.Hdr.Name), ".")
					if strings.HasSuffix(host, ".local") && v.A != nil {
						mdnsLock.Lock()
						mdnsHostnames[v.A.String()] = host
						mdnsLock.Unlock()
					}
				case *dns.AAAA:
					host := strings.TrimSuffix(strings.ToLower(v.Hdr.Name), ".")
					if strings.HasSuffix(host, ".local") && v.AAAA != nil {
						mdnsLock.Lock()
						mdnsHostnames[v.AAAA.String()] = host
						mdnsLock.Unlock()
					}
				}
			}
		}
	}()
}
