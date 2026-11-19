package main

import (
	"net"
	"net/http"
	"strings"
)

func ingressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingressPath := r.Header.Get("X-Ingress-Path")
		if ingressPath != "" {
			ingressPath = strings.TrimSuffix(ingressPath, "/")
			if strings.HasPrefix(r.URL.Path, ingressPath) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, ingressPath)
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isLocalOrTailnetHost(hostHeader string) bool {
	h := hostHeader
	if host, _, err := net.SplitHostPort(hostHeader); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSpace(h))

	if h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "shielddns.local" {
		return true
	}
	configLock.RLock()
	adminDomain := strings.ToLower(strings.TrimSpace(config.AdminDomain))
	workerDomain := strings.ToLower(strings.TrimSpace(config.ClusterWorkerDomain))
	trustedDomains := append([]string{}, config.TrustedHostDomains...)
	configLock.RUnlock()
	if adminDomain != "" && (h == adminDomain || strings.HasSuffix(h, "."+adminDomain)) {
		return true
	}
	if workerDomain != "" && (h == workerDomain || strings.HasSuffix(h, "."+workerDomain)) {
		return true
	}
	if strings.HasSuffix(h, ".local") || strings.HasSuffix(h, ".lan") ||
		strings.HasSuffix(h, ".home.arpa") || strings.HasSuffix(h, ".internal") {
		return true
	}
	for _, td := range trustedDomains {
		clean := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(td)), ".")
		if clean != "" && (h == clean || strings.HasSuffix(h, "."+clean)) {
			return true
		}
	}

	ip := net.ParseIP(h)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
		// Tailscale CGNAT range 100.64.0.0/10
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 100 && (ip4[1]&0xc0) == 64 {
				return true
			}
		}
	}
	return false
}
