package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	defaultYouTubeGeoDomains = []string{"youtube.com", "youtu.be", "googlevideo.com", "youtubei.googleapis.com", "youtube.googleapis.com", "youtube-nocookie.com", "ytimg.com", "ggpht.com", "gvt1.com", "video.google.com", "yt.be"}
	defaultTwitchGeoDomains  = []string{"usher.ttvnw.net", "gql.twitch.tv", "hls.ttvnw.net", "video-weaver.fra02.hls.ttvnw.net", "edge.ads.twitch.tv", "spade.twitch.tv"}
	defaultRedditGeoDomains  = []string{"gql.reddit.com", "oauth.reddit.com", "gateway.reddit.com", "alb.reddit.com", "w3-reporting.reddit.com"}
	defaultSpotifyGeoDomains = []string{"spclient.wg.spotify.com", "audio-fa.scdn.co", "heads-fa.scdn.co", "api-v2.soundcloud.com", "cf-hls-media.sndcdn.com"}
	defaultSocialGeoDomains  = []string{"tiktokv.com", "byteoversea.com", "i.instagram.com", "graph.instagram.com", "api.x.com", "api.twitter.com"}
	defaultSmartTVGeoDomains = []string{"lgad.cjpowercast.com", "ad.lgappstv.com", "SmartClip.net", "ads.samsung.com", "samsungads.com", "gpm.samsungqbe.com", "mas-ext.amazon.com", "aax-eu.amazon-adsystem.com"}
)

func activeServiceGeoZones(cfg *Config) [][]string {
	var sets [][]string
	if cfg.YouTubeAdblockEnabled && (!cfg.NextDNSYouTube || isNextDNSQuotaExceeded(cfg)) {
		sets = append(sets, defaultYouTubeGeoDomains)
	}
	if cfg.TwitchAdblockEnabled {
		sets = append(sets, defaultTwitchGeoDomains)
	}
	if cfg.RedditAdblockEnabled && (!cfg.NextDNSReddit || isNextDNSQuotaExceeded(cfg)) {
		sets = append(sets, defaultRedditGeoDomains)
	}
	if cfg.SpotifyAdblockEnabled {
		sets = append(sets, defaultSpotifyGeoDomains)
	}
	if cfg.SocialAdblockEnabled {
		sets = append(sets, defaultSocialGeoDomains)
	}
	if cfg.SmartTVAdblockEnabled {
		sets = append(sets, defaultSmartTVGeoDomains)
	}
	return sets
}

// GetEffectiveGeoProxyIP returns the IPv4 address that DNS should return for SmartDNS/Geo-routed domains.
func GetEffectiveGeoProxyIP(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	for _, candidate := range []string{cfg.GeoProxyIP, cfg.BlockPageIP, detectedServerIP} {
		ip := strings.TrimSpace(candidate)
		if ip != "" && ip != "0.0.0.0" && ip != "127.0.0.1" && net.ParseIP(ip) != nil {
			return ip
		}
	}
	if dom := strings.TrimSpace(cfg.AdminDomain); dom != "" && dom != "shielddns.local" {
		if ip := resolveHost(dom); ip != "" && ip != "0.0.0.0" && ip != "127.0.0.1" && net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// GetGeoRoutedZones returns the deduplicated list of apex/exact zones that should be redirected to the Geo-Proxy IP.
func GetGeoRoutedZones(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]bool)
	var zones []string

	addZone := func(d string) {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "*."))
		d = strings.Trim(d, ".")
		if d != "" && isValidDomain(d) && !seen[d] {
			for _, r := range cfg.RoutingRules {
				if r.Enabled && r.Target == "nextdns" && !isNextDNSQuotaExceeded(cfg) && strings.EqualFold(strings.TrimPrefix(r.Match, "*."), d) {
					return
				}
			}
			seen[d] = true
			zones = append(zones, d)
		}
	}

	for _, list := range activeServiceGeoZones(cfg) {
		for _, z := range list {
			addZone(z)
		}
	}

	for _, rule := range cfg.RoutingRules {
		if rule.Enabled && rule.MatchType != "client_ip" && (rule.Target == "vpn" || rule.Target == "geo_proxy") {
			addZone(rule.Match)
		}
	}
	return zones
}

// MatchSNIGeoRoute checks if an incoming TLS SNI hostname is authorized for Geo-Proxy routing
// and returns the upstream proxy URL (empty string for direct connection if no proxy URL is configured) and whether it matched.
func MatchSNIGeoRoute(cfg *Config, sni string) (string, bool) {
	if cfg == nil {
		return "", false
	}
	sni = strings.ToLower(strings.Trim(strings.TrimSpace(sni), "."))
	if sni == "" || !isValidDomain(sni) {
		return "", false
	}
	if adminDom := strings.ToLower(strings.Trim(strings.TrimSpace(cfg.AdminDomain), ".")); adminDom != "" && strings.EqualFold(sni, adminDom) {
		return "", false
	}

	for _, rule := range cfg.RoutingRules {
		if !rule.Enabled || rule.MatchType == "client_ip" || (rule.Target != "vpn" && rule.Target != "geo_proxy") {
			continue
		}
		m := strings.ToLower(strings.TrimPrefix(strings.Trim(strings.TrimSpace(rule.Match), "."), "*."))
		if m != "" && (sni == m || strings.HasSuffix(sni, "."+m)) {
			proxyURL := strings.TrimSpace(rule.ProxyURL)
			if proxyURL == "" && cfg.VPNCountryProxies != nil && rule.Country != "" {
				proxyURL = strings.TrimSpace(cfg.VPNCountryProxies[strings.ToUpper(strings.TrimSpace(rule.Country))])
			}
			if proxyURL == "" {
				proxyURL = strings.TrimSpace(cfg.VPNProxyURL)
			}
			return proxyURL, true
		}
	}

	for _, list := range activeServiceGeoZones(cfg) {
		for _, yd := range list {
			d := strings.ToLower(yd)
			if sni == d || strings.HasSuffix(sni, "."+d) {
				return strings.TrimSpace(cfg.VPNProxyURL), true
			}
		}
	}
	return "", false
}

// ExtractTLSSNI parses a TLS ClientHello record from the initial bytes and extracts the ServerName (SNI).
func ExtractTLSSNI(data []byte) string {
	// TLS Record header: Type (1B = 0x16 Handshake), Version (2B), Length (2B)
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recLen {
		recLen = len(data) - 5
	}
	buf := data[5 : 5+recLen]

	// Handshake header: Type (1B = 0x01 ClientHello), Length (3B)
	if len(buf) < 4 || buf[0] != 0x01 {
		return ""
	}
	hsLen := int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	buf = buf[4:]
	if len(buf) > hsLen {
		buf = buf[:hsLen]
	}

	// ClientVersion (2B) + Random (32B) = 34B
	if len(buf) < 34 {
		return ""
	}
	buf = buf[34:]

	// SessionID (1B length + SessionID)
	if len(buf) < 1 {
		return ""
	}
	sessIDLen := int(buf[0])
	buf = buf[1:]
	if len(buf) < sessIDLen {
		return ""
	}
	buf = buf[sessIDLen:]

	// CipherSuites (2B length + suites)
	if len(buf) < 2 {
		return ""
	}
	csLen := int(buf[0])<<8 | int(buf[1])
	buf = buf[2:]
	if len(buf) < csLen {
		return ""
	}
	buf = buf[csLen:]

	// CompressionMethods (1B length + methods)
	if len(buf) < 1 {
		return ""
	}
	compLen := int(buf[0])
	buf = buf[1:]
	if len(buf) < compLen {
		return ""
	}
	buf = buf[compLen:]

	// Extensions (2B length)
	if len(buf) < 2 {
		return ""
	}
	extTotalLen := int(buf[0])<<8 | int(buf[1])
	buf = buf[2:]
	if len(buf) > extTotalLen {
		buf = buf[:extTotalLen]
	}

	for len(buf) >= 4 {
		extType := int(buf[0])<<8 | int(buf[1])
		extLen := int(buf[2])<<8 | int(buf[3])
		buf = buf[4:]
		if len(buf) < extLen {
			break
		}
		extData := buf[:extLen]
		buf = buf[extLen:]

		if extType == 0x0000 { // server_name extension
			if len(extData) < 2 {
				return ""
			}
			listLen := int(extData[0])<<8 | int(extData[1])
			extData = extData[2:]
			if len(extData) > listLen {
				extData = extData[:listLen]
			}
			for len(extData) >= 3 {
				nameType := extData[0]
				nameLen := int(extData[1])<<8 | int(extData[2])
				extData = extData[3:]
				if len(extData) < nameLen {
					break
				}
				if nameType == 0x00 { // host_name
					return strings.ToLower(strings.TrimSpace(string(extData[:nameLen])))
				}
				extData = extData[nameLen:]
			}
		}
	}
	return ""
}

// peekedConn wraps a net.Conn and replays bytes that were peeked during SNI inspection.
type peekedConn struct {
	net.Conn
	peeked *bytes.Reader
}

func (c *peekedConn) Read(b []byte) (int, error) {
	if c.peeked != nil && c.peeked.Len() > 0 {
		return c.peeked.Read(b)
	}
	return c.Conn.Read(b)
}

// sniMuxListener intercepts TLS connections matching geo-routed domains and forwards all other connections to the underlying HTTPS server.
type sniMuxListener struct {
	net.Listener
	acceptCh chan net.Conn
	closeCh  chan struct{}
	once     sync.Once
}

func NewSNIMuxListener(inner net.Listener) net.Listener {
	l := &sniMuxListener{
		Listener: inner,
		acceptCh: make(chan net.Conn, 256),
		closeCh:  make(chan struct{}),
	}
	go l.loop()
	return l
}

func (l *sniMuxListener) loop() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			select {
			case <-l.closeCh:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			close(l.acceptCh)
			return
		}
		go l.inspectAndRoute(conn)
	}
}

func (l *sniMuxListener) inspectAndRoute(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || n == 0 {
		conn.Close()
		return
	}
	peekedData := buf[:n]
	sni := ExtractTLSSNI(peekedData)

	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	if sni != "" {
		if proxyURL, matched := MatchSNIGeoRoute(cfg, sni); matched {
			handleGeoProxyStream(&peekedConn{Conn: conn, peeked: bytes.NewReader(peekedData)}, sni, proxyURL, cfg)
			return
		}
	}

	wrapped := &peekedConn{Conn: conn, peeked: bytes.NewReader(peekedData)}
	select {
	case l.acceptCh <- wrapped:
	case <-l.closeCh:
		conn.Close()
	}
}

func (l *sniMuxListener) Accept() (net.Conn, error) {
	conn, ok := <-l.acceptCh
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *sniMuxListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)
	})
	return l.Listener.Close()
}

// startSNIProxyServer starts the standalone TLS SNI Geo-Proxy listener (default port 8444)
func startSNIProxyServer(ctx context.Context) {
	configLock.RLock()
	port := config.SNIProxyPort
	configLock.RUnlock()
	if port <= 0 {
		port = 8444
	}

	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Warn("SNI Geo-Proxy standalone listener could not bind", "addr", addr, "error", err)
		return
	}
	slog.Info("SNI Geo-Proxy listener started", "addr", addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}
		go func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 2048)
			n, err := c.Read(buf)
			_ = c.SetReadDeadline(time.Time{})
			if err != nil || n == 0 {
				c.Close()
				return
			}
			peeked := buf[:n]
			sni := ExtractTLSSNI(peeked)
			if sni == "" {
				c.Close()
				return
			}
			configLock.RLock()
			cfg := config.Clone()
			configLock.RUnlock()

			proxyURL, matched := MatchSNIGeoRoute(cfg, sni)
			if !matched {
				slog.Debug("SNI Geo-Proxy rejected unauthorized domain", "sni", sni, "remote", c.RemoteAddr().String())
				c.Close()
				return
			}
			handleGeoProxyStream(&peekedConn{Conn: c, peeked: bytes.NewReader(peeked)}, sni, proxyURL, cfg)
		}(conn)
	}
}

func handleGeoProxyStream(clientConn net.Conn, sni, proxyURL string, cfg *Config) {
	defer clientConn.Close()

	// Security check: ensure client IP is not in BlockedClients
	if host, _, err := net.SplitHostPort(clientConn.RemoteAddr().String()); err == nil && cfg != nil {
		for _, blocked := range cfg.BlockedClients {
			if blocked == host {
				return
			}
		}
	}

	targetAddr := net.JoinHostPort(sni, "443")
	upstreamConn, err := dialViaGeoProxy(targetAddr, proxyURL, 10*time.Second)
	if err != nil {
		slog.Warn("SNI Geo-Proxy upstream dial failed", "sni", sni, "proxy", proxyURL, "error", err)
		return
	}
	defer upstreamConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()
	<-done
}

// dialViaGeoProxy connects to targetAddr ("host:443") either via HTTP CONNECT proxy, SOCKS5 proxy, or direct TCP.
func dialViaGeoProxy(targetAddr, proxyURL string, timeout time.Duration) (net.Conn, error) {
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" || strings.HasPrefix(strings.ToLower(proxyURL), "interface://") {
		return dialViaInterfaceOrDirect(targetAddr, strings.TrimPrefix(proxyURL, "interface://"), timeout)
	}

	if !strings.Contains(proxyURL, "://") {
		proxyURL = "http://" + proxyURL
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	scheme := strings.ToLower(u.Scheme)
	proxyHost := u.Host
	if !strings.Contains(proxyHost, ":") {
		if scheme == "socks5" || scheme == "socks5h" {
			proxyHost = net.JoinHostPort(proxyHost, "1080")
		} else {
			proxyHost = net.JoinHostPort(proxyHost, "8888")
		}
	}

	if scheme == "socks5" || scheme == "socks5h" {
		return dialSOCKS5(proxyHost, targetAddr, u.User, timeout)
	}

	// Default: HTTP CONNECT proxy (used by Gluetun HTTPPROXY=on on :8888, Privado, Mullvad, etc.)
	conn, err := net.DialTimeout("tcp", proxyHost, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	reqStr := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if u.User != nil {
		pw, _ := u.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
		reqStr += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	reqStr += "\r\n"

	if _, err := conn.Write([]byte(reqStr)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned status %d (%s)", resp.StatusCode, resp.Status)
	}

	_ = conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		peeked, _ := io.ReadAll(io.LimitReader(br, int64(br.Buffered())))
		return &peekedConn{Conn: conn, peeked: bytes.NewReader(peeked)}, nil
	}
	return conn, nil
}

func dialSOCKS5(proxyHost, targetAddr string, authUser *url.Userinfo, timeout time.Duration) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	conn, err := net.DialTimeout("tcp", proxyHost, timeout)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Greeting
	if authUser != nil {
		_, err = conn.Write([]byte{0x05, 0x02, 0x00, 0x02})
	} else {
		_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed")
	}
	if resp[1] == 0x02 && authUser != nil {
		user, pw := authUser.Username(), ""
		if p, ok := authUser.Password(); ok {
			pw = p
		}
		authReq := append(append([]byte{0x01, byte(len(user))}, []byte(user)...), byte(len(pw)))
		authReq = append(authReq, []byte(pw)...)
		if _, err := conn.Write(authReq); err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := io.ReadFull(conn, resp); err != nil || resp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 authentication failed")
		}
	} else if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 unsupported auth method %d", resp[1])
	}

	req := append(append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...), byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed")
	}
	var skip int
	switch hdr[3] {
	case 0x01:
		skip = 6
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(lb[0]) + 2
	case 0x04:
		skip = 18
	}
	if skip > 0 {
		if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
			conn.Close()
			return nil, err
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
