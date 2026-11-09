package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	nativeVPNMu        sync.Mutex
	nativeVPNCmd       *exec.Cmd
	nativeVPNCancel    context.CancelFunc
	nativeVPNActiveIf  string
	nativeVPNLastError string
	nativeVPNStartedAt time.Time
)

var privadoCountryEndpoints = map[string]string{
	"AL": "tia-001.vpn.privado.io",
	"CH": "zrh-001.vpn.privado.io",
	"NL": "ams-001.vpn.privado.io",
	"DE": "fra-001.vpn.privado.io",
	"US": "nyc-001.vpn.privado.io",
	"GB": "lon-001.vpn.privado.io",
}

// GetVPNInterfaceIP returns the first IPv4 address assigned to the specified network interface.
func GetVPNInterfaceIP(ifaceName string) string {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		return ""
	}
	ief, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return ""
	}
	addrs, err := ief.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.To4().String()
		}
	}
	return ""
}

// GetEffectiveGeoBindIP resolves the local source IPv4 address to bind to when native VPN or interface/Tailscale mode is configured.
func GetEffectiveGeoBindIP(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.VPNMode))
	iface := strings.TrimSpace(cfg.VPNInterface)
	switch mode {
	case "native_openvpn":
		if iface == "" {
			iface = "tun_shield"
		}
	case "native_wireguard":
		if iface == "" {
			iface = "wg_shield"
		}
	case "tailscale":
		if iface == "" {
			iface = "tailscale0"
		}
	case "interface":
		if iface == "" {
			iface = "tun0"
		}
	default:
		return ""
	}
	return GetVPNInterfaceIP(iface)
}

func dialViaInterfaceOrDirect(targetAddr, overrideIface string, timeout time.Duration) (net.Conn, error) {
	if overrideIface != "" {
		if ip := GetVPNInterfaceIP(overrideIface); ip != "" {
			if parsed := net.ParseIP(ip); parsed != nil {
				d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: parsed}}
				return d.Dial("tcp", targetAddr)
			}
		}
	}
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	if bindIP := GetEffectiveGeoBindIP(cfg); bindIP != "" {
		if parsed := net.ParseIP(bindIP); parsed != nil {
			dialer := &net.Dialer{
				Timeout:   timeout,
				LocalAddr: &net.TCPAddr{IP: parsed},
			}
			return dialer.Dial("tcp", targetAddr)
		}
	}
	return net.DialTimeout("tcp", targetAddr, timeout)
}

// syncNativeVPN starts, stops, or restarts the embedded OpenVPN / WireGuard tunnel inside ShieldDNS.
// It uses --route-nopull / Table=off so the host's default routing table is never hijacked.
func syncNativeVPN(cfg *Config) {
	if testMode || cfg == nil {
		return
	}
	nativeVPNMu.Lock()
	defer nativeVPNMu.Unlock()

	stopLocked := func() {
		if nativeVPNCancel != nil {
			nativeVPNCancel()
			nativeVPNCancel = nil
		}
		if nativeVPNCmd != nil && nativeVPNCmd.Process != nil {
			_ = nativeVPNCmd.Process.Kill()
			nativeVPNCmd = nil
		}
		if nativeVPNActiveIf == "wg_shield" {
			_ = exec.Command("wg-quick", "down", filepath.Join(DataDir, "wg_shield.conf")).Run()
		}
		nativeVPNActiveIf = ""
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.VPNMode))
	if mode != "native_openvpn" && mode != "native_wireguard" {
		stopLocked()
		return
	}

	stopLocked()

	if mode == "native_openvpn" {
		iface := strings.TrimSpace(cfg.VPNInterface)
		if iface == "" {
			iface = "tun_shield"
		}
		ovpnContent := strings.TrimSpace(cfg.VPNConfigContent)
		if ovpnContent == "" && strings.EqualFold(cfg.VPNProvider, "privado") {
			country := strings.ToUpper(strings.TrimSpace(cfg.VPNDefaultCountry))
			host, ok := privadoCountryEndpoints[country]
			if !ok {
				host = privadoCountryEndpoints["AL"]
			}
			ovpnContent = fmt.Sprintf("client\ndev %s\nproto udp\nremote %s 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nverb 3\n", iface, host)
		}
		if ovpnContent == "" {
			nativeVPNLastError = "missing OpenVPN configuration (.ovpn)"
			return
		}

		// Ensure route-nopull and custom tun interface so host routing is untouched
		if !strings.Contains(ovpnContent, "route-nopull") {
			ovpnContent += "\nroute-nopull\n"
		}
		ovpnPath := filepath.Join(DataDir, "native_vpn.ovpn")
		args := []string{"--config", ovpnPath, "--dev", iface, "--dev-type", "tun", "--route-nopull"}

		if strings.TrimSpace(cfg.VPNUsername) != "" {
			authPath := filepath.Join(DataDir, "native_vpn.auth")
			authData := fmt.Sprintf("%s\n%s\n", strings.TrimSpace(cfg.VPNUsername), cfg.VPNPassword)
			_ = os.WriteFile(authPath, []byte(authData), 0600)
			args = append(args, "--auth-user-pass", authPath)
		}
		if err := os.WriteFile(ovpnPath, []byte(ovpnContent), 0600); err != nil {
			nativeVPNLastError = err.Error()
			return
		}

		ctx, cancel := context.WithCancel(appCtx)
		cmd := exec.CommandContext(ctx, "openvpn", args...)
		if err := cmd.Start(); err != nil {
			cancel()
			nativeVPNLastError = fmt.Sprintf("openvpn start failed: %v", err)
			slog.Warn("Native OpenVPN failed to start", "error", err)
			return
		}
		nativeVPNCmd = cmd
		nativeVPNCancel = cancel
		nativeVPNActiveIf = iface
		nativeVPNLastError = ""
		nativeVPNStartedAt = time.Now()
		slog.Info("Native OpenVPN started in non-intrusive split-tunnel mode", "interface", iface)
		return
	}

	if mode == "native_wireguard" {
		iface := strings.TrimSpace(cfg.VPNInterface)
		if iface == "" {
			iface = "wg_shield"
		}
		wgContent := strings.TrimSpace(cfg.VPNConfigContent)
		if wgContent == "" {
			nativeVPNLastError = "missing WireGuard configuration (.conf)"
			return
		}
		if !strings.Contains(wgContent, "Table") {
			wgContent = strings.Replace(wgContent, "[Interface]", "[Interface]\nTable = off", 1)
		}
		wgPath := filepath.Join(DataDir, iface+".conf")
		if err := os.WriteFile(wgPath, []byte(wgContent), 0600); err != nil {
			nativeVPNLastError = err.Error()
			return
		}
		if out, err := exec.Command("wg-quick", "up", wgPath).CombinedOutput(); err != nil {
			nativeVPNLastError = fmt.Sprintf("wg-quick failed: %v (%s)", err, strings.TrimSpace(string(out)))
			slog.Warn("Native WireGuard failed to start", "error", nativeVPNLastError)
			return
		}
		nativeVPNActiveIf = iface
		nativeVPNLastError = ""
		nativeVPNStartedAt = time.Now()
		slog.Info("Native WireGuard started in split-tunnel mode (Table = off)", "interface", iface)
	}
}

func handleVPNStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	nativeVPNMu.Lock()
	activeIf := nativeVPNActiveIf
	lastErr := nativeVPNLastError
	startedAt := nativeVPNStartedAt
	nativeVPNMu.Unlock()

	mode := cfg.VPNMode
	if mode == "" {
		mode = "proxy"
	}
	bindIP := GetEffectiveGeoBindIP(cfg)
	if activeIf == "" && cfg.VPNInterface != "" {
		activeIf = cfg.VPNInterface
	}
	tailscaleIP := GetVPNInterfaceIP("tailscale0")

	resp := map[string]interface{}{
		"vpn_mode":         mode,
		"vpn_provider":     cfg.VPNProvider,
		"vpn_country":      cfg.VPNDefaultCountry,
		"vpn_proxy_url":    cfg.VPNProxyURL,
		"vpn_interface":    activeIf,
		"interface_ip":     bindIP,
		"tailscale_ip":     tailscaleIP,
		"geo_proxy_ip":     GetEffectiveGeoProxyIP(cfg),
		"sni_proxy_port":   cfg.SNIProxyPort,
		"last_error":       lastErr,
		"started_at":       startedAt,
		"geo_routed_zones": len(GetGeoRoutedZones(cfg)),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
