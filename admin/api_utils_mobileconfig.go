package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"
)

func handleQR(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "data parameter required", http.StatusBadRequest)
		return
	}
	if len(data) > 500 {
		http.Error(w, "data too long", http.StatusBadRequest)
		return
	}

	png, err := qrcode.Encode(data, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(png)
}

func handleMobileConfig(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	adminDomain := config.AdminDomain
	blockPageIP := config.BlockPageIP
	signEnabled := config.SignMobileConfig
	workerDomain := config.ClusterWorkerDomain
	replicas := append([]ClusterReplica{}, config.ClusterReplicas...)
	primaryURL := config.ClusterPrimaryURL
	configLock.RUnlock()

	host := adminDomain
	if host == "" {
		host = r.Host
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
	}

	// Cluster worker support: If a Cloudflare Worker dispatcher is configured,
	// clients can route DoH through the worker. However, Apple mobileconfig signing
	// requires that the signing certificate matches the profile or isn't invalid.
	// Allow explicit ?host= override or fallback gracefully.
	if reqHost := r.URL.Query().Get("host"); reqHost != "" {
		host = reqHost
	} else if workerDomain != "" && r.URL.Query().Get("prefer_worker") == "1" {
		host = workerDomain
	}

	// Build ServerAddresses XML block (Bootstrap IPs)
	// Supports multi-node failover bootstrap: iOS tests and resolves against these IPs
	var bootstrapIPs []string
	if blockPageIP != "" && blockPageIP != "127.0.0.1" && blockPageIP != "0.0.0.0" {
		bootstrapIPs = append(bootstrapIPs, blockPageIP)
	}

	// Also extract IPs from replica or primary hostnames if directly resolvable or IP-based
	for _, rep := range replicas {
		if rep.URL != "" {
			if u, err := url.Parse(rep.URL); err == nil {
				h := u.Hostname()
				if net.ParseIP(h) != nil && h != "127.0.0.1" {
					bootstrapIPs = append(bootstrapIPs, h)
				}
			}
		}
	}
	if primaryURL != "" {
		if u, err := url.Parse(primaryURL); err == nil {
			h := u.Hostname()
			if net.ParseIP(h) != nil && h != "127.0.0.1" {
				bootstrapIPs = append(bootstrapIPs, h)
			}
		}
	}

	if len(bootstrapIPs) == 0 {
		h := r.Host
		if strings.Contains(h, ":") {
			h, _, _ = net.SplitHostPort(h)
		}
		if net.ParseIP(h) != nil && h != "127.0.0.1" && h != "0.0.0.0" {
			bootstrapIPs = append(bootstrapIPs, h)
		}
	}

	serverAddrsXML := ""
	if len(bootstrapIPs) > 0 {
		var addrStrings []string
		seen := make(map[string]bool)
		for _, ip := range bootstrapIPs {
			if !seen[ip] {
				seen[ip] = true
				addrStrings = append(addrStrings, fmt.Sprintf("\t\t\t\t<string>%s</string>", ip))
			}
		}
		if len(addrStrings) > 0 {
			serverAddrsXML = fmt.Sprintf("\n\t\t\t<key>ServerAddresses</key>\n\t\t\t<array>\n%s\n\t\t\t</array>", strings.Join(addrStrings, "\n"))
		}
	}

	// Certificate handling - check if self-signed
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}

	isSelfSigned := false
	var certBase64 string
	certData, err := os.ReadFile(certFile)
	if err != nil {
		certData, _ = os.ReadFile("/etc/shielddns/ssl/selfsigned.crt")
	}

	if certData != nil {
		block, _ := pem.Decode(certData)
		if block != nil {
			cert, pErr := x509.ParseCertificate(block.Bytes)
			if pErr == nil {
				if cert.Issuer.String() == cert.Subject.String() {
					isSelfSigned = true
					certBase64 = base64.StdEncoding.EncodeToString(block.Bytes)
				}
			}
		}
	} else {
		// Try fallback from DataDir
		fallbackPath := filepath.Join(DataDir, "ssl", "selfsigned.crt")
		if certData, err = os.ReadFile(fallbackPath); err == nil {
			block, _ := pem.Decode(certData)
			if block != nil {
				if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
					if cert.Issuer.String() == cert.Subject.String() {
						isSelfSigned = true
						certBase64 = base64.StdEncoding.EncodeToString(block.Bytes)
					}
				}
			}
		}
	}

	// Generate unique UUIDs
	genUUID := func(offset int64) string {
		now := time.Now().UnixNano() + offset
		return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
			now&0xFFFFFFFF, now>>32&0xFFFF,
			0x4000|(now>>48&0x0FFF), 0x8000|(now>>60&0x3FFF),
			now&0xFFFFFFFFFFFF)
	}

	dohUUID := genUUID(0)
	profileUUID := genUUID(1)
	certPayloadUUID := genUUID(2)

	certPayloadXML := ""
	certReferenceXML := ""
	if isSelfSigned && certBase64 != "" {
		certPayloadXML = fmt.Sprintf(`
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ShieldDNS.crt</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>Trusts the ShieldDNS self-signed root certificate.</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS Root Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.rootcert</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>`, certBase64, certPayloadUUID)

		certReferenceXML = fmt.Sprintf("\n\t\t\t<key>PayloadCertificateUUID</key>\n\t\t\t<string>%s</string>", certPayloadUUID)
	}

	// NOTE: iOS Configuration Profiles only support DNSProtocol values "TLS" and "HTTPS".
	// QUIC is NOT part of Apple's MDM specification and causes "internal error" on install.
	// DoQ is supported natively via third-party apps (DNSecure, AdGuard) but not via profiles.

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=shielddns_%s.mobileconfig", escapeXML(host)))

	mobileConfig := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://%[1]s/dns-query</string>%[2]s
			</dict>
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
				</dict>
			</array>
			<key>PayloadDescription</key>
			<string>Encrypted DNS-over-HTTPS (DoH) for ShieldDNS (%[1]s).</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS DoH (%[1]s)</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.doh.%[1]s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%[3]s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>%[5]s
		</dict>%[4]s
	</array>
	<key>PayloadDescription</key>
	<string>ShieldDNS Encryption Profile (%[1]s). Enables system-wide DNS encryption for improved privacy.</string>
	<key>PayloadDisplayName</key>
	<string>ShieldDNS Protection (%[1]s)</string>
	<key>PayloadIdentifier</key>
	<string>com.shielddns.profile.%[1]s</string>
	<key>PayloadOrganization</key>
	<string>ShieldDNS Project</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%[6]s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>SECURITY &amp; PRIVACY NOTICE:
This profile configures your device to use ShieldDNS (%[1]s) as its encrypted DNS provider.

WHAT THIS MEANS:
ShieldDNS will encrypt all DNS queries from this device, preventing ISPs and third parties from monitoring your web activity. It also leverages advanced blocklists to protect you from advertisements, trackers, and malicious content in real-time.

TECHNICAL DETAILS:
- Target Server: %[1]s
- Supported Protocol: DNS-over-HTTPS (DoH)
- Documentation: https://github.com/FaserF/ShieldDNS

By proceeding, you consent to all DNS traffic being routed through this server. No personal web traffic (HTTP/HTTPS content) is decrypted; only the destination addresses are processed for filtering. You can remove this profile at any time in Settings &gt; General &gt; VPN &amp; Device Management.</string>
	</dict>
</dict>
</plist>`, escapeXML(host), serverAddrsXML, dohUUID, certPayloadXML, certReferenceXML, profileUUID)

	finalContent := []byte(mobileConfig)
	if signEnabled {
		// Get cert and key files
		certFile := os.Getenv("CERT_FILE")
		if certFile == "" {
			certFile = "/ssl/fullchain.pem"
		}
		keyFile := os.Getenv("KEY_FILE")
		if keyFile == "" {
			keyFile = "/ssl/privkey.pem"
		}

		if _, err := os.Stat(certFile); err == nil {
			// If host differs from local certificate domain (e.g. using Cloudflare Worker domain),
			// verify if cert matches. If local cert doesn't cover worker domain, serve unsigned
			// rather than broken/mismatched signature.
			canSign := true
			if certData != nil {
				block, _ := pem.Decode(certData)
				if block != nil {
					if c, err := x509.ParseCertificate(block.Bytes); err == nil {
						if err := c.VerifyHostname(host); err != nil {
							// Local cert doesn't cover this host (e.g. worker domain vs node cert)
							canSign = false
							slog.Info("Serving unsigned mobileconfig because local SSL certificate does not cover profile hostname", "profile_host", host, "cert_subject", c.Subject.CommonName)
						}
					}
				}
			}

			if canSign {
				signed, signErr := signProfile(finalContent, certFile, keyFile)
				if signErr == nil {
					finalContent = signed
				} else {
					slog.Error("Failed to sign mobileconfig profile", "error", signErr)
					// Fallback to unsigned content (which we already have in finalContent)
				}
			}
		}
	}

	w.Write(finalContent)
}

func signProfile(content []byte, certFile, keyFile string) ([]byte, error) {
	// openssl smime -sign -signer cert.pem -inkey key.pem -certfile chain.pem -nodetach -outform der
	// Note: certFile (fullchain.pem) usually contains both the entity cert and the chain.
	cmd := exec.Command("openssl", "smime", "-sign",
		"-signer", certFile,
		"-inkey", keyFile,
		"-certfile", certFile,
		"-nodetach",
		"-outform", "der")

	cmd.Stdin = bytes.NewReader(content)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl error: %v, stderr: %s", err, stderr.String())
	}

	return out.Bytes(), nil
}
