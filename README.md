<img src="logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a lightweight, efficient, and privacy-focused DNS-over-TLS (DoT) proxy.

It enables you to securely accept DNS queries (e.g., Android Private DNS) and forward them to your local DNS server (AdGuard Home, Pi-hole) or public resolvers.

## Features
- 🔒 **DNS-over-TLS (DoT)**
- 🌍 **DNS-over-HTTPS (DoH)**: Supported on port 443 (or custom).
- 🚇 **Cloudflare Tunnel Support**: Expose your DoT/DoH server safely.
- 🚀 **High Performance**: Alpine + CoreDNS.
- 🪵 **Flexible Logging**: Configurable log levels.

## Usage

### Docker Compose

```yaml
services:
  shielddns:
    image: ghcr.io/faserf/shielddns:latest
    ports:
      - "853:853"   # DoT
      - "443:443"   # DoH
    environment:
      - UPSTREAM_DNS=1.1.1.1
      - CLOUDFLARE_TUNNEL_TOKEN=eyJh... # Optional
      - ENABLE_INFO_PAGE=true # Optional: Enable Info Page on DoH Port
      - LOG_LEVEL=info # debug, info, error
      - CERT_FILE=/certs/fullchain.pem
      - KEY_FILE=/certs/privkey.pem
    volumes:
      - ./certs:/certs
```

## Optional: Info Page
You can enable a lightweight "Fancy" Info Page to display a professional landing page for your DNS endpoint.
- **Why?** To inform visitors (or yourself) that this is a private DNS endpoint and not a public website.
- **Enable**: Set `ENABLE_INFO_PAGE=true`.
- **Port**: Default is `8080` (mapped in Docker).

## 🛡️ Security Best Practices

Since you are exposing a DNS server to the public (via Tunnel or Port Forwarding), you should secure it to prevent abuse (DNS Amplification, Scanning, DDoS).

### 1. Cloudflare Tunnel (Highly Recommended)
Using Cloudflare Tunnel hides your Origin IP and allows you to use **Cloudflare Zero Trust** features.
- **WAF / Custom Rules**:
    - **Block Countries**: Block all countries except your own.
    - **Block Bots**: Enable "Bot Fight Mode" or block known bot User-Agents.
- **Rate Limiting**: Set a Rate Limiting rule for your hostname (e.g. max 50 requests / 10 seconds per IP) to prevent flooding.
- **Zero Trust Authentication**: If feasible, put the DNS endpoint behind Cloudflare Access (Note: This breaks standard DoH clients unless they support authentication headers. For a pure public endpoint, rely on WAF).

### 2. General Firewalls
If running without Cloudflare (Direct Exposure):
- **Whitelist IPs**: Only allow your own mobile IP ranges or specific networks if possible.
- **Fail2Ban**: Monitor logs and ban abusive IPs (requires mounting logs to host).
- **Limit Rates**: Use `iptables` or UFW to limit connection rates on port 853/443.

### 3. Client Configuration
- **Android**: Use strict Private DNS hostname. Android verifies the certificate chain.
- **iOS**: Use a `.mobileconfig` that enforces HTTPS and specific SNI.

## 💡 Concepts & Protocols

To use ShieldDNS effectively, it helps to understand the two main protocols:

| Protocol | Port | Description | Android Support |
| :--- | :--- | :--- | :--- |
| **DoT (DNS-over-TLS)** | `853` (TCP) | Uses a dedicated secure port. | **Native Support**. Used by "Private DNS" setting. |
| **DoH (DNS-over-HTTPS)** | `443` (TCP) | Uses standard HTTPS web port. | **Requires App** (Intra/Nebulo) or Browser Config. |
| **UDP/53** | `53` (UDP) | Standard unencrypted DNS. | Legacy. Not supported by ShieldDNS (by design). |

### ⚠️ Important for Cloudflare Tunnel Users
**Cloudflare Tunnel** (without Enterprise/Spectrum) only proxies HTTP/HTTPS traffic (DoH). It **does not** proxy raw TCP (DoT/853).
- **If you use Cloudflare Tunnel**: You **MUST** use DoH (via an App on Android). "Private DNS" setting will **FAIL** because it tries to use DoT/853.
- **If you use Port Forwarding**: You can use both DoT (Private DNS) and DoH.

## Setup Guide

### 1. Requirements
1.  A **Public Domain** (e.g., `dns.example.com`).
2.  A **Valid SSL Certificate** for that domain.
    *   **Android Private DNS** checks for a valid chain (Let's Encrypt or similar).
    *   **Cloudflare Tunnel**: You can usage a Cloudflare Origin Certificate (lasts 15 years) on your server, and let Cloudflare Edge handle the valid public cert.

### 2. Best Practice: The "Hybrid" Architecture
If you want **"Native" Android support** AND **Cloudflare Tunnel**, you need two DNS records.

#### Record A: `doh.example.com` (For iOS, Browsers, Apps)
*   **Type**: CNAME (Proxied via Cloudflare Tunnel).
*   **Target**: Your Tunnel ID.
*   **Tunnel Config**: Service `HTTPS://192.168.1.x:3443` (No TLS Verify).
*   **iOS Profile**: Use `https://doh.example.com/dns-query`.

#### Record B: `dot.example.com` (For Android Native)
*   **Type**: A/CNAME (DNS Only / Grey Cloud).
*   **Target**: Your Home IP (DDNS).
*   **Router**: Port Forwarding **WAN:853** -> **LAN:8853** (HA IP).
*   **Android Setting**: Enter `dot.example.com`.
*   **⚠️ Restriction**: You explicitly stated "No Port Forwarding". If you do not open Port 853, **Method 1 (Native Private DNS) is IMPOSSIBLE**. You *must* use Method 2 (App).

This gives you the best of both worlds: Tunnel security where possible, and raw TCP access where required.

### 3. Client Configuration

#### 📱 Android (Samsung / Pixel / etc.)

**Method 1: Native "Private DNS" (Cannot work with Tunnel-Only)**
*Requires Port Forwarding (WAN 853). If you refuse to open ports, SKIP THIS.*
1.  Ensure you have Port Forwarding (853->8853) and a Grey Cloud DNS record.
2.  Go to **Settings > Network > Private DNS**.
3.  Enter: `dot.example.com`.

**Method 2: App (Works with Tunnel-Only)**
*This is your ONLY option if you refuse to open ports.*
1.  Install **Intra**.
2.  URL: `https://doh.example.com/dns-query`.

#### 🍎 iOS (iPhone / iPad)

iOS supports native encrypted DNS via **Configuration Profiles**.
1.  **Download Template**: Get the [mobileconfig-template.mobileconfig](./mobileconfig-template.mobileconfig) file from this repository.
2.  **Edit**: Open it with a text editor and replace `REPLACE_ME_DOMAIN` with your domain (e.g. `doh.example.com`).
3.  **Install**: Email/AirDrop file to device -> **Settings > Profile Downloaded** -> Install.
4.  **Result**: System-wide ad-blocking on 4G/5G/Wifi.

#### 💻 Windows 11
1.  **Settings > Network > Ethernet/Wi-Fi > DNS settings > Edit**.
2.  Set IPv4 DNS to `127.0.0.1` (dummy) or actual server IP.
3.  Set **DNS over HTTPS** to **On (Manual)**.
4.  Template: `https://dns.example.com/dns-query`.

## Home Assistant Addon
This project is also available as a Home Assistant Addon.
[View on GitHub](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)
