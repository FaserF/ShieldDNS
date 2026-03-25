<img src="logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a lightweight, efficient, and privacy-focused DNS-over-TLS (DoT) proxy.

It enables you to securely accept DNS queries (e.g., Android Private DNS) and forward them to your local DNS server (AdGuard Home, Pi-hole) or public resolvers.

## Features
- 🔒 **DNS-over-TLS (DoT)**
- 🌍 **DNS-over-HTTPS (DoH)**: Supported on port 443 (or custom).
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

Since you are exposing a DNS server to the public, you should secure it to prevent abuse (DNS Amplification, Scanning, DDoS).

### 1. External Proxy / WAF (Recommended)
You can use external solutions like **Cloudflare Tunnel** or a **Reverse Proxy** to add a layer of security. If using Cloudflare:
- **WAF / Custom Rules**:
    - **Block Countries**: Block all countries except your own.
    - **Block Bots**: Enable "Bot Fight Mode" or block known bot User-Agents.
- **Rate Limiting**: Set a Rate Limiting rule for your hostname (e.g. max 50 requests / 10 seconds per IP) to prevent flooding.

### 2. General Firewalls
If running with Direct Exposure:
- **Whitelist IPs**: Only allow your own mobile IP ranges or specific networks if possible.
- **Fail2Ban**: Monitor logs and ban abusive IPs (requires mounting logs to host).
- **Limit Rates**: Use `iptables` or UFW to limit connection rates on port 853/443.

### 3. Client Configuration
- **Android**: Use strict Private DNS hostname. Android verifies the certificate chain.
- **iOS**: Use a `.mobileconfig` that enforces HTTPS and specific SNI.

## 💡 Concepts & Protocols

To use ShieldDNS effectively, it helps to understand the protocols:

| Protocol | Port | Description | Android Support |
| :--- | :--- | :--- | :--- |
| **DoT (DNS-over-TLS)** | `853` (TCP) | Uses a dedicated secure port. | **Native Support**. Used by "Private DNS" setting. |
| **DoH (DNS-over-HTTPS)** | `443` (TCP) | Uses standard HTTPS web port. | **Native Support** (newer) or via App/Profile. |

## Setup Guide

### 1. Requirements
1.  A **Public Domain** (e.g., `dns.example.com`).
2.  A **Valid SSL Certificate** for that domain.
    *   **Android Private DNS** checks for a valid chain (Let's Encrypt or similar).

### 2. Client Configuration

#### 📱 Android (Samsung / Pixel / etc.)
1.  Go to **Settings > Network > Private DNS**.
2.  Enter: `dns.example.com`.

#### 🍎 iOS (iPhone / iPad)
iOS supports native encrypted DNS via **Configuration Profiles**.
1.  **Download Template**: Get the [mobileconfig-template.mobileconfig](./mobileconfig-template.mobileconfig) file from this repository.
2.  **Edit**: Open it with a text editor and replace `REPLACE_ME_DOMAIN` with your domain (e.g. `dns.example.com`).
3.  **Install**: Email/AirDrop file to device -> **Settings > Profile Downloaded** -> Install.

#### 💻 Windows 11
1.  **Settings > Network > Ethernet/Wi-Fi > DNS settings > Edit**.
2.  Set IPv4 DNS to `127.0.0.1` (dummy) or actual server IP.
3.  Set **DNS over HTTPS** to **On (Manual)**.
4.  Template: `https://dns.example.com/dns-query`.

## Home Assistant Addon
This project is also available as a Home Assistant Addon.
[View on GitHub](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)
