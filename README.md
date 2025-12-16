<img src="logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a lightweight, efficient, and privacy-focused DNS-over-TLS (DoT) proxy.

It enables you to securely accept DNS queries (e.g., Android Private DNS) and forward them to your local DNS server (AdGuard Home, Pi-hole) or public resolvers.

## Features
- 🔒 **DNS-over-TLS (DoT)**
- 🌍 **DNS-over-HTTPS (DoH)**: Supported on ports 443, 784, 2443.
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
      - "784:784"   # DoH (Alternative)
      - "2443:2443" # DoH (Alternative)
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

## Setup Guide

### 1. Requirements for Public Access (DoH/DoT)
To use DoH/DoT over the internet, you need:
1.  A **Public Domain** (e.g., `dns.example.com`).
2.  A **Valid SSL Certificate** for that domain.
    *   **Android Private DNS** checks for a valid chain (Let's Encrypt or similar).
    *   **Cloudflare Tunnel**: You can usage a Cloudflare Origin Certificate (lasts 15 years) on your server, and let Cloudflare Edge handle the valid public cert.

### 2. Cloudflare Tunnel Integration
You can use the built-in tunnel support or an external tunnel.

#### Using Built-in Tunnel & Certificates
1.  Generate a **Cloudflare Origin Certificate** in the Cloudflare Dashboard (SSL/TLS > Origin Server).
2.  Save the items as `fullchain.pem` (Certificate) and `privkey.pem` (Private Key) in your `./certs` folder.
3.  Set the environment variable `CLOUDFLARE_TUNNEL_TOKEN`.
4.  ShieldDNS will use these certs to run DoT/DoH, and the Tunnel will route traffic to it.
5.  *Tip*: In your Tunnel Public Hostname configuration, point traffic to `HTTPS://localhost:443` and enable "No TLS Verify" if using self-signed, or rely on the Origin Cert.

### 3. Client Configuration

#### 📱 Android (Private DNS)
Android natively supports **DNS-over-TLS (DoT)**.
1.  Go to **Settings > Network & Internet > Private DNS**.
2.  Select **Private DNS provider hostname**.
3.  Enter your domain: `dns.example.com`.
4.  *Note:* Only works if port `853` is reachable or tunneled, and the certificate is valid and trusted by Android.

#### 🍎 iOS (iPhone/iPad)
iOS does not natively support custom DoT/DoH in settings without a **Configuration Profile**.
1.  Create a `.mobileconfig` file (using tools like [DNS Profile Creator](https://github.com/paulmillr/encrypted-dns)).
2.  Email or AirDrop it to your device.
3.  Install via **Settings > Profile Downloaded**.
4.  *Alternative:* Use apps like **DNSCloak** or **AdGuard** and configure your server details manually (`https://dns.example.com/dns-query` for DoH).

#### 💻 Windows 11
Windows 11 supports DoH natively.
1.  Set your DNS Server IP to be the IP where ShieldDNS is running (or 127.0.0.1 if using DoH client proxy).
2.  Run: `netsh dns add global doh https://dns.example.com/dns-query` (Command Line)
3.  Or go to **Settings > Network > Ethernet/Wi-Fi > DNS settings > Edit**.
    - Set IPv4 DNS to your server IP.
    - Set **DNS over HTTPS** to **On (Manual)** and enter the URI template: `https://dns.example.com/dns-query`.

## Home Assistant Addon
This project is also available as a Home Assistant Addon.
[View on GitHub](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)
