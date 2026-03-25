<img src="logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a high-performance, privacy-focused DNS solution supporting both **DNS-over-TLS (DoT)** and **DNS-over-HTTPS (DoH)**. 

It features a premium **Admin Dashboard** for real-time monitoring and a powerful **Filtering Engine** compatible with AdGuard, Pi-hole, and uBlock origin lists.

## 🚀 Key Features

- 🔒 **Unified Secure Access**: Support for **DNS-over-TLS (DoT)** (port 853) and **DNS-over-HTTPS (DoH)** (port 443).
- 📊 **Unified Dashboard**: Access the **Admin Dashboard** and **DoH** on the same standard HTTPS port (443).
- 🛡️ **DNS Filtering**: Integrated engine for blocklists with automatic updates and deduplication.
- ⚡ **High Performance**: Built on CoreDNS and Go for maximum efficiency.
- 🔐 **Secure Access**: Mandatory password protection (bcrypt) for the Admin UI.
- 📱 **Multi-Platform**: Perfect for Android Private DNS, iOS Profiles, and Windows 11.

## 🛠️ Usage

### Docker Compose

```yaml
services:
  shielddns:
    image: ghcr.io/faserf/shielddns:latest
    ports:
      - "853:853/tcp"    # DoT
      - "443:443/tcp"    # DoH & Admin Dashboard
    environment:
      - UPSTREAM_DNS=1.1.1.1, 8.8.8.8
      - LOG_LEVEL=info # debug, info, error
      - CERT_FILE=/certs/fullchain.pem
      - KEY_FILE=/certs/privkey.pem
    volumes:
      - ./certs:/certs
      - ./data:/etc/shielddns # Persistent config and stats
```

## 🖥️ Admin Dashboard

Access the dashboard at `https://YOUR_SERVER_IP/`.

### 🛡️ Setup Wizard
On your first visit, a multi-step setup wizard will guide you through:
1.  **Security**: Setting a strong 12-character administrative password (hashed with bcrypt).
2.  **Upstream DNS**: Selecting your preferred upstream providers (e.g., Cloudflare, Google, Quad9).
3.  **Protection**: Choosing from a curated catalog of industry-standard blocklists.

### 📊 Real-Time Analytics
- **Live Query Log**: Monitor every DNS request in real-time. See which domains are being allowed or blocked instantly.
- **Traffic Trends**: A dynamic 24-hour chart visualizes your network's activity, showing query spikes and blocking efficiency.
- **Search Tool**: Use the built-in search to deep-dive into your active blocklists and verify if specific domains are filtered.

### 🛡️ Filtering Management
ShieldDNS merges all enabled lists into a high-performance filtering database.
- **Preset Catalog**: Easily enable popular lists like OISD, Hagezi (Multi/Pro), and Steven Black.
- **Custom Lists**: Add any GitHub or raw URL list to your filtering engine.
- **Status Hub**: The "Am I Protected?" indicator provides immediate feedback on your filtering status.

## 📱 Client Configuration

### DoT (DNS-over-TLS) - Port 853
- **Android**: Go to **Settings > Network > Private DNS** and enter `dns.example.com`.
- **iOS/macOS**: Use the provided `.mobileconfig` template.

### DoH (DNS-over-HTTPS) - Port 443
- **Windows 11**: **Settings > Network > DNS settings > Edit**. Set DNS over HTTPS to "On (Manual)" and enter `https://dns.example.com/dns-query`.
- **Browsers**: Enter `https://dns.example.com/dns-query` in your browser's "Secure DNS" settings.

## 🛡️ Security Best Practices

Since you are exposing a DNS server to the public, you should secure it:
1.  **Use a WAF**: Place a Reverse Proxy or Cloudflare Tunnel in front of your DoH endpoint.
2.  **Firewall**: Whitelist your mobile IP ranges for port 853 if possible.
3.  **Password**: Use a strong, unique password for the Admin UI (min 12 chars).

## 💡 Concepts & Protocols

| Protocol | Port | Port (TCP) | Description | Support |
| :--- | :--- | :--- | :--- | :--- |
| **DoT** | `853` | Dedicated secure DNS port. | **Native** (Android Private DNS). |
| **DoH** | `443` | Standard HTTPS web port. | **Native** (Windows 11, iOS, Browsers). |

## 🏠 Home Assistant Addon
ShieldDNS is available as an official Home Assistant Addon, featuring full **Ingress** support for the Admin Dashboard.
[View Addon Repo](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)
