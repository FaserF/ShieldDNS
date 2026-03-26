<img src="www/logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a high-performance, hardened, privacy-focused DNS solution supporting **DNS-over-TLS (DoT)** and standard DNS.

It features a premium **Admin Dashboard** with persistent SQLite-backed analytics, custom rule management, and a powerful **Filtering Engine** compatible with AdGuard, Pi-hole, and uBlock origin lists.

## 🚀 Key Features

- 🔒 **Secure DNS**: Native support for **DNS-over-TLS (DoT)** (port 853) for encrypted, private lookups.
- 📊 **Persistent Analytics**: SQLite-backed query history and advanced analytics (Top Blocked Domains, Top Clients).
- 🏳️ **Custom Rules**: Instantly allow or block individual domains via the Admin UI.
- 🛡️ **DNS Filtering**: Integrated engine for blocklists with automatic updates and deduplication.
- 🔌 **Protection Kill-Switch**: Instantly disable all filtering via the dashboard or API.
- ⚡ **Optimized Performance**: Intelligent caching and prefetching enabled by default for ultra-low latency.
- 🔐 **Secure Admin**: Mandatory password protection (bcrypt) for the Admin UI on port 443.
- 📱 **Modern Protocols**: Perfect for Android Private DNS and standard system-wide filtering.
- ⚡ **Live Monitoring**: Real-time query log updates via Server-Sent Events (SSE).
- 🧠 **Smart DNS**: Automatic upstream selection based on live latency (RTT) measurements.

## 🧐 ShieldDNS vs. AdGuard Home vs. Pi-hole

ShieldDNS is a modern, lightweight alternative to established solutions like AdGuard Home or Pi-hole. It was built with a focus on performance (CoreDNS-based) and native support for encrypted DNS (DoT/DoH).

### 🛡️ Comparison Table

| Feature | ShieldDNS 🛡️ | AdGuard Home | Pi-hole |
| :--- | :--- | :--- | :--- |
| **Base** | CoreDNS (Go) | Cloudflare Go | dnsmasq (C) |
| **DoT (Port 853)** | Native ✅ | Native ✅ | Requires Unbound ❌ |
| **DoH (Port 443)** | Native ✅ | Native ✅ | Requires cloudflared ❌ |
| **Performance** | Ultra-High (Go/WAL) | High | Moderate (dnsmasq) |
| **Analytics** | SQLite (WAL/Batching) | Internal (Local) | FTL (C/Stats) |
| **Hardening** | AEAD-only Ciphers  | Standard | Upstream Dependent |
| **Home Assistant** | [HA App Available](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS) | HA App Available | HA App Available |

### 🛠️ Pros and Cons

#### **ShieldDNS**
- **Pros**: Incredibly performant thanks to the CoreDNS core; native DoT support (perfect for Android Private DNS); modern DoH stack; transaction-safe logging via SQLite WAL; real-time SSE updates.
- **Cons**: More focused feature set than AdGuard Home (no DNS-over-QUIC yet); minimalist UI designed for efficiency.

#### **AdGuard Home**
- **Pros**: Very comprehensive user interface; supports DNS-over-QUIC; integrated parental controls.
- **Cons**: Can be more resource-intensive with many clients; more closed architecture.

#### **Pi-hole**
- **Pros**: Massive community support; runs on almost any hardware; very detailed statistics.
- **Cons**: Based on `dnsmasq`; lacks native DoT/DoH support (often requires additional Docker containers like `unbound`).

## 🛠️ Usage

### Docker Compose

```yaml
services:
  shielddns:
    image: ghcr.io/faserf/shielddns:latest
    ports:
      - "53:53/udp"      # DNS (UDP)
      - "53:53/tcp"      # DNS (TCP)
      - "853:853/tcp"    # DoT
      - "443:443/tcp"    # Admin Dashboard (HTTPS)
    environment:
      - UPSTREAM_DNS=86.54.11.100, 1.1.1.1, 9.9.9.9, 8.8.8.8, 1.0.0.1 # Max 5
      - UPSTREAM_DOT=unfiltered.joindns4.eu, dns.quad9.net, one.one.one.one # Max 5
      - PREFER_ENCRYPTED=true # Set to true to prefer DoT over standard DNS
      - LOG_LEVEL=info # debug, info, error
      - CERT_FILE=/ssl/fullchain.pem
      - KEY_FILE=/ssl/privkey.pem
      - DATA_DIR=/etc/shielddns # Optional: customize data path
    volumes:
      - ./ssl:/ssl
      - ./data:/etc/shielddns # Persistent config, database, and lists
```

## 🛠️ Troubleshooting

### Port 53 already in use
On many Linux systems (like Ubuntu), `systemd-resolved` uses port 53 by default. To use ShieldDNS, you must disable the stub listener on your host:

1. Edit `/etc/systemd/resolved.conf` and set `DNSStubListener=no`.
2. Run `sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf`.
3. Restart the service: `sudo systemctl restart systemd-resolved`.

### Oracle Cloud VM (OCI) - Ubuntu 24.04
Oracle Cloud VMs have multiple layers of firewalls. For 2026, the recommended approach is as follows:

1. **OCI Console**: Use the search bar to find **Network Security Groups**. Add ingress rules for UDP 53 and TCP 53, 443, 853.
2. **Host Firewall (iptables)**:
```bash
sudo iptables -I INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 53,443,853 -j ACCEPT
sudo netfilter-persistent save
```

## 🔐 API Key Management & RBAC

ShieldDNS includes a secure, granular API key system for remote monitoring and automation (e.g., Home Assistant integration).

### Authentication
Authenticate by sending your API key in the `X-API-Key` header or as a `Bearer` token in the `Authorization` header.

### Permissions (RBAC)
ShieldDNS uses a Role-Based Access Control model. Tokens can be restricted to:
- `read:stats`: Dashboard metrics and analytics history.
- `read:logs`: Sensitive data including Query Logs and Client IPs.
- `read:system`: System terminal logs, SSL diagnostics, and backups.
- `write:filtering`: Toggle the global protection/filtering engine.
- `read:all`: Grant all read-only permissions above.

### Health Endpoints
- `/api/health/live`: Public endpoint for container liveness checks (No authentication required).
- `/api/health/ready`: System readiness check (Requires `read:system` permission).

> [!IMPORTANT]
> **Security Guard Policy**: If no API keys are defined in the Settings, all token-based authentication attempts are rejected by default.

## 🖥️ Admin Dashboard

Access the dashboard at `https://YOUR_SERVER_IP/`.

### 🛡️ Setup Wizard
On your first visit, a multi-step setup wizard will guide you through:
1.  **Security**: Setting a strong administrative password (hashed with bcrypt).
2.  **Upstream DNS**: Selecting your preferred DoT and standard DNS providers.
3.  **Protection**: Choosing from a curated catalog of industry-standard blocklists.

### 📊 Advanced Analytics
ShieldDNS now stores your query history in a persistent SQLite database:
- **Query History**: View the last 100 queries or search through historical data.
- **Top Blocked Domains**: identify the most aggressive trackers on your network.
- **Top Clients**: See which devices are generating the most traffic.
- **Hourly Trends**: 24-hour traffic visualization shows you exactly when your network is most active.
- **Cache Hit Ratio**: Real-time diagnostic tracker showing the percentage of queries served from the local cache.
- **Query-Type Breakdown**: Professional visualization of DNS record types (A, AAAA, MX, etc.).
- **Live Logs**: Zero-latency query streaming via Server-Sent Events (SSE).

### 🏳️ Custom Rules
Immediately take control of your network without managing external lists:
- **Custom Blocklist**: Instantly block any domain (e.g., `tiktok.com`).
- **Custom Allowlist**: Ensure critical domains (e.g., `myvpn.com`) are never blocked.

### ⚡ Optimization & Health
- **Intelligent Caching**: Large 10k entry cache reduces upstream lookups.
- **Prefetching**: ShieldDNS proactively refreshes popular records before they expire.
- **Upstream Probing**: Background health checks every 30 seconds ensure you only use healthy upstreams.
- **Smart Selection**: Optionally reorder upstreams dynamically to always use the lowest-latency provider.
- **Data Retention**: Configurable history purging (e.g., 7, 30, 90 days) for privacy and disk management.
- **System Backups**: One-click `.zip` backup of configuration and query history.

## 📱 Client Configuration

### DoT (DNS-over-TLS) - Port 853
- **Android**: Go to **Settings > Network > Private DNS** and enter your domain (e.g., `dns.example.com`).
- **iOS/macOS**: Use a `.mobileconfig` profile pointing to your DoT endpoint.

## 🛡️ Technical Hardening
ShieldDNS is built for extreme reliability in production environments:
1.  **Graceful Shutdown**: SIGTERM/SIGINT handling ensures all buffered logs are flushed to SQLite and connections are closed safely, preventing data corruption.
2.  **IPv6 Robustness**: Native support for IPv6 client IP extraction using `net.SplitHostPort`.
3.  **Brute-Force Protection**: Intelligent rate-limiting on the `/api/login` endpoint (max 5 attempts/min/IP).
4.  **Modern TLS**: Enforced AEAD-only cipher suites (TLS 1.2/1.3) for all management and DNS-over-TLS endpoints.

## 🛡️ Security Best Practices
1.  **Password**: Use a strong, unique password for the Admin UI.
2.  **Certificates**: Use valid Let's Encrypt certificates for both DoT and the Admin UI.
3.  **Firewall**: Only expose ports 53, 443, and 853.

## 🏠 Home Assistant Addon
ShieldDNS is available as an official Home Assistant Addon with Ingress support.
[View Addon Repo](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)
