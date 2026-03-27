<img src="www/logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a high-performance, hardened, privacy-focused DNS solution supporting **DNS-over-TLS (DoT)**, **DNS-over-HTTPS (DoH)**, **DNS-over-QUIC (DoQ)** and standard DNS.

It features a premium **Admin Dashboard** with persistent SQLite-backed analytics, custom rule management, and a powerful **Filtering Engine** compatible with AdGuard, Pi-hole, and uBlock origin lists.

## 🚀 Key Features

- 🔒 **Secure DNS**: Native support for **DNS-over-TLS (DoT)** (port 853), **DNS-over-HTTPS (DoH)** (port 443), and **DNS-over-QUIC (DoQ)** — zero extra setup needed.
- 📊 **Persistent Analytics**: SQLite-backed query history and advanced analytics (Top Blocked Domains, Top Clients).
- 🏳️ **Custom Rules**: Instantly allow or block individual domains via the Admin UI. Input is auto-sanitized — paste a full URL if you like!
- 🛡️ **DNS Filtering**: Integrated engine for blocklists with automatic updates and deduplication.
- 🔌 **Protection Kill-Switch**: Instantly disable all filtering via the dashboard or API.
- ⚡ **Optimized Performance**: Intelligent caching, prefetching, and **Serve Stale** support for instant responses even when upstreams are slow.
- 🔐 **Secure Admin**: Mandatory password protection (bcrypt) for the Admin UI on port 443.
- 📱 **Modern Protocols**: Perfect for Android Private DNS and standard system-wide filtering (iOS `.mobileconfig` with DoT/DoH/DoQ support).
- ⚡ **Live Monitoring**: Real-time query log updates via Server-Sent Events (SSE).
- 🧠 **Smart DNS**: Automatic upstream selection based on live latency (RTT) with **Broadcast Mode** for ultra-low latency.
- 🌙 **Dark & Light Mode**: Full theme support, persisted locally per user.
- 🔄 **Config Backup & Restore**: One-click backup download and in-browser JSON configuration restore.
- ⚡ **1-Click Allow / Block**: Directly allow or block any domain from the live Query Log table.
- 🔍 **Client IP Diagnostics**: Clickable Client IPs in logs with detailed GeoIP, Reverse DNS, and history preview.
- 🧹 **Optimized Default Lists**: Ships with a single, curated default (HaGeZi Multi Normal) for maximum protection with minimal RAM usage on any hardware — including Raspberry Pi.

## ❤️ Support This Project

> I maintain this Project in my **free time alongside my regular job** — bug hunting, new features, and keeping up with OCI updates. Every donation helps me stay independent and dedicate more time to open-source work.
>
> **This project is and will always remain 100% free.**
>
> Donations are completely voluntary — but the more support I receive, the more time I can realistically invest into these projects. 💪

<div align="center">

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on-GitHub-%23EA4AAA?style=for-the-badge&logo=github-sponsors&logoColor=white)](https://github.com/sponsors/FaserF)&nbsp;&nbsp;
[![PayPal](https://img.shields.io/badge/Donate%20via-PayPal-%2300457C?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/FaserF)

</div>

## 🧐 ShieldDNS vs. AdGuard Home vs. Pi-hole

ShieldDNS is a modern, lightweight alternative to established solutions like AdGuard Home or Pi-hole. It was built with a focus on performance (CoreDNS-based) and native support for encrypted DNS (DoT/DoH).

### 🛡️ Comparison Table

| Feature | ShieldDNS 🛡️ | AdGuard Home | Pi-hole |
| :--- | :--- | :--- | :--- |
| **Base** | CoreDNS (Go) | Cloudflare Go | dnsmasq (C) |
| **DoT (Port 853)** | Native ✅ | Native ✅ | Requires Unbound ❌ |
| **DoH (Port 443)** | Native ✅ | Native ✅ | Requires cloudflared ❌ |
| **DoQ (QUIC)** | Native ✅ | Native ✅ | ❌ |
| **Performance** | Ultra-High (Go/WAL) | High | Moderate (dnsmasq) |
| **Analytics** | SQLite (WAL/Batching) | Internal (Local) | FTL (C/Stats) |
| **Hardening** | AEAD-only Ciphers  | Standard | Upstream Dependent |
| **Home Assistant** | [HA App Available](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS) | HA App Available | HA App Available |

### 🛠️ Pros and Cons

#### **ShieldDNS**
- **Pros**: Incredibly performant thanks to the CoreDNS core; native DoT/DoH/DoQ support; modern security stack; transaction-safe logging via SQLite WAL; real-time SSE updates.
- **Cons**: Focused feature set designed for efficiency.

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
      - PREFER_ENCRYPTED=true
      - LOG_LEVEL=info
      - DATA_DIR=/etc/shielddns
    volumes:
      - ./ssl:/ssl
      - ./data:/etc/shielddns # Persistent config, database, and lists
```

### 🐋 Standard Docker
If you prefer the command line, use the following to build and run with persistence:
```bash
docker build -t shielddns:local .
docker run -d \
  --name shielddns \
  -p 53:53/udp -p 53:53/tcp \
  -p 443:443/tcp -p 853:853/tcp \
  -v $(pwd)/data:/etc/shielddns \
  -v $(pwd)/ssl:/ssl \
  shielddns:local
```

### 💾 Persistent Storage
To ensure your configuration, query logs, and SSL certificates are saved across container updates and restarts, you **must** mount the following directories:
- `/etc/shielddns` (Config, SQLite Database, Blocklists)
- `/ssl` (Your certificates, or where ShieldDNS generates fallback ones)

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

Access the dashboard at `https://your.domain/`.

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
- **Live Logs**: Zero-latency query streaming via Server-Sent Events (SSE).
- **Client IP Diagnostics**: Interactive query logs where clicking an IP reveals GeoIP location, Reverse DNS hostname, and a client-specific query history preview.
- **Cache Hit Ratio**: Real-time diagnostic tracker showing the percentage of queries served from the local cache.

### 🏳️ Custom Rules
Immediately take control of your network without managing external lists:
- **Custom Blocklist**: Instantly block any domain (e.g., `tiktok.com`). Paste a full URL — it's auto-sanitized to a clean domain.
- **Custom Allowlist**: Ensure critical domains are never blocked.
- **1-Click Allow/Block**: Act on any domain directly from the live Query Log without copy-pasting.

### ⚡ Optimization & Health
- **Intelligent Caching**: Large 10k entry cache reduces upstream lookups.
- **IP Info Caching**: In-memory caching for GeoIP and Reverse DNS lookups (cached for 24h) to ensure zero-latency UI interaction.
- **Prefetching**: ShieldDNS proactively refreshes popular records before they expire.
- **Upstream Probing**: Background health checks every 30 seconds ensure you only use healthy upstreams.
- **Smart Selection**: Optionally reorder upstreams dynamically to always use the lowest-latency provider.
- **Data Retention**: Configurable history purging (e.g., 7, 30, 90 days) for privacy and disk management.
- **System Backups**: One-click `.zip` backup of configuration and query history.
- **Config Restore**: Upload a `config.json` directly from the Settings page to instantly restore a previous configuration.
- **Dark & Light Mode**: Toggle the UI theme — preference is saved locally.
- **Optimized Default Lists**: Ships with a single curated default (HaGeZi Multi Normal). Avoids enabling multiple overlapping lists (e.g., OISD + HaGeZi + AdGuard) by default, which would triple RAM usage with near-zero added coverage.
- **Streaming Blocklist Downloader**: Lists are processed line-by-line via streaming (not loaded fully into RAM) — critical for low-memory hardware like Raspberry Pi 3/4.
- **Structured Log Parsing**: Uses CoreDNS structured log format for robust, format-change-resistant query parsing.


## 📱 Client Configuration

### DoT (DNS-over-TLS) & DoQ (DNS-over-QUIC) - Port 853
- **Android**: Go to **Settings > Network > Private DNS** and enter your domain (e.g., `dns.example.com`). Modern Android versions will automatically attempt DoT first. For DoQ, use a supporting app like *Nebulo* or *Personal DNS Filter*.
- **iOS/macOS**: Download the `.mobileconfig` from your ShieldDNS dashboard. It implements both DoT and DoH. For native DoQ, ensure you are on iOS 17+.

### ⚡ Setup DNS-over-QUIC (DoQ)
DNS-over-QUIC is the fastest encrypted protocol as it eliminates TCP head-of-line blocking. ShieldDNS supports it out of the box on port 853.

#### **Android (Advanced)**
While standard "Private DNS" uses DoT, you can use **DoQ** for even better performance on unstable networks:
1. Install an app like [Google Intra](https://play.google.com/store/apps/details?id=app.intra), or [AdGuard for Android](https://adguard.com/).
2. Add a custom server: `quic://your.domain:853`.

#### **iOS (Native)**
ShieldDNS provides a profile that prefers DoT/DoH. To specifically force **DoQ**:
1. Port 853 (UDP) must be open in your firewall.
2. Use an app like [DNSecure](https://apps.apple.com/app/dnsecure/id1531065103) and enter `quic://your.domain`.

### OpenWrt Integration (Best Practices)
If you host ShieldDNS publicly and want to route your entire home network through it via an OpenWrt router, follow these steps:

#### 1. Configure DNS Forwarding
Navigate to **Network > DHCP and DNS** in LuCI:
- **DNS forwardings**: Enter the IP of your ShieldDNS server (e.g., `94.31.75.54`).
- **Fallback**: Add a secondary DNS server (e.g., `1.1.1.1`) as a second entry.
- **Strict Order**: (Optional) In the **Advanced Settings** tab, check `Strict Order` to ensure ShieldDNS is always tried first.

#### 2. Enforce ShieldDNS (DNS Hijacking)
To prevent devices from bypassing ShieldDNS by using hardcoded DNS servers (like 8.8.8.8), add a NAT rule under **Network > Firewall > Traffic Rules > DNAT**:
- **Protocol**: `UDP`, `TCP`
- **Source zone**: `lan`
- **Destination port**: `53`
- **Action**: `DNAT`
- **Rewrite IP**: (Select your router's LAN IP)
- **Rewrite port**: `53`

This forces all DNS traffic on your network to go through the router's DNSmasq, which then forwards it to ShieldDNS.

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

## 📋 Blocklist Recommendations

The preset catalog is organized by category. For most home users, the following configuration offers the best balance of protection vs. compatibility:

| Scenario | Recommended Lists |
| :--- | :--- |
| **Minimal (fast, few false positives)** | HaGeZi Multi (Light) |
| **Balanced (recommended default ✅)** | HaGeZi Multi (Normal) |
| **Max Protection** | HaGeZi Multi (Pro) + HaGeZi TIF |
| **+ Malware/Phishing** | + HaGeZi TIF (Threat Intelligence) |
| **+ Adult Content Blocking** | + OISD NSFW |
| **+ Regional (German)** | + KADhost (German Blocklist) |

> [!WARNING]
> **Avoid enabling multiple large lists in the same category at once** (e.g., HaGeZi Normal + OISD Full + AdGuard Main). These lists overlap heavily — using all three triples your RAM consumption without adding meaningful coverage.

> [!TIP]
> **UI Feedback**: When lists are downloading, real-time progress entries appear in the **System Logs** tab. On first setup with many large lists, the dashboard may take 1–2 minutes to populate blocklist data — this is normal.

## 🧪 Testing Your Setup

To verify that your devices are correctly using ShieldDNS and that filtering is active, you can visit the following built-in test URL in your browser:

👉 **[https://shielddns-maleware.test](https://shielddns-maleware.test)**

This test domain is permanently blocked at the system level regardless of which blocklists you have enabled. If ShieldDNS is working correctly, you will see the official ShieldDNS "Website Blocked" page.

## 💻 Development & Testing

ShieldDNS uses Go's standard `testing` package with a fully in-memory test environment (no Docker required).

```bash
# Run all tests
cd admin
go test ./... -v

# Run a specific test
go test ./... -run TestProcessList_StreamingMemoryEfficiency -v
```

### Test Coverage

| Area | Test File | What's Covered |
| :--- | :--- | :--- |
| Blocklist streaming parser | `config_test.go` | AdBlock/hosts/dnsmasq/allowlist formats, streaming line-by-line download |
| CoreDNS log parser | `dns_test.go` | Structured log format, blocked detection, SSE broadcast, latency parsing |
| API handlers | `main_test.go`, `api_test.go` | Stats, search, history, auth, token management |
| Upstream health & smart sorting | `main_test.go` | Latency-based upstream ordering, Corefile generation |
| Presets integrity | `presets_test.go` | Default preset list availability |

## 🏠 Home Assistant Integration


ShieldDNS has full first-class Home Assistant support:

- **Official HA Addon** (run ShieldDNS directly inside Home Assistant with Ingress support):
  👉 [hassio-addons / ShieldDNS](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)

- **Official HA Integration** (expose ShieldDNS stats and controls as sensors/services in Home Assistant):
  👉 [ha-shielddns](https://github.com/FaserF/ha-shielddns)

## 🙏 Acknowledgements

ShieldDNS stands on the shoulders of giants. We would like to express our profound gratitude to the following projects:

- **[CoreDNS](https://coredns.io/)**: The incredibly fast, flexible, and robust CNCF-hosted DNS server that powers the core naming resolution engine of ShieldDNS.
- **[AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)** & **[Pi-hole](https://pi-hole.net/)**: The trailblazers in network-wide ad-blocking. Their pioneering ideas, standard-setting filter list syntax, and community-driven approach deeply inspired the development and feature-set of ShieldDNS.

## 📄 License

**ShieldDNS** is released under the **[ShieldDNS Personal & Internal Commercial License](LICENSE)**.

✅ **Allowed (Free)**:
- Personal and home usage.
- Internal business/company usage to protect your own networks or employees.

❌ **Prohibited (Without Permission)**:
- Commercial hosted services (e.g., offering ShieldDNS as a paid cloud service or SaaS).
- Reselling the software or packaging it into a commercial product for profit.

For the full legal text, please review the [LICENSE](LICENSE) file.
