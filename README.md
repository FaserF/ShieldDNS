<img src="logo.png" align="right" width="128" height="128">

# ShieldDNS 🛡️

**ShieldDNS** is a high-performance, hardened, privacy-focused DNS solution supporting **DNS-over-TLS (DoT)** and standard DNS.

It features a premium **Admin Dashboard** with persistent SQLite-backed analytics, custom rule management, and a powerful **Filtering Engine** compatible with AdGuard, Pi-hole, and uBlock origin lists.

## 🚀 Key Features

- 🔒 **Secure DNS**: Native support for **DNS-over-TLS (DoT)** (port 853) for encrypted, private lookups.
- 📊 **Persistent Analytics**: SQLite-backed query history and advanced analytics (Top Blocked Domains, Top Clients).
- 🏳️ **Custom Rules**: Instantly allow or block individual domains via the Admin UI.
- 🛡️ **DNS Filtering**: Integrated engine for blocklists with automatic updates and deduplication.
- ⚡ **Optimized Performance**: Intelligent caching and prefetching enabled by default for ultra-low latency.
- 🔐 **Secure Admin**: Mandatory password protection (bcrypt) for the Admin UI on port 443.
- 📱 **Modern Protocols**: Perfect for Android Private DNS and standard system-wide filtering.

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

### 🏳️ Custom Rules
Immediately take control of your network without managing external lists:
- **Custom Blocklist**: Instantly block any domain (e.g., `tiktok.com`).
- **Custom Whitelist**: Ensure critical domains (e.g., `myvpn.com`) are never blocked.

### ⚡ Optimization & Health
- **Intelligent Caching**: Large 10k entry cache reduces upstream lookups.
- **Prefetching**: ShieldDNS proactively refreshes popular records before they expire.
- **Upstream Probing**: Background health checks every 30 seconds ensure you only use healthy upstreams.

## 📱 Client Configuration

### DoT (DNS-over-TLS) - Port 853
- **Android**: Go to **Settings > Network > Private DNS** and enter your domain (e.g., `dns.example.com`).
- **iOS/macOS**: Use a `.mobileconfig` profile pointing to your DoT endpoint.

## 🛡️ Security Best Practices
1.  **Password**: Use a strong, unique password for the Admin UI.
2.  **Certificates**: Use valid Let's Encrypt certificates for both DoT and the Admin UI.
3.  **Firewall**: Only expose ports 53, 443, and 853.

## 🏠 Home Assistant Addon
ShieldDNS is available as an official Home Assistant Addon with Ingress support.
[View Addon Repo](https://github.com/FaserF/hassio-addons/tree/master/ShieldDNS)
