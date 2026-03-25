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
      - "53:53/udp"      # DNS (UDP)
      - "53:53/tcp"      # DNS (TCP)
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

## 🛠️ Troubleshooting

### Port 53 already in use
On many Linux systems (like Ubuntu), `systemd-resolved` uses port 53 by default. To use ShieldDNS, you must disable the stub listener on your host:

1. Edit `/etc/systemd/resolved.conf` and set `DNSStubListener=no`.
2. Run `sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf`.
3. Restart the service: `sudo systemctl restart systemd-resolved`.

### Oracle Cloud VM (OCI) - Ubuntu 24.04
Oracle Cloud VMs have multiple layers of firewalls. For 2026, the recommended approach is as follows:

#### 1. OCI Console (Network Security)
The fastest way to navigate the OCI Console is using the **Search Bar** at the top. Search for **"Network Security Groups"** or **"Security Lists"**.

**Option A: Network Security Group (Recommended)**
1. Search for **Network Security Groups** and select your VCN's group.
2. Add **Security Rules**:
   - **Ingress**, Protocol: **UDP**, Port: **53** (DNS)
   - **Ingress**, Protocol: **TCP**, Port: **53, 443, 853**

**Option B: Security Lists**
1. Navigate to **Networking > Virtual Cloud Networks > [Your VCN] > Security Lists**.
2. Add **Ingress Rules** (Stateless: No) for the ports mentioned above.

#### 2. Host Firewall (iptables)
OCI's Ubuntu images block all traffic by default. You **must** run these commands on the VM:
```bash
# Allow DNS (UDP/TCP), DoH/Admin (443), and DoT (853)
sudo iptables -I INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT -p tcp -m multiport --dports 53,443,853 -j ACCEPT

# Save the rules so they survive a reboot
sudo netfilter-persistent save
```

## 🛡️ Default Blocklists

ShieldDNS comes pre-configured with several industry-standard blocklists to provide immediate protection. You can enable, disable, or add custom lists via the Admin Dashboard.

### Out-of-the-box Protection (Enabled by Default)
- **AdGuard DNS Filter**: Comprehensive protection against ads and tracking.
- **AdAway Default**: Mobile-focused ad and malware blocking.
- **Peter Lowe's List**: A long-standing, curated list of ad and tracking servers.

### Available Presets (One-click Activation)
The Admin UI provides an extensive **Catalog of 20+ premium presets**, including:
- **Hagezi**: TIF (Threat Intelligence), Multi (Light to Ultimate tiers), Gambling, and Fake Stores.
- **OISD**: Basic and Full lists.
- **AdGuard & uBlock**: Specialized Tracking, Social Media, Annoyances, and uBlock Origin filters.
- **Steven Black**: Unified + Porn/Gambling/FakeNews variants.
- **1Hosts**: Lite and Pro tiers.
- **Specialized**: Phishing Database, Game Console Adblock, and Hacked Site lists.

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
