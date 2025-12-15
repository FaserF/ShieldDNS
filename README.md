# ShieldDNS 🛡️

**ShieldDNS** is a lightweight, efficient, and privacy-focused DNS-over-TLS (DoT) proxy.

It enables you to securely accept DNS queries (e.g., Android Private DNS) and forward them to your local DNS server (AdGuard Home, Pi-hole) or public resolvers.

## Features
- 🔒 **DNS-over-TLS (DoT)**
- 🚇 **Cloudflare Tunnel Support**: Expose your DoT server without opening ports.
- 🚀 **High Performance**: Alpine + CoreDNS.
- 🪵 **Flexible Logging**: Configurable log levels.

## Usage

### Docker Compose

```yaml
services:
  shielddns:
    image: ghcr.io/faserf/shielddns:latest
    ports:
      - "853:853"
    environment:
      - UPSTREAM_DNS=1.1.1.1
      - CLOUDFLARE_TUNNEL_TOKEN=eyJh... # Optional
      - LOG_LEVEL=info # debug, info, error
      - CERT_FILE=/certs/fullchain.pem
      - KEY_FILE=/certs/privkey.pem
    volumes:
      - ./certs:/certs
```

## Home Assistant Addon
This project is also available as a Home Assistant Addon.
See [addon/README.md](addon/README.md) for details.
