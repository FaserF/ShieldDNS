# ShieldDNS Policy-Based Routing Rules 🔀

ShieldDNS supports selective DNS routing rules that allow steering queries for specific domains or client IP subnets through dedicated resolution paths while preserving the full ShieldDNS security, blocking, and caching pipeline.

---

## 🧭 Routing Modes

ShieldDNS classifies routing rules into three configurable targets:

### 1. Mode A: Normal Default Routing (`default`)
- Queries follow standard upstream DNS or configured encrypted DNS-over-TLS (DoT) upstreams.
- Uses configured latency-based smart upstream selection and failover.
- Default behavior when no specific routing rule matches.

### 2. Mode B: Specific Host Routing (`host`)
- Routes queries for specific domains directly to a dedicated upstream DNS host (e.g. Master/Slave node, internal Windows Active Directory DNS, or specific upstream resolver).
- Syntax: IP or hostname with optional port (e.g. `192.168.1.1:53` or `ad-dc.corp.local:53`).
- Ideal for split-horizon DNS, intranet resolving, and Master/Slave cluster setups.

### 3. Mode C: WireGuard VPN Exit Routing (`wireguard`)
- Steers queries through a dedicated WireGuard tunnel endpoint while preserving all ShieldDNS protection layers:
  - Adblock and threat lists remain actively enforced.
  - DNS cache and prefetching continue to accelerate query resolution.
  - Queries are forwarded to the WireGuard gateway / remote VPN DNS resolver (e.g. `10.200.0.1:53`).
- Fallback: If no rule-specific `wireguard_config` is defined, the global `wireguard_gateway` setting is utilized.

---

## 🛠️ Configuration & API

### REST API Endpoints

#### `GET /api/routing/rules`
Lists all active routing rules and the default WireGuard gateway.
```json
{
  "rules": [
    {
      "id": "corp-rule-1",
      "name": "Corporate Intranet",
      "match": "corp.internal",
      "match_type": "domain",
      "target": "host",
      "host_target": "192.168.10.1:53",
      "enabled": true
    },
    {
      "id": "vpn-rule-2",
      "name": "Secure VPN Exit",
      "match": "secure.external.net",
      "match_type": "domain",
      "target": "wireguard",
      "wireguard_config": "10.200.0.1:53",
      "enabled": true
    }
  ],
  "wireguard_gateway": "10.200.0.1:53"
}
```

#### `POST /api/routing/rules`
Create or update a routing rule:
```json
{
  "name": "Corporate AD",
  "match": "corp.internal",
  "match_type": "domain",
  "target": "host",
  "host_target": "10.0.0.1:53",
  "enabled": true
}
```

#### `DELETE /api/routing/rules?match=corp.internal`
Removes the specified routing rule.

---

## 🤖 MCP (Model Context Protocol) Integration

ShieldDNS includes embedded MCP tools for AI assistants and autonomous automation:
- `list_routing_rules`: Inspect current routing configuration and active rules.
- `set_routing_rule`: Create or modify a routing rule with target `default`, `host`, or `wireguard`.
- `delete_routing_rule`: Remove an existing routing rule by match domain or IP.

---

## 🏠 Home Assistant Integration

The Home Assistant integration (`ha-shielddns`) provides native services:
- `shielddns.set_routing_rule`: Add or update domain/IP routing rules via automations.
- `shielddns.delete_routing_rule`: Remove routing rules dynamically.
