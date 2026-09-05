# ShieldDNS Cluster & High Availability Architecture 🌐

ShieldDNS supports multi-node clustering and federation to provide high availability, distributed edge resolution, and unified management across multiple instances.

---

## 🏗️ Roles & Topologies

### 1. Primary (Master Controller)
- **Central Authority**: Blocklists, allowlists, custom rewrite mappings, threat thresholds, and access control settings originate here.
- **Admin & MFA Management**: Password hashes and multi-factor authentication credentials (TOTP, WebAuthn Passkeys) are managed solely on the Primary.
- **Replica Registry**: Tracks all registered edge nodes, last-seen timestamps, sync status, and replica health.
- **Log Aggregation**: Can ingest and display unified DNS query traffic across all cluster nodes.

### 2. Secondary / Replica (Edge Resolver)
- **Automated Sync**: Pulls configuration from the Primary on startup and on scheduled intervals (hourly, 6-hourly, daily).
- **Offline Fallback**: If connection to the Primary is lost, the replica continues uninterrupted using cached configurations and credentials.
- **Read-Only Security Safeguards**: Password changes and MFA modifications are locked on replicas (`403 Forbidden`) to prevent split-brain auth divergence.
- **Optional Failover Upstream**: Can forward cache-missed queries directly to the Primary as its first upstream DNS resolver.

---

## 🌍 Environment Profiles

Each node can be configured with an environment profile tailored to its network position:

| Profile | Target Environment | Rate Limits | Security Controls |
|---|---|---|---|
| **Private (LAN)** | Home network / internal appliance / Home Assistant | Generous (>= 200 QPS) | Local DNS rebinding protection enabled; router guides displayed on landing page |
| **Public** | VPS / Public Cloud edge | Strict (60 QPS) | Aggressive abuse detection; DoH/DoT setup guides; router guides hidden |
| **Hybrid** | Cloud VPS acting as external failover for local networks | Balanced (120 QPS) | Rebinding disabled for external traversal; both LAN router and mobile profiles supported |

---

## 📊 Query Log Replication Modes

Cluster log aggregation is customizable under **Settings &rarr; Cluster & Multi-Node**:

1. **Local Only (`local_only`)**: Each node stores and displays only queries generated locally.
2. **Forward to Primary (`push_to_primary`)**: Replicas stream their query logs to the Primary during sync cycles. The Primary provides a unified global query log with node identification badges.
3. **Full Sync (`full_sync`)**: Both Primary and Replicas synchronize and aggregate all query logs.

---

## 🤖 MCP (Model Context Protocol) Integration

ShieldDNS includes an embedded MCP server endpoint (`/api/mcp`) supporting JSON-RPC 2.0 with tools for cluster analytics, debugging, and administrative control:

- `cluster_status`: Inspect cluster topology, connection health, failover configuration, and registered replicas.
- `cluster_sync`: Trigger immediate synchronization between replica and primary.
- `cluster_log_analytics`: Analyze traffic breakdown and volume per cluster node.
- `cluster_revoke_replica`: Disconnect an untrusted or retired replica.

---

## 📖 Related Guides
- [High-Availability Failover with Cloudflare Worker](cloudflare_worker_failover.md)
- [Mobile Device Setup Guide](mobile_setup_help.md)
