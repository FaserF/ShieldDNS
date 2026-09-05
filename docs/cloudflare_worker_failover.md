# High-Availability & Failover with Cloudflare Worker 🌐

This guide demonstrates how to configure high availability (HA), automatic health-checked failover, and load balancing between two public ShieldDNS nodes (Primary and Secondary/Replica) using a **Cloudflare Worker**.

---

## 🎯 Architecture Overview

```
                          [ Client Devices ]
                       (DoH / Browser / Mobile)
                                  │
                                  ▼
               ┌─────────────────────────────────────┐
               │ Cloudflare Worker (Dispatcher)      │
               │  - Host: worker.yourdomain.com      │
               │  - Path: /dns-query (DoH)           │
               │  - Shortcuts: /master, /slave       │
               │  - Background Health Checks         │
               └──────────────────┬──────────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 ▼ (Healthy: Active)               ▼ (Failover: Standby)
     ┌───────────────────────┐          ┌───────────────────────┐
     │  Primary ShieldDNS    │          │  Secondary ShieldDNS  │
     │  dns1.yourdomain.com  │◄────────►│  dns2.yourdomain.com  │
     │  (Central Controller) │  Cluster │  (Edge Replica)       │
     └───────────────────────┘   Sync   └───────────────────────┘
```

- **Cloudflare Worker** acts as the high-performance global dispatcher:
  - Forwards DNS queries (`/dns-query`) using standard DNS-over-HTTPS (DoH).
  - Actively checks `/api/health/live` on both ShieldDNS nodes.
  - Automatically routes traffic to the Secondary node if the Primary is down or degraded.
  - Supports administrative shortcuts like `https://worker.yourdomain.com/master` and `https://worker.yourdomain.com/slave`.
- **ShieldDNS Cluster** keeps blocklists, custom rules, and security policies synchronized between Primary and Secondary in real time.

---

## 📋 Prerequisites

1. Two publicly reachable ShieldDNS instances:
   - **Primary Node**: e.g., `https://dns1.yourdomain.com`
   - **Secondary Node**: e.g., `https://dns2.yourdomain.com`
2. A Cloudflare account with your custom domain (e.g. `yourdomain.com`).
3. Cloudflare Workers enabled (free tier is fully sufficient).

---

## ⚙️ Step 1: Configure ShieldDNS Cluster Settings

### 1. On the Primary Node (`dns1.yourdomain.com`)
1. Log in to the Admin Dashboard.
2. Go to **Settings** &rarr; **Cluster & Multi-Node**.
3. Set **Cluster Role** to `Primary (Central Configuration Master)`.
4. Enter your Cloudflare Worker hostname in **Cloudflare Worker Dispatcher Domain**:
   ```
   worker.yourdomain.com
   ```
5. Click **Save Configuration**.
6. Under **Access & Security**, create an API Key with `cluster:sync` (or Cluster Sync) permission. Save the generated key.

### 2. On the Secondary Node (`dns2.yourdomain.com`)
1. Log in to the Admin Dashboard.
2. Go to **Settings** &rarr; **Cluster & Multi-Node**.
3. Set **Cluster Role** to `Secondary / Replica`.
4. Set **Primary ShieldDNS URL** to `https://dns1.yourdomain.com`.
5. Enter the API Token created on the Primary node.
6. Check **Use Primary as Upstream DNS Resolver (Failover Resolver)** if desired.
7. Click **Sync Now from Primary** and **Save Configuration**.

> [!NOTE]
> Once synchronized as a Replica, admin password changes and MFA configurations are locked on the Secondary node and managed exclusively through the Primary node.

---

## 💻 Step 2: Deploy Cloudflare Worker

### Option A: Using Wrangler CLI

Create a new Wrangler project:
```bash
npm create cloudflare@latest shielddns-dispatcher -- --type hello-world
cd shielddns-dispatcher
```

Replace `src/index.js` (or `src/index.ts`) with the following production-ready Worker code:

```javascript
/**
 * ShieldDNS High-Availability Dispatcher & Failover Worker
 * 
 * Features:
 * - High-speed DNS-over-HTTPS (DoH) proxying to Primary and Secondary nodes
 * - Automatic active health checks with fast failover
 * - Administrative shortcut redirects (/master, /slave, /primary, /replica)
 * - Worker proxy authentication header injection
 */

/**
 * Configuration for Multi-Region Nodes & Dynamic Steering
 * NODES: Define any number of primary/replica/edge instances.
 * Each node specifies:
 *   - url: Base URL of the ShieldDNS instance
 *   - role: 'primary' | 'secondary' | 'edge'
 *   - preferredCountries: Array of ISO country codes (e.g. ['TR', 'DE', 'US'])
 *   - preferredContinents: Array of continent codes (e.g. ['EU', 'NA', 'AS', 'AF', 'OC', 'SA'])
 */
const CONFIG = {
  HEALTH_CHECK_PATH: "/api/health/live",
  HEALTH_TIMEOUT_MS: 1500,
  WORKER_SHARED_SECRET: "shielddns-worker-secure-token",

  NODES: [
    {
      id: "primary",
      name: "Primary Controller",
      url: "https://dns1.yourdomain.com",
      role: "primary",
      preferredCountries: ["DE", "AT", "CH", "NL", "FR"],
      preferredContinents: ["EU"],
    },
    {
      id: "secondary",
      name: "Secondary / Edge Replica",
      url: "https://dns2.yourdomain.com",
      role: "secondary",
      preferredCountries: ["TR", "GR", "CY", "BG", "IQ", "GE"],
      preferredContinents: ["AS", "ME"],
    }
  ]
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase().replace(/\/+$/, "");

    // 1. Admin Shortcuts
    const primaryNode = CONFIG.NODES.find(n => n.role === "primary") || CONFIG.NODES[0];
    const secondaryNode = CONFIG.NODES.find(n => n.role === "secondary" || n.role === "edge") || CONFIG.NODES[1] || primaryNode;

    if (path === "/master" || path === "/primary") {
      return Response.redirect(`${primaryNode.url}/admin/`, 302);
    }
    if (path === "/slave" || path === "/replica") {
      return Response.redirect(`${secondaryNode.url}/admin/`, 302);
    }
    if (path === "/admin" || path.startsWith("/admin/")) {
      // Forward Admin UI traffic to Primary by default
      const target = new URL(url.pathname + url.search, primaryNode.url);
      return fetch(new Request(target.toString(), request));
    }

    // 2. DNS-over-HTTPS (DoH) Queries
    if (path === "/dns-query") {
      return handleDoHQuery(request);
    }

    // 3. Root landing page or static info
    return handleLanding(request);
  },
};

/**
 * Handle DNS-over-HTTPS query with universal Geo-proximity steering & health failover
 */
async function handleDoHQuery(request) {
  const clientCountry = (request.cf && request.cf.country) ? request.cf.country.toUpperCase() : "";
  const clientContinent = (request.cf && request.cf.continent) ? request.cf.continent.toUpperCase() : "";

  // 1. Check health of all nodes in parallel
  const healthChecks = await Promise.all(
    CONFIG.NODES.map(async (node) => ({
      ...node,
      isHealthy: await checkNodeHealth(node.url)
    }))
  );

  const healthyNodes = healthChecks.filter(n => n.isHealthy);
  if (healthyNodes.length === 0) {
    // Emergency fallback to primary if all health checks report negative
    healthyNodes.push(CONFIG.NODES[0]);
  }

  // 2. Universal Geo-Proximity Scorer:
  // - Matches country: +100 points
  // - Matches continent: +50 points
  // - Primary node bonus: +10 points (to break ties)
  let bestNode = healthyNodes[0];
  let bestScore = -1;

  for (const node of healthyNodes) {
    let score = 0;
    if (clientCountry && node.preferredCountries && node.preferredCountries.includes(clientCountry)) {
      score += 100;
    } else if (clientContinent && node.preferredContinents && node.preferredContinents.includes(clientContinent)) {
      score += 50;
    }
    if (node.role === "primary") {
      score += 10;
    }
    if (score > bestScore) {
      bestScore = score;
      bestNode = node;
    }
  }

  const targetUrl = new URL(new URL(request.url).pathname + new URL(request.url).search, bestNode.url);

  // Clone headers and add proxy indicator
  const headers = new Headers(request.headers);
  headers.set("X-Forwarded-Host", new URL(request.url).hostname);
  headers.set("X-Client-Country", clientCountry);
  headers.set("X-Client-Continent", clientContinent);
  headers.set("X-Selected-Node", bestNode.id);
  headers.set("X-ShieldDNS-Worker", CONFIG.WORKER_SHARED_SECRET);

  try {
    const response = await fetch(new Request(targetUrl.toString(), {
      method: request.method,
      headers: headers,
      body: request.method === "POST" ? request.body : null,
      redirect: "follow",
    }));

    // If selected node returns 502/503/504, immediately failover to any other healthy node
    if (!response.ok && response.status >= 502 && healthyNodes.length > 1) {
      const fallbackNode = healthyNodes.find(n => n.id !== bestNode.id) || healthyNodes[0];
      const fallbackUrl = new URL(new URL(request.url).pathname + new URL(request.url).search, fallbackNode.url);
      return fetch(new Request(fallbackUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.method === "POST" ? request.body : null,
      }));
    }

    return response;
  } catch (err) {
    // Network error failover
    const fallbackNode = healthyNodes.find(n => n.id !== bestNode.id) || healthyNodes[0];
    const fallbackUrl = new URL(new URL(request.url).pathname + new URL(request.url).search, fallbackNode.url);
    return fetch(new Request(fallbackUrl.toString(), {
      method: request.method,
      headers: headers,
      body: request.method === "POST" ? request.body : null,
    }));
  }
}

/**
 * Perform rapid non-blocking health check
 */
async function checkNodeHealth(baseUrl) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.HEALTH_TIMEOUT_MS);
    
    const resp = await fetch(`${baseUrl}${CONFIG.HEALTH_CHECK_PATH}`, {
      method: "GET",
      signal: controller.signal,
      cf: { cacheTtl: 5, cacheEverything: true }
    });
    clearTimeout(timeout);
    return resp.status === 200;
  } catch (e) {
    return false;
  }
}

/**
 * Handle Worker Landing Page & Health Status
 */
async function handleLanding(request) {
  const url = new URL(request.url);
  const nodeStatuses = await Promise.all(
    CONFIG.NODES.map(async (n) => ({
      name: n.name,
      url: n.url,
      role: n.role,
      isHealthy: await checkNodeHealth(n.url)
    }))
  );

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ShieldDNS Cluster Dispatcher</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0b0f19; color: #f3f4f6; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: rgba(255, 255, 255, 0.04); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 32px; max-width: 520px; width: 100%; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
    h1 { font-size: 1.5rem; margin-top: 0; display: flex; align-items: center; gap: 10px; color: #60a5fa; }
    .node { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: rgba(0,0,0,0.25); border-radius: 8px; margin-bottom: 10px; border: 1px solid rgba(255,255,255,0.06); }
    .badge { padding: 4px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: bold; }
    .badge.online { background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid #22c55e; }
    .badge.offline { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .btn { display: inline-block; padding: 8px 14px; background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; font-size: 0.85rem; font-weight: 500; margin-right: 8px; margin-top: 15px; }
    .btn.subtle { background: rgba(255,255,255,0.1); color: #e5e7eb; }
    code { background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px; font-size: 0.85rem; color: #93c5fd; }
  </style>
</head>
<body>
  <div class="card">
    <h1>🛡️ ShieldDNS Dispatcher</h1>
    <p style="color:#9ca3af; font-size:0.9rem;">Cloudflare Worker High-Availability Gateway</p>
    <div style="margin: 20px 0;">
      ${nodeStatuses.map(n => `
      <div class="node">
        <div><strong>${n.name}</strong> (${n.role})<br><small style="color:#9ca3af;">${n.url}</small></div>
        <span class="badge ${n.isHealthy ? 'online' : 'offline'}">${n.isHealthy ? 'ONLINE' : 'DOWN'}</span>
      </div>`).join("")}
    </div>
    <div style="font-size:0.85rem; color:#9ca3af; line-height: 1.6;">
      DoH Endpoint: <code>https://${url.hostname}/dns-query</code>
    </div>
    <div style="margin-top: 20px;">
      <a href="/master" class="btn">Primary Dashboard &rarr;</a>
      <a href="/slave" class="btn subtle">Replica Dashboard &rarr;</a>
    </div>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
```

### Option B: Using the Cloudflare Web Dashboard
1. Log in to your Cloudflare Dashboard &rarr; **Workers & Pages**.
2. Click **Create application** &rarr; **Create Worker**.
3. Name it (e.g. `shielddns-dispatcher`) and click **Deploy**.
4. Click **Quick Edit**, paste the code above, update `CONFIG.PRIMARY_URL` and `CONFIG.SECONDARY_URL`, and click **Save and Deploy**.
5. Under **Settings** &rarr; **Domains & Routes**, add a custom domain: `worker.yourdomain.com`.

---

## 📱 Step 3: Client Device Configuration

Configure your devices to use the Cloudflare Worker domain:

- **Browser (Chrome / Edge / Firefox / Brave)**:
  - Settings &rarr; Privacy & Security &rarr; Security &rarr; Use Secure DNS.
  - Custom provider URL: `https://worker.yourdomain.com/dns-query`
- **Android**:
  - For DoH support, use apps like *PersonalDNSFilter*, *Intra*, or browser DoH settings pointing to `https://worker.yourdomain.com/dns-query`.
- **iOS / macOS**:
  - Download the `.mobileconfig` profile from the ShieldDNS landing page. When `ClusterWorkerDomain` is configured, it automatically populates `worker.yourdomain.com`.

---

## 🛡️ Administrative Shortcuts

The Worker provides clean shortcuts for quick management:

| Path | Destination | Description |
|---|---|---|
| `https://worker.yourdomain.com/master` | `https://dns1.yourdomain.com/admin/` | Direct redirect to Primary Admin UI |
| `https://worker.yourdomain.com/primary` | `https://dns1.yourdomain.com/admin/` | Alias for Primary Admin UI |
| `https://worker.yourdomain.com/slave` | `https://dns2.yourdomain.com/admin/` | Direct redirect to Secondary/Replica Admin UI |
| `https://worker.yourdomain.com/replica` | `https://dns2.yourdomain.com/admin/` | Alias for Secondary/Replica Admin UI |
| `https://worker.yourdomain.com/dns-query` | Dynamic failover proxy | DNS-over-HTTPS (DoH) resolution endpoint |
