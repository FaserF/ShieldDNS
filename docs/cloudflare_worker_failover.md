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

const CONFIG = {
  PRIMARY_URL: "https://dns1.yourdomain.com",
  SECONDARY_URL: "https://dns2.yourdomain.com",
  HEALTH_CHECK_PATH: "/api/health/live",
  HEALTH_TIMEOUT_MS: 1500,
  WORKER_SHARED_SECRET: "shielddns-worker-secure-token", // Optional header verification
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase().replace(/\/+$/, "");

    // 1. Admin Shortcuts
    if (path === "/master" || path === "/primary") {
      return Response.redirect(`${CONFIG.PRIMARY_URL}/admin/`, 302);
    }
    if (path === "/slave" || path === "/replica") {
      return Response.redirect(`${CONFIG.SECONDARY_URL}/admin/`, 302);
    }
    if (path === "/admin" || path.startsWith("/admin/")) {
      // Forward Admin UI traffic to Primary by default
      const target = new URL(url.pathname + url.search, CONFIG.PRIMARY_URL);
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
 * Handle DNS-over-HTTPS request with active failover
 */
async function handleDoHQuery(request) {
  // Determine preferred target by trying Primary first
  const primaryUp = await checkNodeHealth(CONFIG.PRIMARY_URL);
  const targetBase = primaryUp ? CONFIG.PRIMARY_URL : CONFIG.SECONDARY_URL;

  const targetUrl = new URL(new URL(request.url).pathname + new URL(request.url).search, targetBase);

  // Clone headers and add proxy indicator
  const headers = new Headers(request.headers);
  headers.set("X-Forwarded-Host", new URL(request.url).hostname);
  headers.set("X-ShieldDNS-Worker", CONFIG.WORKER_SHARED_SECRET);

  try {
    const response = await fetch(new Request(targetUrl.toString(), {
      method: request.method,
      headers: headers,
      body: request.method === "POST" ? request.body : null,
      redirect: "follow",
    }));

    // If Primary returned 502/503/504, attempt emergency fallback to Secondary
    if (!response.ok && response.status >= 502 && targetBase === CONFIG.PRIMARY_URL) {
      const fallbackUrl = new URL(new URL(request.url).pathname + new URL(request.url).search, CONFIG.SECONDARY_URL);
      return fetch(new Request(fallbackUrl.toString(), {
        method: request.method,
        headers: headers,
        body: request.method === "POST" ? request.body : null,
      }));
    }

    return response;
  } catch (err) {
    // Immediate fallback to secondary node
    const fallbackUrl = new URL(new URL(request.url).pathname + new URL(request.url).search, CONFIG.SECONDARY_URL);
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
  const primaryOk = await checkNodeHealth(CONFIG.PRIMARY_URL);
  const secondaryOk = await checkNodeHealth(CONFIG.SECONDARY_URL);

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
      <div class="node">
        <div><strong>Primary (Master)</strong><br><small style="color:#9ca3af;">${CONFIG.PRIMARY_URL}</small></div>
        <span class="badge ${primaryOk ? 'online' : 'offline'}">${primaryOk ? 'ONLINE' : 'DOWN'}</span>
      </div>
      <div class="node">
        <div><strong>Secondary (Replica)</strong><br><small style="color:#9ca3af;">${CONFIG.SECONDARY_URL}</small></div>
        <span class="badge ${secondaryOk ? 'online' : 'offline'}">${secondaryOk ? 'ONLINE' : 'DOWN'}</span>
      </div>
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
