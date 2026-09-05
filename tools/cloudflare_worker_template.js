/**
 * ShieldDNS High-Availability Dispatcher & Failover Worker
 * 
 * Features:
 * - Ultra-low latency DNS-over-HTTPS (DoH) proxying across distributed ShieldDNS nodes
 * - Universal dynamic geo-proximity steering (continent & country match scoring)
 * - Automatic active health checks with fast failover on HTTP 5xx or network drop
 * - Administrative shortcut redirects (/master, /slave, /primary, /replica)
 * - Worker proxy authentication header injection
 * 
 * Placeholders:
 * - __NODES_CONFIG_JSON__: Generated dynamically from cluster topology or preset manually
 * - __WORKER_SHARED_SECRET__: Shared auth token for X-ShieldDNS-Worker header
 */

const CONFIG = {
  HEALTH_CHECK_PATH: "/api/health/live",
  HEALTH_TIMEOUT_MS: 1500,
  WORKER_SHARED_SECRET: "__WORKER_SHARED_SECRET__",

  /**
   * NODES: Define any number of primary/replica/edge instances.
   * Each node specifies:
   *   - id: Unique identifier
   *   - name: Descriptive name
   *   - url: Base URL of the ShieldDNS instance (e.g. "https://dns1.yourdomain.com")
   *   - role: 'primary' | 'secondary' | 'edge'
   *   - preferredCountries: Array of ISO 3166-1 alpha-2 codes (e.g. ['DE', 'AT', 'CH'])
   *   - preferredContinents: Array of continent codes (e.g. ['EU', 'NA', 'AS'])
   */
  NODES: __NODES_CONFIG_JSON__
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.toLowerCase().replace(/\/+$/, "");

    // 1. Admin Shortcuts
    const primaryNode = (Array.isArray(CONFIG.NODES) && CONFIG.NODES.find(n => n.role === "primary")) || (CONFIG.NODES && CONFIG.NODES[0]) || { url: "https://dns1.yourdomain.com" };
    const secondaryNode = (Array.isArray(CONFIG.NODES) && CONFIG.NODES.find(n => n.role === "secondary" || n.role === "edge")) || (CONFIG.NODES && CONFIG.NODES[1]) || primaryNode;

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

    // 3. Root landing page and cluster status overview
    return handleLanding(request);
  },
};

/**
 * Handle DNS-over-HTTPS query with universal Geo-proximity steering & health failover
 */
async function handleDoHQuery(request) {
  const clientCountry = (request.cf && request.cf.country) ? request.cf.country.toUpperCase() : "";
  const clientContinent = (request.cf && request.cf.continent) ? request.cf.continent.toUpperCase() : "";

  const nodeList = Array.isArray(CONFIG.NODES) && CONFIG.NODES.length > 0
    ? CONFIG.NODES
    : [{ id: "primary", name: "Primary Node", url: "https://dns1.yourdomain.com", role: "primary" }];

  // 1. Check health of all nodes in parallel
  const healthChecks = await Promise.all(
    nodeList.map(async (node) => ({
      ...node,
      isHealthy: await checkNodeHealth(node.url)
    }))
  );

  let healthyNodes = healthChecks.filter(n => n.isHealthy);
  if (healthyNodes.length === 0) {
    // Emergency fallback to first configured node if health checks fail
    healthyNodes = [nodeList[0]];
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

  // Clone headers and add proxy metadata
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
  const nodeList = Array.isArray(CONFIG.NODES) && CONFIG.NODES.length > 0 ? CONFIG.NODES : [];
  const nodeStatuses = await Promise.all(
    nodeList.map(async (n) => ({
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
