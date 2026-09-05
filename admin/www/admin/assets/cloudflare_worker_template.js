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
    nodeList.map(async (node) => {
      const res = await checkNodeHealth(node.url);
      return {
        ...node,
        isHealthy: res.isHealthy
      };
    })
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
 * Perform rapid non-blocking health check with latency measurement
 */
async function checkNodeHealth(baseUrl) {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.HEALTH_TIMEOUT_MS);
    
    const resp = await fetch(`${baseUrl}${CONFIG.HEALTH_CHECK_PATH}`, {
      method: "GET",
      signal: controller.signal,
      cf: { cacheTtl: 5, cacheEverything: true }
    });
    clearTimeout(timeout);
    return {
      isHealthy: resp.status === 200,
      latencyMs: resp.status === 200 ? Date.now() - start : null,
    };
  } catch (e) {
    return { isHealthy: false, latencyMs: null };
  }
}

/**
 * Handle Worker Landing Page & Privacy-Safe Status in ShieldDNS Design
 */
async function handleLanding(request) {
  const url = new URL(request.url);
  const clientCountry = (request.cf && request.cf.country) ? request.cf.country.toUpperCase() : "GLOBAL";
  const clientColo = (request.cf && request.cf.colo) ? request.cf.colo : "EDGE";
  const httpProtocol = request.cf && request.cf.httpProtocol ? request.cf.httpProtocol : "HTTP/2";

  const nodeList = Array.isArray(CONFIG.NODES) && CONFIG.NODES.length > 0 ? CONFIG.NODES : [];
  const nodeStatuses = await Promise.all(
    nodeList.map(async (n) => {
      const health = await checkNodeHealth(n.url);
      return {
        id: n.id,
        name: n.name,
        role: n.role,
        isHealthy: health.isHealthy,
        latencyMs: health.latencyMs,
      };
    })
  );

  const healthyCount = nodeStatuses.filter(n => n.isHealthy).length;
  const allHealthy = healthyCount === nodeStatuses.length && nodeStatuses.length > 0;
  const anyHealthy = healthyCount > 0;

  const statusBadgeColor = allHealthy ? "#10b981" : (anyHealthy ? "#f59e0b" : "#ef4444");
  const statusBadgeBg = allHealthy ? "rgba(16, 185, 129, 0.12)" : (anyHealthy ? "rgba(245, 158, 11, 0.12)" : "rgba(239, 68, 68, 0.12)");
  const statusBorder = allHealthy ? "rgba(16, 185, 129, 0.3)" : (anyHealthy ? "rgba(245, 158, 11, 0.3)" : "rgba(239, 68, 68, 0.3)");
  const statusText = allHealthy ? "All Systems Operational" : (anyHealthy ? "Partial Degradation (Failover Active)" : "All Upstreams Offline");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ShieldDNS Edge Gateway</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: rgba(22, 27, 44, 0.85);
      --card-border: rgba(255, 255, 255, 0.08);
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent: #6366f1;
      --accent-hover: #4f46e5;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --code-bg: rgba(0, 0, 0, 0.4);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #171d33 0%, var(--bg) 75%);
      color: var(--text-primary);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }
    .wrapper {
      max-width: 580px;
      width: 100%;
      background: var(--card-bg);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      padding: 36px 32px;
      box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.7), inset 0 1px 1px 0 rgba(255, 255, 255, 0.08);
    }
    .header {
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
    }
    .logo-badge {
      width: 48px;
      height: 48px;
      border-radius: 14px;
      background: linear-gradient(135deg, #4f46e5 0%, #818cf8 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 8px 20px -4px rgba(99, 102, 241, 0.5);
      flex-shrink: 0;
    }
    .logo-badge svg {
      width: 26px;
      height: 26px;
      stroke: #fff;
    }
    h1 {
      font-size: 1.45rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
    }
    .subtitle {
      font-size: 0.85rem;
      color: var(--text-secondary);
      margin-top: 2px;
    }
    .overall-status {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      border-radius: 12px;
      background: ${statusBadgeBg};
      border: 1px solid ${statusBorder};
      margin-bottom: 24px;
    }
    .overall-label {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 600;
      font-size: 0.88rem;
      color: ${statusBadgeColor};
    }
    .pulse-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: ${statusBadgeColor};
      box-shadow: 0 0 10px ${statusBadgeColor};
      animation: pulse 2s infinite ease-in-out;
    }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.4; transform: scale(0.85); }
    }
    .section-title {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      font-weight: 700;
      margin-bottom: 12px;
    }
    .nodes-grid {
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-bottom: 24px;
    }
    .node-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
      background: rgba(0, 0, 0, 0.25);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      transition: border-color 0.2s;
    }
    .node-row:hover {
      border-color: rgba(255, 255, 255, 0.12);
    }
    .node-name {
      font-weight: 600;
      font-size: 0.92rem;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .node-role {
      font-size: 0.72rem;
      font-weight: 600;
      padding: 2px 7px;
      border-radius: 6px;
      text-transform: uppercase;
      background: rgba(99, 102, 241, 0.15);
      color: #a5b4fc;
      border: 1px solid rgba(99, 102, 241, 0.25);
    }
    .node-meta {
      font-size: 0.78rem;
      color: var(--text-muted);
      margin-top: 3px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.03em;
    }
    .badge.healthy {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .badge.down {
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .info-box {
      background: rgba(0, 0, 0, 0.3);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      font-size: 0.83rem;
      line-height: 1.6;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.03);
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: var(--text-secondary); }
    .info-value { color: var(--text-primary); font-family: ui-monospace, SFMono-Regular, monospace; font-size: 0.82rem; }
    .code-pill {
      background: var(--code-bg);
      padding: 3px 8px;
      border-radius: 6px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      color: #93c5fd;
      font-size: 0.8rem;
    }
    .actions {
      display: flex;
      gap: 10px;
      margin-top: 10px;
    }
    .btn {
      flex: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 11px 16px;
      border-radius: 10px;
      font-size: 0.86rem;
      font-weight: 600;
      text-decoration: none;
      transition: all 0.2s ease;
      cursor: pointer;
      text-align: center;
    }
    .btn-primary {
      background: var(--accent);
      color: #fff;
      box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
    }
    .btn-primary:hover {
      background: var(--accent-hover);
      transform: translateY(-1px);
    }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.06);
      color: var(--text-primary);
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .btn-secondary:hover {
      background: rgba(255, 255, 255, 0.1);
      transform: translateY(-1px);
    }
    .footer {
      margin-top: 24px;
      text-align: center;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .footer a {
      color: #818cf8;
      text-decoration: none;
    }
    .footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <div class="logo-badge">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div>
        <h1>ShieldDNS Dispatcher</h1>
        <div class="subtitle">Cloudflare Edge &bull; Anycast Failover Gateway</div>
      </div>
    </div>

    <div class="overall-status">
      <div class="overall-label">
        <span class="pulse-dot"></span>
        <span>${statusText}</span>
      </div>
      <span style="font-size: 0.78rem; color: var(--text-secondary); font-weight: 500;">
        ${healthyCount} / ${nodeStatuses.length} Upstream Nodes Active
      </span>
    </div>

    <div class="section-title">Upstream Cluster Nodes</div>
    <div class="nodes-grid">
      ${nodeStatuses.map(n => `
      <div class="node-row">
        <div>
          <div class="node-name">
            <span>${n.name}</span>
            <span class="node-role">${n.role}</span>
          </div>
          <div class="node-meta">
            ${n.isHealthy && n.latencyMs !== null ? `Health check latency: ${n.latencyMs}ms` : (n.isHealthy ? `Operational` : `Unreachable / Offline`)}
          </div>
        </div>
        <span class="badge ${n.isHealthy ? 'healthy' : 'down'}">
          ${n.isHealthy ? '● OPERATIONAL' : '✕ OFFLINE'}
        </span>
      </div>`).join("")}
    </div>

    <div class="section-title">Gateway Details</div>
    <div class="info-box">
      <div class="info-row">
        <span class="info-label">DoH Endpoint</span>
        <span class="info-value"><span class="code-pill">https://${url.hostname}/dns-query</span></span>
      </div>
      <div class="info-row">
        <span class="info-label">Protocols</span>
        <span class="info-value">DoH (HTTP/2) &bull; DoH3 (HTTP/3 QUIC)</span>
      </div>
      <div class="info-row">
        <span class="info-label">Edge Ingress</span>
        <span class="info-value">${clientCountry} (${clientColo}) &bull; ${httpProtocol}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Privacy &amp; Security</span>
        <span class="info-value" style="color: var(--success);">Zero-Log Edge &bull; DNSSEC Verified</span>
      </div>
    </div>

    <div class="actions">
      <a href="/master" class="btn btn-primary">Primary Node &rarr;</a>
      <a href="/slave" class="btn btn-secondary">Replica Node &rarr;</a>
    </div>

    <div class="footer">
      Powered by <a href="https://github.com/FaserF/ShieldDNS" target="_blank" rel="noopener noreferrer">ShieldDNS</a> &bull; Privacy-Focused High Availability
    </div>
  </div>
</body>
</html>`;

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

