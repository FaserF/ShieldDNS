/**
 * UI Renderers Module
 */
import { state, uiRefs, getEl } from '../core/state.js';
import * as helpers from './helpers.js';
import * as charts from './charts.js';
import * as ui from './ui.js';
import { VirtualScroller } from './scroller.js';

export function renderDashStats(data) {
    const c = uiRefs.statsContainer;
    if (!c.total) return;
    c.total.textContent = data.total_queries.toLocaleString();
    c.blocked.textContent = data.blocked_queries.toLocaleString();
    c.ratio.textContent = `${(data.total_queries > 0 ? (data.blocked_queries/data.total_queries*100) : 0).toFixed(1)} %`;
    c.cache.textContent = `${(data.total_queries > 0 ? (data.cache_hits/data.total_queries*100) : 0).toFixed(1)} %`;
    c.latency.textContent = `${(data.average_latency || 0).toFixed(2)} ms`;
    c.clients.textContent = data.unique_clients || 0;
    
    const appVer = getEl('app-version');
    if (appVer) appVer.textContent = data.version;
    const aboutAppVer = getEl('about-shielddns-ver');
    if (aboutAppVer) aboutAppVer.textContent = data.version;
}

export function renderQueries(queries) {
    // Top-level Dashboard Feed (last 20)
    if (uiRefs.queryLogItems) {
        uiRefs.queryLogItems.innerHTML = '';
        queries.slice(0, 20).forEach(q => uiRefs.queryLogItems.appendChild(createQueryRow(q)));
    }

    // Full Query Log View (Virtual Scroller)
    if (uiRefs.fullQueryLogItems) {
        if (!state.fullQueryScroller) {
            state.fullQueryScroller = new VirtualScroller('full-query-log-items', 48, createQueryRow);
        }
        state.cachedQueries = queries;
        state.fullQueryScroller.setData(queries);
    }
}

export function createQueryRow(q) {
    const row = document.createElement('tr');
    const time = new Date(q.time).toLocaleTimeString();
    const actionBtn = q.status === 'Blocked' ?
        `<button class="btn btn-sm secondary" onclick="addCustomRule('allowed', '${q.domain}')" title="Whitelist Domain">Allow</button>` :
        `<button class="btn btn-sm secondary" onclick="addCustomRule('blocked', '${q.domain}')" title="Blacklist Domain">Block</button>`;

    const statusClass = q.status === 'Blocked' ? 'danger' : 'official';
    const displayIp = q.client_alias ? `${q.client_alias} (${q.client_ip})` : q.client_ip;

    row.innerHTML = `
        <td>${time}</td>
        <td><span class="domain-link" onclick="showDomainDetails('${q.domain}')">${q.domain}</span></td>
        <td><span class="ip-link" onclick="showIPDetails('${q.client_ip}')">${displayIp}</span></td>
        <td class="hide-mobile">${q.type || 'A'}</td>
        <td><span class="badge ${statusClass}">${q.status}</span></td>
        <td class="hide-mobile">${actionBtn}</td>
    `;
    return row;
}

export function renderConfig(cfg) {
    const domain = cfg.admin_domain || window.location.hostname;

    // Connection Guide
    const dotHost = getEl('guide-dot-host');
    const dotUrl = getEl('guide-dot-url');
    const dohUrl = getEl('guide-doh-url');
    const doqUrl = getEl('guide-doq-url');
    if (dotHost) dotHost.value = domain;
    if (dotUrl) dotUrl.value = `tls://${domain}`;
    if (dohUrl) dohUrl.value = `https://${domain}/dns-query`;
    if (doqUrl) doqUrl.value = `quic://${domain}`;

    // Last Login
    const lastLoginEl = getEl('dashboard-last-login');
    if (lastLoginEl && cfg.previous_login) {
        const prev = new Date(cfg.previous_login);
        if (prev.getTime() > 0) {
            lastLoginEl.textContent = `Last login: ${prev.toLocaleString()}`;
        }
    }

    // Populate Settings form if visible
    const upstreamsInput = getEl('upstreams-input');
    if (upstreamsInput) upstreamsInput.value = (cfg.upstreams || []).join(', ');
    const dotInput = getEl('dot-upstreams-input');
    if (dotInput) dotInput.value = (cfg.upstream_dot || []).join(', ');
    const adminDomainInput = getEl('admin-domain-input');
    if (adminDomainInput) adminDomainInput.value = cfg.admin_domain || '';
    const blockIpInput = getEl('block-ip-input');
    if (blockIpInput) blockIpInput.value = cfg.block_page_ip || '';
    
    if (getEl('prefer-encrypted-check')) getEl('prefer-encrypted-check').checked = !!cfg.prefer_encrypted;
    if (getEl('debug-mode-check')) getEl('debug-mode-check').checked = !!cfg.debug_mode;
    if (getEl('sign-mobileconfig-check')) getEl('sign-mobileconfig-check').checked = !!cfg.sign_mobileconfig;
    if (getEl('abuse-detection-check')) getEl('abuse-detection-check').checked = !!cfg.abuse_detection_enabled;
    if (getEl('dnssec-check')) getEl('dnssec-check').checked = !!cfg.dnssec_enabled;
    if (getEl('serve-stale-check')) getEl('serve-stale-check').checked = !!cfg.serve_stale;
    if (getEl('smart-upstream-check')) getEl('smart-upstream-check').checked = !!cfg.smart_upstream_enabled;
    if (getEl('smart-selection-policy-input')) getEl('smart-selection-policy-input').value = cfg.smart_selection_policy || 'fastest';
    if (getEl('latency-interval-input')) getEl('latency-interval-input').value = cfg.latency_check_interval || 10;
    if (getEl('diagnostics-interval-input')) getEl('diagnostics-interval-input').value = cfg.diagnostics_interval || 600;
    if (getEl('retention-input')) getEl('retention-input').value = cfg.retention_days || 30;

    // Custom Rules
    const renderCustomList = (id, items) => {
        const el = getEl(id);
        if (!el) return;
        el.innerHTML = items?.map(domain => `
            <div class="preset-selection-item">
                <span>${domain}</span>
                <button class="btn danger-text" onclick="removeCustomRule('${domain}', event)"><i class="fas fa-trash"></i></button>
            </div>
        `).join('') || '';
    };

    renderCustomList('custom-blocked-list', cfg.custom_blocked);
    renderCustomList('custom-allowed-list', cfg.custom_allowed);

    const mappingsList = getEl('custom-mappings-list');
    if (mappingsList) {
        mappingsList.innerHTML = Object.entries(cfg.custom_mappings || {}).map(([domain, ip]) => `
            <div class="preset-selection-item">
                <span style="flex:1">${domain}</span>
                <span class="badge secondary" style="font-family:monospace; margin-right: 15px;">${ip}</span>
                <button class="btn danger-text" onclick="removeCustomMapping('${domain}', event)"><i class="fas fa-trash"></i></button>
            </div>
        `).join('');
    }

    // Lists
    const activeBlocks = getEl('active-blocklists-list');
    if (activeBlocks) {
        activeBlocks.innerHTML = (cfg.lists || []).map((list, i) => `
            <div class="list-item" onclick="window.openListDetailsModal(${i}, 'block')">
                <div class="list-info"><h3>${list.name}</h3><p>${list.url}</p></div>
                <div class="list-actions">
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'block', event)">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm danger" onclick="event.stopPropagation(); window.removeList(${i}, 'block', event)"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('') || '<p class="help">No active blocklists.</p>';
    }

    const activeAllows = getEl('active-allowlists-list');
    if (activeAllows) {
        activeAllows.innerHTML = (cfg.allowlists || []).map((list, i) => `
            <div class="list-item" onclick="window.openListDetailsModal(${i}, 'allow')">
                <div class="list-info"><h3>${list.name}</h3><p>${list.url}</p></div>
                <div class="list-actions">
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'allow', event)">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm danger" onclick="event.stopPropagation(); window.removeList(${i}, 'allow', event)"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('') || '<p class="help">No active allowlists.</p>';
    }

    const tags = getEl('blocked-countries-tags');
    if (tags) {
        tags.innerHTML = (cfg.blocked_countries || []).map(code => `
            <div class="tag">
                <img src="https://flagcdn.com/w20/${code.toLowerCase()}.png">
                <span>${state.allCountries[code] || code}</span>
                <span class="remove-tag" onclick="removeCountry('${code}', event)">&times;</span>
            </div>
        `).join('');
    }

    // Blocked Clients in Settings
    const blockedClientsList = getEl('settings-blocked-clients-list');
    if (blockedClientsList) {
        blockedClientsList.innerHTML = (cfg.blocked_clients || []).map(ip => `
            <div class="tag danger">
                <span>${ip}</span>
                <span class="remove-tag" onclick="unblockClient('${ip}')">&times;</span>
            </div>
        `).join('') || '<p class="help">No clients are currently blocked.</p>';
    }
}

export function renderAnalytics(blocked, clients) {
    const topBlockedList = getEl('top-blocked-list');
    if (topBlockedList) {
        topBlockedList.innerHTML = (blocked || []).map(b => `
            <tr>
                <td><span class="domain-link" onclick="showDomainDetails('${b.domain}')">${b.domain}</span></td>
                <td class="text-right">${b.count || 0}</td>
            </tr>
        `).join('') || '<tr><td colspan="2">No data available</td></tr>';
    }
    
    const topClientsList = getEl('top-clients-list');
    if (topClientsList) {
        topClientsList.innerHTML = (clients || []).map(c => {
            const display = c.client_alias ? `${c.client_alias} (${c.client_ip})` : c.client_ip;
            return `<tr>
                <td><span class="ip-link" onclick="showIPDetails('${c.client_ip}')">${display}</span></td>
                <td class="text-right">${c.count || 0}</td>
            </tr>`;
        }).join('') || '<tr><td colspan="2">No data available</td></tr>';
    }
}

export function renderDiagnostics(d) {
    if (getEl('diag-cpu-load')) getEl('diag-cpu-load').textContent = d.cpu_load ? d.cpu_load.map(n => n.toFixed(2)).join(', ') : '0.00, 0.00, 0.00';
    if (getEl('diag-cpu-model')) getEl('diag-cpu-model').textContent = d.cpu_model || 'Unknown CPU';
    
    if (d.ram) {
        const used = (d.ram.used / 1024).toFixed(0);
        const total = (d.ram.total / 1024).toFixed(0);
        const pct = (d.ram.used / d.ram.total * 100).toFixed(1);
        if (getEl('diag-ram-usage')) getEl('diag-ram-usage').textContent = `${used} / ${total} MB (${pct}%)`;
        const bar = getEl('diag-ram-bar');
        if (bar) bar.style.width = pct + '%';
    }
    
    if (d.disk) {
        const used = (d.disk.used / 1024 / 1024 / 1024).toFixed(1);
        const total = (d.disk.total / 1024 / 1024 / 1024).toFixed(1);
        const pct = (d.disk.used / d.disk.total * 100).toFixed(1);
        if (getEl('diag-disk-usage')) getEl('diag-disk-usage').textContent = `${used} / ${total} GB (${pct}%)`;
        const bar = getEl('diag-disk-bar');
        if (bar) bar.style.width = pct + '%';
    }

    if (getEl('diag-uptime')) {
        const up = d.uptime_seconds || 0;
        const h = Math.floor(up / 3600);
        const m = Math.floor((up % 3600) / 60);
        const s = up % 60;
        getEl('diag-uptime').textContent = `${h.toString().padStart(2,'0')}:${m.toString().padStart(2,'0')}:${s.toString().padStart(2,'0')}`;
    }

    const certInfo = getEl('cert-info-content');
    if (certInfo) {
        if (!d.certificate || !d.certificate.valid) {
             certInfo.innerHTML = '<p class="help">No valid SSL certificate information available.</p>';
        } else {
             const cert = d.certificate;
             const daysLeft = Math.floor((new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24));
             certInfo.innerHTML = `
                 <div class="diag-item"><span>Status</span><span class="badge ${cert.valid ? 'official' : 'danger'}">${cert.valid ? 'Valid' : 'Expired'}</span></div>
                 <div class="diag-item"><span>Subject</span><span title="${cert.subject || ''}">${cert.subject || '-'}</span></div>
                 <div class="diag-item"><span>Issuer</span><span title="${cert.issuer || ''}">${cert.issuer || '-'}</span></div>
                 <div class="diag-item"><span>Expires</span><span>${new Date(cert.not_after).toLocaleString()} (${daysLeft} days left)</span></div>
                 <div class="diag-item"><span>SANs</span><span style="white-space: normal; word-break: break-all;">${(cert.dns_names || []).join(', ') || '-'}</span></div>
             `;
        }
    }
    
    const latencyList = getEl('upstream-latency-list');
    const selectionMethodEl = getEl('upstream-selection-method');
    
    if (selectionMethodEl && d.upstream_health) {
        const method = state.currentConfig?.smart_upstream_enabled ? 
            `Smart Selection (${state.currentConfig.smart_selection_policy})` : 'Static Priority';
        selectionMethodEl.textContent = `— ${method}`;
    }

    if (latencyList && d.upstream_health) {
         latencyList.innerHTML = d.upstream_health.map(h => {
             const isUp = h.status === 'up';
             const isPreferred = h.preferred || false;
             return `<tr class="${isPreferred ? 'preferred-row' : ''}">
                 <td>
                    <div style="display:flex; align-items:center; gap:8px;">
                        ${h.server}
                        ${isPreferred ? '<span class="badge" style="background:var(--accent); font-size:0.6rem; padding:2px 6px;">Active</span>' : ''}
                    </div>
                 </td>
                 <td><span class="badge ${isUp ? 'official' : 'danger'}">${isUp ? 'Healthy' : 'Down'}</span></td>
                 <td style="text-align:right; font-weight:${isPreferred ? '600' : '400'}">${isUp ? h.latency_ms.toFixed(1) + ' ms' : '-'}</td>
             </tr>`;
         }).join('') || '<tr><td colspan="3" class="help">No upstreams configured.</td></tr>';
    }
}

export function renderAPIKeys(keys) {
    const list = getEl('api-keys-list');
    if (!list) return;
    
    list.innerHTML = (keys || []).map(key => `
        <tr>
            <td>${key.name}</td>
            <td>${(key.permissions || []).map(p => `<span class="badge secondary" style="font-size:0.7rem; margin-right:4px;">${p}</span>`).join('') || '-'}</td>
            <td class="help" style="font-size:0.75rem;">${new Date(key.created_at).toLocaleDateString()}</td>
            <td class="help" style="font-size:0.75rem;">${key.last_used_at ? new Date(key.last_used_at).toLocaleDateString() : 'Never'}</td>
            <td>
                <button class="btn btn-sm danger" onclick="window.deleteAPIKey('${key.id}', event)"><i class="fas fa-trash"></i></button>
            </td>
        </tr>
    `).join('') || '<tr><td colspan="5" class="help">No API keys generated.</td></tr>';
}


export function renderIPDetails(ip, stats, topDomains, topBlocked) {
    getEl('ip-info-title').textContent = stats.alias || ip;
    getEl('ip-info-subtitle').textContent = stats.alias ? ip : '';
    getEl('ip-info-total').textContent = stats.total_queries?.toLocaleString() || '0';
    getEl('ip-info-blocked').textContent = stats.blocked_queries?.toLocaleString() || '0';
    
    const pct = stats.total_queries > 0 ? (stats.blocked_queries / stats.total_queries * 100) : 0;
    getEl('ip-info-blocked-bar').style.width = pct + '%';
    
    getEl('ip-info-hostname').textContent = stats.hostname || '-';
    getEl('ip-info-manufacturer').textContent = stats.manufacturer || '-';
    
    getEl('ip-info-top-domains').innerHTML = (topDomains || []).map(d => `
        <tr>
            <td style="word-break: break-all;">${d.domain}</td>
            <td style="text-align:right">${d.count}</td>
        </tr>
    `).join('') || '<tr><td colspan="2">No data</td></tr>';
    
    getEl('ip-info-top-blocked').innerHTML = (topBlocked || []).map(d => `
        <tr>
            <td style="word-break: break-all;">${d.domain}</td>
            <td style="text-align:right">${d.count}</td>
        </tr>
    `).join('') || '<tr><td colspan="2">No data</td></tr>';

    // Show/Hide block buttons
    const isBlocked = (state.currentConfig.blocked_clients || []).includes(ip);
    getEl('ip-block-btn').style.display = isBlocked ? 'none' : 'block';
    getEl('ip-unblock-btn').style.display = isBlocked ? 'block' : 'none';
    
    getEl('ip-info-modal').classList.remove('hidden');
}

export function renderDomainDetails(domain, stats, clients, blockInfo) {
    getEl('domain-info-title').textContent = domain;
    getEl('domain-info-total').textContent = stats.total_queries?.toLocaleString() || '0';
    getEl('domain-info-category').textContent = stats.category || 'General';
    
    const blockRate = stats.total_queries > 0 ? (stats.blocked_queries / stats.total_queries * 100) : 0;
    getEl('domain-info-block-rate').textContent = blockRate.toFixed(1) + '%';
    
    // Status Badge and Block Info
    const badge = getEl('domain-status-badge');
    const isCustomBlocked = (state.currentConfig.custom_blocked || []).includes(domain);
    const isListBlocked = blockInfo.lists && blockInfo.lists.length > 0;
    
    if (isCustomBlocked) {
        badge.textContent = 'Blocked (Custom)';
        badge.className = 'badge danger';
    } else if (isListBlocked) {
        badge.textContent = `Blocked by ${blockInfo.lists.length} list(s)`;
        badge.className = 'badge danger';
        getEl('domain-info-subtitle').textContent = blockInfo.lists.join(', ');
    } else {
        badge.textContent = 'Allowed';
        badge.className = 'badge success';
        getEl('domain-info-subtitle').textContent = domain;
    }

    getEl('domain-info-clients').innerHTML = (clients || []).map(c => `
        <tr>
            <td><a href="#" onclick="showIPDetails('${c.ip}'); return false;" style="color: var(--accent);">${c.ip}</a></td>
            <td>${c.alias || '-'}</td>
            <td style="text-align:right">${c.count}</td>
        </tr>
    `).join('') || '<tr><td colspan="3">No data</td></tr>';

    getEl('domain-block-btn').style.display = isCustomBlocked ? 'none' : 'block';
    getEl('domain-allow-btn').style.display = isCustomBlocked ? 'block' : 'none';

    getEl('domain-info-modal').classList.remove('hidden');
}




