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
    row.style.height = '48px';
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

    // Custom Rules
    const renderCustomList = (id, items) => {
        const el = getEl(id);
        if (!el) return;
        el.innerHTML = items?.map(domain => `
            <div class="preset-selection-item">
                <span>${domain}</span>
                <button class="btn danger-text" onclick="removeCustomRule('${domain}')"><i class="fas fa-trash"></i></button>
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
                <button class="btn danger-text" onclick="removeCustomMapping('${domain}')"><i class="fas fa-trash"></i></button>
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
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'block')">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm danger" onclick="event.stopPropagation(); window.removeList(${i}, 'block')"><i class="fas fa-trash"></i></button>
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
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'allow')">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm danger" onclick="event.stopPropagation(); window.removeList(${i}, 'allow')"><i class="fas fa-trash"></i></button>
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
                <span class="remove-tag" onclick="removeCountry('${code}')">&times;</span>
            </div>
        `).join('');
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
    if (latencyList && d.upstream_health) {
         latencyList.innerHTML = d.upstream_health.map(h => {
             const isUp = h.status === 'up';
             return `<tr>
                 <td>${h.server}</td>
                 <td><span class="badge ${isUp ? 'official' : 'danger'}">${isUp ? 'Healthy' : 'Down'}</span></td>
                 <td style="text-align:right">${isUp ? h.latency_ms.toFixed(1) + ' ms' : '-'}</td>
             </tr>`;
         }).join('') || '<tr><td colspan="3" class="help">No upstreams configured.</td></tr>';
    }
}
