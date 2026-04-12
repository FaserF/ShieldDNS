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
    const actionBtn = q.status.includes('Blocked') ?
        `<button class="btn btn-sm secondary" onclick="addCustomRule('allowed', '${helpers.escapeHTML(q.domain)}')" title="Whitelist Domain">Allow</button>` :
        `<button class="btn btn-sm secondary" onclick="addCustomRule('blocked', '${helpers.escapeHTML(q.domain)}')" title="Blacklist Domain">Block</button>`;

    let statusClass = 'official';
    if (q.status.includes('Blocked')) {
        statusClass = 'danger';
    } else if (q.status === 'Allowed') {
        statusClass = 'success';
    }
    const escapedAlias = q.client_alias ? helpers.escapeHTML(q.client_alias) : '';
    const displayIp = q.client_alias ? `${escapedAlias} (${helpers.escapeHTML(q.client_ip)})` : helpers.escapeHTML(q.client_ip);

    row.innerHTML = `
        <td>${time}</td>
        <td><span class="domain-link" onclick="showDomainDetails('${helpers.escapeHTML(q.domain)}')">${helpers.escapeHTML(q.domain)}</span></td>
        <td><span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(q.client_ip)}')">${displayIp}</span></td>
        <td class="hide-mobile">${helpers.escapeHTML(q.type) || 'A'}</td>
        <td><span class="badge ${statusClass}">${helpers.escapeHTML(q.status)}</span></td>
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

    // Protection Status Card (Dashboard)
    const statusTitle = getEl('status-title');
    const statusDesc = getEl('status-desc');
    const statusIcon = getEl('status-icon');
    const toggleBtn = getEl('toggle-protection-btn');

    if (statusTitle && statusDesc && statusIcon && toggleBtn) {
        if (cfg.filtering_enabled) {
            statusTitle.textContent = 'ShieldDNS is Active';
            statusDesc.textContent = 'Your requests are being filtered and secured.';
            statusIcon.className = 'status-icon-wrapper protected';
            toggleBtn.textContent = 'Disable Protection';
            toggleBtn.className = 'btn btn-primary';
        } else {
            statusTitle.textContent = 'Protection Disabled';
            statusDesc.textContent = 'Filtering is currently inactive. Your network is unprotected.';
            statusIcon.className = 'status-icon-wrapper disabled';
            toggleBtn.textContent = 'Enable Protection';
            toggleBtn.className = 'btn btn-success';
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
    if (getEl('smart-upstream-check')) getEl('smart-upstream-check').checked = !!cfg.use_fastest_upstream;
    if (getEl('smart-selection-policy-input')) getEl('smart-selection-policy-input').value = cfg.smart_selection_policy || 'fastest';
    if (getEl('latency-interval-input')) getEl('latency-interval-input').value = cfg.latency_test_interval || 10;
    if (getEl('diagnostics-interval-input')) getEl('diagnostics-interval-input').value = cfg.diagnostics_refresh_interval || 600;
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
        const method = state.currentConfig?.use_fastest_upstream ? 
            `Smart Selection (${state.currentConfig.smart_selection_policy})` : 'Static Priority';
        selectionMethodEl.textContent = `— ${method}`;
    }

    if (latencyList && d.upstream_health) {
         latencyList.innerHTML = d.upstream_health.map(h => {
             const isUp = h.status === 'up' || h.status === 'Healthy';
             const isPreferred = h.is_preferred || false;
             return `<tr class="${isPreferred ? 'preferred-row' : ''}">
                 <td>
                    <div style="display:flex; align-items:center; gap:8px;">
                        ${helpers.escapeHTML(h.server)}
                        ${isPreferred ? '<span class="badge" style="background:var(--accent); font-size:0.65rem; padding:3px 8px; color:white; border-radius:12px; display:inline-flex; align-items:center; gap:4px;"><i class="fas fa-bolt" style="font-size:0.6rem"></i> Currently Active</span>' : ''}
                    </div>
                 </td>
                 <td><span class="badge ${isUp ? 'official' : 'danger'}">${isUp ? 'Healthy' : 'Down'}</span></td>
                 <td style="text-align:right; font-weight:${isPreferred ? '600' : '400'}">${isUp ? h.latency_ms.toFixed(1) + ' ms' : '-'}</td>
             </tr>`;
         }).join('') || '<tr><td colspan="3" class="help">No upstreams configured.</td></tr>';
         
         // Add manual trigger button if it doesn't exist or update it
         if (!getEl('recheck-latency-btn')) {
            const header = latencyList.parentElement.parentElement.querySelector('.chart-header');
            if (header) {
                const btn = document.createElement('button');
                btn.id = 'recheck-latency-btn';
                btn.className = 'btn btn-sm secondary';
                btn.style.marginLeft = 'auto';
                btn.innerHTML = '<i class="fas fa-sync-alt"></i> Retest Now';
                btn.onclick = (e) => {
                    e.preventDefault();
                    window.recheckUpstreams(btn);
                };
                header.appendChild(btn);
            }
         }
    }
}

export function renderAPIKeys(keys) {
    const list = getEl('api-keys-list') || getEl('api-keys-list-container');
    if (!list) return;
    
    list.innerHTML = (keys || []).map(k => {
        const createdDate = (!k.created_at || k.created_at.startsWith('0001')) ? 'Unknown' : new Date(k.created_at).toLocaleDateString();
        const lastUsed = (!k.last_used || k.last_used.startsWith('0001')) ? 'Never' : new Date(k.last_used).toLocaleString();
        
        return `
            <tr>
                <td>${helpers.escapeHTML(k.name)}</td>
                <td>${(k.permissions || []).map(p => `<span class="badge secondary" style="font-size:0.7rem; margin-right:4px;">${helpers.escapeHTML(p)}</span>`).join('') || '-'}</td>
                <td class="help" style="font-size:0.75rem;">${lastUsed}</td>
                <td>
                    <div style="display:flex; gap:8px;">
                        <button class="btn btn-sm secondary" onclick="window.editAPIKey('${k.id}')"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-sm danger" onclick="window.deleteAPIKey('${k.id}')"><i class="fas fa-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="4" class="help">No API keys generated.</td></tr>';
}


export function renderIPDetails(ip, stats, topDomains, topBlocked, history) {
    const setTxt = (id, txt) => { const el = getEl(id); if (el) el.textContent = txt; };
    
    setTxt('ip-info-title', stats.alias || ip);
    setTxt('ip-info-subtitle', stats.alias ? ip : '');
    setTxt('ip-info-total', stats.total?.toLocaleString() || '0');
    setTxt('ip-info-blocked', stats.blocked?.toLocaleString() || '0');
    
    const pct = stats.total > 0 ? (stats.blocked / stats.total * 100) : 0;
    const bar = getEl('ip-info-blocked-bar');
    if (bar) bar.style.width = pct + '%';
    
    setTxt('ip-info-hostname', stats.hostname || '-');
    setTxt('ip-info-isp', stats.isp || '-');
    setTxt('ip-info-mac', stats.mac || '-');
    
    // Location Info
    setTxt('ip-info-country', stats.country || '-');
    setTxt('ip-info-city', stats.city || '-');
    const flagEl = getEl('ip-info-flag');
    if (flagEl) {
        if (stats.country_code) {
            flagEl.innerHTML = `<img src="https://flagcdn.com/w40/${stats.country_code.toLowerCase()}.png" style="height: 14px; border-radius: 2px;">`;
        } else {
            flagEl.innerHTML = '';
        }
    }
    
    getEl('ip-info-top-domains').innerHTML = (topDomains || []).map(d => `
        <tr>
            <td style="word-break: break-all;">${helpers.escapeHTML(d.domain)}</td>
            <td style="text-align:right">${d.count}</td>
        </tr>
    `).join('') || '<tr><td colspan="2">No data</td></tr>';
    
    getEl('ip-info-top-blocked').innerHTML = (topBlocked || []).map(d => `
        <tr>
            <td style="word-break: break-all;">${helpers.escapeHTML(d.domain)}</td>
            <td style="text-align:right">${d.count}</td>
        </tr>
    `).join('') || '<tr><td colspan="2">No data</td></tr>';

    getEl('ip-info-history').innerHTML = (history || []).map(q => `
        <tr>
            <td>${new Date(q.time).toLocaleTimeString()}</td>
            <td style="word-break: break-all;">${helpers.escapeHTML(q.domain)}</td>
            <td><span class="badge ${q.status.includes('Allowed') ? 'success' : 'danger'}">${helpers.escapeHTML(q.status)}</span></td>
        </tr>
    `).join('') || '<tr><td colspan="3">No recent activity</td></tr>';

    // Show/Hide block buttons
    const isBlocked = (state.currentConfig.blocked_clients || []).includes(ip);
    getEl('ip-block-btn').style.display = isBlocked ? 'none' : 'block';
    getEl('ip-unblock-btn').style.display = isBlocked ? 'block' : 'none';
    
    getEl('ip-info-modal').classList.remove('hidden');
}

export function renderDomainDetails(domain, stats, clients, blockInfo, history) {
    const setTxt = (id, txt) => { const el = getEl(id); if (el) el.textContent = txt; };

    setTxt('domain-info-title', domain);
    setTxt('domain-info-total', stats.total?.toLocaleString() || '0');
    setTxt('domain-info-blocked', stats.blocked?.toLocaleString() || '0');
    setTxt('domain-info-clients', stats.clients_count || '0');
    setTxt('domain-info-category', stats.category || 'General');
    
    const blockRate = stats.total > 0 ? (stats.blocked / stats.total * 100) : 0;
    const ratioEl = getEl('domain-info-ratio') || getEl('domain-info-block-rate');
    if (ratioEl) ratioEl.textContent = blockRate.toFixed(1) + '%';
    
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

    getEl('domain-info-clients-list').innerHTML = (clients || []).map(c => `
        <tr>
            <td><a href="#" onclick="window.showIPDetails('${helpers.escapeHTML(c.ip)}'); return false;" style="color: var(--accent);">${helpers.escapeHTML(c.ip)}</a></td>
            <td>${helpers.escapeHTML(c.alias) || '-'}</td>
            <td style="text-align:right">${c.count}</td>
        </tr>
    `).join('') || '<tr><td colspan="3">No data</td></tr>';

    getEl('domain-info-history').innerHTML = (history || []).map(q => `
        <tr>
            <td>${new Date(q.time).toLocaleTimeString()}</td>
            <td><a href="#" onclick="window.showIPDetails('${helpers.escapeHTML(q.client_ip)}'); return false;" style="color: var(--accent);">${helpers.escapeHTML(q.client_alias || q.client_ip)}</a></td>
            <td><span class="badge ${q.status.includes('Allowed') ? 'success' : 'danger'}">${helpers.escapeHTML(q.status)}</span></td>
        </tr>
    `).join('') || '<tr><td colspan="3">No recent activity</td></tr>';

    getEl('domain-block-btn').style.display = isCustomBlocked ? 'none' : 'block';
    getEl('domain-allow-btn').style.display = isCustomBlocked ? 'block' : 'none';

    getEl('domain-info-modal').classList.remove('hidden');
}

// Remove duplicate renderAPIKeys
