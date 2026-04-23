/**
 * UI Renderers Module
 */
import { state, uiRefs, getEl } from '../core/state.js';
import * as helpers from './helpers.js';
import * as charts from './charts.js';
import * as ui from './ui.js';
import { VirtualScroller } from './scroller.js';

const getFlagHTML = (code, size = 'w20') => {
    if (!code || code.toLowerCase() === 'geo' || code.toLowerCase() === 'unknown' || code.length !== 2) {
        return `<i class="fas fa-globe" style="color: var(--accent); opacity: 0.6;"></i>`;
    }
    const width = size === 'w40' ? '18px' : '15px';
    return `<img src="https://flagcdn.com/${size}/${code.toLowerCase()}.png" alt="${code}" style="height: ${width}; border-radius: 2px; vertical-align: middle;">`;
};

export function renderDashStats(data) {
    const c = uiRefs.statsContainer;
    if (!c.total) return;

    helpers.countTo(c.total, data.total_queries);
    helpers.countTo(c.blocked, data.blocked_queries);

    const ratio = data.total_queries > 0 ? (data.blocked_queries / data.total_queries * 100) : 0;
    helpers.countTo(c.ratio, ratio, 800, ' %');

    const cache = data.total_queries > 0 ? (data.cache_hits / data.total_queries * 100) : 0;
    helpers.countTo(c.cache, cache, 800, ' %');

    helpers.countTo(c.latency, data.average_latency || 0, 800, ' ms');
    helpers.countTo(c.clients, data.unique_clients || 0);

    if (c.qps) {
        c.qps.textContent = (data.active_qps || 0).toFixed(1);
    }

    helpers.countTo(c.blockedDomains, data.blocked_domains || 0);
    const badge = getEl('stat-blocked-domains-list-badge');
    if (badge) {
        badge.textContent = (data.blocked_domains || 0).toLocaleString() + ' domains';
    }

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

    // Mobile Config QR and Link
    const g = uiRefs.guide;
    if (g && g.mobileBtn && g.mobileQR) {
        const fullUrl = `https://${domain}/api/mobileconfig`;
        g.mobileBtn.href = fullUrl;
        g.mobileQR.src = `/api/qr?data=${encodeURIComponent(fullUrl)}`;
    }

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
    if (getEl('diagnostics-interval-input')) getEl('diagnostics-interval-input').value = cfg.diagnostics_refresh_interval || 30;
    if (getEl('retention-input')) getEl('retention-input').value = cfg.retention_days || 30;
    if (getEl('doh-rate-limit-input')) getEl('doh-rate-limit-input').value = cfg.doh_rate_limit || 30;
    if (getEl('abuse-dga-threshold-input')) getEl('abuse-dga-threshold-input').value = cfg.abuse_dga_threshold || 3.8;
    if (getEl('abuse-dga-min-len-input')) getEl('abuse-dga-min-len-input').value = cfg.abuse_dga_min_len || 8;

    if (getEl('malicious-check')) getEl('malicious-check').checked = cfg.malicious_ip_blocking_enabled;
    if (getEl('malicious-interval-input')) getEl('malicious-interval-input').value = cfg.malicious_ip_interval || 8;
    if (getEl('verify-upstream-tls-check')) getEl('verify-upstream-tls-check').checked = !!cfg.verify_upstream_tls;

    // Custom Rules
    const renderCustomList = (id, items) => {
        const el = getEl(id);
        if (!el) return;
        el.innerHTML = items?.map(domain => `
            <div class="preset-selection-item">
                <span>${helpers.escapeHTML(domain)}</span>
                <button class="btn btn-sm secondary" onclick="removeCustomRule('${helpers.escapeHTML(domain)}', event)" title="Remove Rule"><i class="fas fa-trash"></i></button>
            </div>
        `).join('') || '';
    };

    renderCustomList('custom-blocked-list', cfg.custom_blocked);
    renderCustomList('custom-allowed-list', cfg.custom_allowed);

    const mappingsList = getEl('custom-mappings-list');
    if (mappingsList) {
        mappingsList.innerHTML = Object.entries(cfg.custom_mappings || {}).map(([domain, ip]) => `
            <div class="preset-selection-item">
                <span style="flex:1">${helpers.escapeHTML(domain)}</span>
                <span class="badge secondary" style="font-family:monospace; margin-right: 15px;">${helpers.escapeHTML(ip)}</span>
                <button class="btn btn-sm secondary" onclick="removeCustomMapping('${helpers.escapeHTML(domain)}', event)" title="Remove Mapping"><i class="fas fa-trash"></i></button>
            </div>
        `).join('');
    }

    // Lists
    const activeBlocks = getEl('active-blocklists-list');
    if (activeBlocks) {
        activeBlocks.innerHTML = (cfg.lists || []).map((list, i) => `
            <div class="list-item" onclick="window.openListDetailsModal(${i}, 'block')">
                <div class="list-info"><h3>${helpers.escapeHTML(list.name)}</h3><p>${helpers.escapeHTML(list.url)}</p></div>
                <div class="list-actions">
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'block', event)">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm secondary danger" onclick="event.stopPropagation(); window.removeList(${i}, 'block', event)" title="Remove List"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('') || '<p class="help">No active blocklists.</p>';
    }

    const activeAllows = getEl('active-allowlists-list');
    if (activeAllows) {
        activeAllows.innerHTML = (cfg.allowlists || []).map((list, i) => `
            <div class="list-item" onclick="window.openListDetailsModal(${i}, 'allow')">
                <div class="list-info"><h3>${helpers.escapeHTML(list.name)}</h3><p>${helpers.escapeHTML(list.url)}</p></div>
                <div class="list-actions">
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'allow', event)">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm secondary danger" onclick="event.stopPropagation(); window.removeList(${i}, 'allow', event)" title="Remove List"><i class="fas fa-trash"></i></button>
                </div>
            </div>
        `).join('') || '<p class="help">No active allowlists.</p>';
    }

    const tags = getEl('blocked-countries-tags');
    if (tags) {
        tags.innerHTML = (cfg.blocked_countries || []).map(code => `
            <div class="tag">
                ${getFlagHTML(code)}
                <span>${helpers.escapeHTML(state.allCountries[code] || code)}</span>
                <span class="remove-tag" onclick="removeCountry('${helpers.escapeHTML(code)}', event)">&times;</span>
            </div>
        `).join('');
    }

    // Blocked Clients in Settings (Compact Summary)
    const blockedBadge = getEl('blocked-clients-count-badge');
    if (blockedBadge) {
        const count = cfg.blocked_clients?.length || 0;
        blockedBadge.textContent = `${count} Client${count !== 1 ? 's' : ''} Blocked`;
        blockedBadge.style.display = count > 0 ? 'inline-block' : 'none';
    }
}

export function renderBlockedClientsModal(blockedClients, infoMap) {
    const list = getEl('blocked-clients-table-body');
    const filter = getEl('blocked-clients-country-filter');
    const search = getEl('blocked-clients-search')?.value.toLowerCase() || '';
    const countryFilter = filter?.value || 'ALL';

    if (!list) return;

    // Collect all countries for the filter dropdown
    const countriesInList = new Set();
    const rows = (blockedClients || []).map(ip => {
        const info = infoMap[ip] || {};
        const countryCode = info.country_code || '';
        if (countryCode && countryCode !== 'geo') countriesInList.add(countryCode);

        // Apply filters
        if (countryFilter !== 'ALL' && countryCode !== countryFilter) return null;
        if (search && !ip.includes(search) && !info.reason?.toLowerCase().includes(search)) return null;

        const dateStr = info.blocked_at ? new Date(info.blocked_at).toLocaleString() : 'Unknown';
        const countryName = (state.allCountries || {})[countryCode] || countryCode || (ip.includes(':') || !ip.match(/^\d+\./) ? 'Local/Internal' : 'Unknown');
        const reason = info.reason || 'Manual block';
        const type = info.auto ? '<i class="fas fa-robot" title="Auto-Blocked"></i> ' : '<i class="fas fa-user-shield" title="Manually Blocked"></i> ';

        return `
            <tr>
                <td><span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(ip)}')">${helpers.escapeHTML(ip)}</span></td>
                <td class="help" style="font-size: 0.75rem;">${dateStr}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        ${getFlagHTML(countryCode)}
                        <span>${helpers.escapeHTML(countryName)}</span>
                    </div>
                </td>
                <td style="font-size: 0.85rem;">${type}${helpers.escapeHTML(reason)}</td>
                <td>
                    <button class="btn btn-sm secondary danger" onclick="unblockClient('${helpers.escapeHTML(ip)}')" title="Unblock Client">
                        <i class="fas fa-unlock"></i>
                    </button>
                </td>
            </tr>
        `;
    }).filter(Boolean);

    list.innerHTML = rows.join('') || '<tr><td colspan="5" class="help text-center">No matching blocked clients found.</td></tr>';

    // Update filter dropdown if it's the first render or if countries changed
    if (filter && filter.options.length <= 1) {
        const sortedCountries = Array.from(countriesInList).sort((a, b) => 
            ((state.allCountries || {})[a] || a).localeCompare((state.allCountries || {})[b] || b)
        );
        sortedCountries.forEach(code => {
            const opt = document.createElement('option');
            opt.value = code;
            opt.textContent = (state.allCountries || {})[code] || code;
            filter.appendChild(opt);
        });
    }
}

export function renderAnalytics(blocked, clients) {
    const topBlockedList = getEl('top-blocked-list');
    if (topBlockedList) {
        topBlockedList.innerHTML = (blocked || []).map(b => `
            <tr>
                <td><span class="domain-link" onclick="showDomainDetails('${helpers.escapeHTML(b.domain)}')">${helpers.escapeHTML(b.domain)}</span></td>
                <td class="text-right">${helpers.escapeHTML(b.count?.toString() || '0')}</td>
            </tr>
        `).join('') || '<tr><td colspan="2">No data available</td></tr>';
    }

    const topClientsList = getEl('top-clients-list');
    if (topClientsList) {
        topClientsList.innerHTML = (clients || []).map(c => {
            const display = c.client_alias ? `${helpers.escapeHTML(c.client_alias)} (${helpers.escapeHTML(c.client_ip)})` : helpers.escapeHTML(c.client_ip);
            return `<tr>
                <td><span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(c.client_ip)}')">${display}</span></td>
                <td class="text-right">${helpers.escapeHTML(c.count?.toString() || '0')}</td>
            </tr>`;
        }).join('') || '<tr><td colspan="2">No data available</td></tr>';
    }
}

export function renderDiagnostics(d) {
    if (getEl('diag-cpu-load')) {
        const load = d.cpu_load ? d.cpu_load.map(n => {
            const val = parseFloat(n);
            return isNaN(val) ? '0.00' : val.toFixed(2);
        }).join(', ') : '0.00, 0.00, 0.00';
        getEl('diag-cpu-load').textContent = load;
    }
    if (getEl('diag-cpu-model')) getEl('diag-cpu-model').textContent = d.cpu_model || 'Unknown CPU';

    if (d.ram && d.ram.total > 0) {
        const used = (d.ram.used / 1024).toFixed(0); // From KB to MB
        const total = (d.ram.total / 1024).toFixed(0);
        const pct = (d.ram.used / d.ram.total * 100).toFixed(1);
        if (getEl('diag-ram-usage')) getEl('diag-ram-usage').textContent = `${used} / ${total} MB (${pct}%)`;
        const bar = getEl('diag-ram-bar');
        if (bar) bar.style.width = pct + '%';
    }

    if (d.disk && d.disk.total > 0) {
        const used = (d.disk.used / 1024 / 1024 / 1024).toFixed(1); // From Bytes to GB
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
        getEl('diag-uptime').textContent = `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
    }

    const certInfo = getEl('cert-info-content');
    if (certInfo) {
        if (!d.certificate || !d.certificate.valid) {
            certInfo.innerHTML = '<p class="help">No valid SSL certificate information available.</p>';
        } else {
            const cert = d.certificate;
            const daysLeft = Math.floor((new Date(cert.not_after) - new Date()) / (1000 * 60 * 60 * 24));
            certInfo.innerHTML = `
                 <div class="diag-item"><span>Status</span><span class="badge ${cert.valid ? 'success' : 'danger'}">${cert.valid ? 'Valid' : 'Expired'}</span></div>
                 <div class="diag-item"><span>Subject</span><span title="${helpers.escapeHTML(cert.subject || '')}">${helpers.escapeHTML(cert.subject || '-')}</span></div>
                 <div class="diag-item"><span>Issuer</span><span title="${helpers.escapeHTML(cert.issuer || '')}">${helpers.escapeHTML(cert.issuer || '-')}</span></div>
                 <div class="diag-item"><span>Expires</span><span>${new Date(cert.not_after).toLocaleString()} (${daysLeft} days left)</span></div>
                 <div class="diag-item"><span>SANs</span><span style="white-space: normal; word-break: break-all;">${(cert.dns_names || []).map(n => helpers.escapeHTML(n)).join(', ') || '-'}</span></div>
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
                 <td><span class="badge ${isUp ? 'success' : 'danger'}">${isUp ? 'Healthy' : 'Down'}</span></td>
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
} export function renderAPIKeys(keys) {
    const list = getEl('api-keys-list') || getEl('api-keys-list-container');
    if (!list) return;

    list.innerHTML = (keys || []).map(k => {
        const createdDate = (!k.created_at || k.created_at.startsWith('0001')) ? 'Unknown' : new Date(k.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
        const lastUsed = (!k.last_used || k.last_used.startsWith('0001')) ? 'Never' : new Date(k.last_used).toLocaleString();

        return `
            <tr>
                <td>${helpers.escapeHTML(k.name)}</td>
                <td>${(k.permissions || []).map(p => `<span class="badge secondary" style="font-size:0.7rem; margin-right:4px;">${helpers.escapeHTML(p)}</span>`).join('') || '-'}</td>
                <td class="help" style="font-size:0.75rem;">${createdDate}</td>
                <td class="help" style="font-size:0.75rem;">${lastUsed}</td>
                <td>
                    <div style="display:flex; gap:8px;">
                        <button class="btn btn-sm secondary" onclick="window.editAPIKey('${k.id}')"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-sm secondary danger" onclick="window.deleteAPIKey('${k.id}')" title="Delete Key"><i class="fas fa-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="5" class="help">No API keys generated.</td></tr>';
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

    const sanitize = (val, fallback = 'N/A') => (!val || val === '-' || val === 'geo' || val === 'none') ? fallback : val;

    const fallbackSpan = (txt) => `<span class="info-empty">${txt}</span>`;
    const toggleEl = (id, show) => { const el = getEl(id); if (el) el.style.display = show ? '' : 'none'; };

    // Hostname visibility
    const hasHostname = stats.hostname && stats.hostname !== '-' && stats.hostname !== 'none' && !stats.hostname.toLowerCase().includes('no hostname');
    setTxt('ip-info-hostname', hasHostname ? stats.hostname : '');
    toggleEl('ip-info-hostname', hasHostname);

    // Device Info Processing
    const manufacturer = sanitize(stats.manufacturer, '');
    const os = sanitize(stats.os, '');
    const mac = sanitize(stats.mac, '');

    const deviceCard = getEl('ip-info-device-card');
    if (deviceCard) {
        // Hide entire card if all significant fields are generic/unavailable
        const isManufacturerUnknown = !manufacturer || manufacturer.toLowerCase().includes('unknown');
        const isOSUnknown = !os || os.toLowerCase().includes('unknown');
        const isMACUnavailable = !mac || mac.toLowerCase().includes('unavailable') || mac === '-';

        if (isManufacturerUnknown && isOSUnknown && isMACUnavailable) {
            deviceCard.style.display = 'none';
        } else {
            deviceCard.style.display = 'block';
            getEl('ip-info-manufacturer').innerHTML = isManufacturerUnknown ? '' : manufacturer;
            toggleEl('ip-info-manufacturer', !isManufacturerUnknown);

            getEl('ip-info-os').innerHTML = isOSUnknown ? '' : os;
            toggleEl('ip-info-os', !isOSUnknown);

            getEl('ip-info-mac').innerHTML = isMACUnavailable ? '' : mac;
            toggleEl('ip-info-mac', !isMACUnavailable);
            
            // Hide the dot separator if items are missing
            const dot = deviceCard.querySelector('span[style*="opacity: 0.5"]');
            if (dot) dot.style.display = (!os || isOSUnknown || !mac || isMACUnavailable) ? 'none' : '';
        }
    }

    // Provider & ASN
    const provider = stats.isp || stats.org;
    const hasProvider = !!provider;
    setTxt('ip-info-isp', provider || (stats.is_private ? 'Local Network' : 'Unknown Provider'));
    
    const hasAS = stats.as && stats.as !== '-' && stats.as !== 'none';
    setTxt('ip-info-as', hasAS ? stats.as : '');
    toggleEl('ip-info-as', hasAS);

    // Type Tag
    const typeTag = getEl('ip-info-type-tag');
    if (typeTag) {
        typeTag.textContent = stats.is_private ? 'Private Network' : 'Public Network';
        typeTag.className = 'badge ' + (stats.is_private ? 'badge-sm success' : 'badge-sm warning');
    }

    // Location Info
    const hasCountry = stats.country && stats.country !== '-' && stats.country !== 'geo';
    let countryDisplay = hasCountry ? stats.country : (stats.is_private ? 'Local Environment' : 'Global Origin');
    setTxt('ip-info-country', countryDisplay);

    const hasCity = stats.city && stats.city !== '-' && stats.city !== 'none';
    setTxt('ip-info-city', hasCity ? stats.city : '');
    toggleEl('ip-info-city', hasCity);

    const flagEl = getEl('ip-info-flag');
    if (flagEl) {
        flagEl.innerHTML = hasCountry ? getFlagHTML(stats.country_code, 'w40') : '<i class="fas fa-globe-europe opacity-40"></i>';
    }


    // IP Activity Chart
    const canvas = getEl('ip-info-chart');
    if (canvas) {
        const hourlyData = new Array(24).fill(0);
        const hourlyBlocked = new Array(24).fill(0);
        const now = new Date();

        (history || []).forEach(q => {
            const d = new Date(q.time);
            const diffHours = Math.floor((now - d) / (1000 * 60 * 60));
            if (diffHours >= 0 && diffHours < 24) {
                const idx = 23 - diffHours;
                hourlyData[idx]++;
                if (q.status.includes('Blocked')) hourlyBlocked[idx]++;
            }
        });
        charts.renderClientChart(canvas, hourlyData, hourlyBlocked);
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
            <td><span class="badge ${q.status.includes('Blocked') ? 'danger' : 'success'}">${helpers.escapeHTML(q.status)}</span></td>
        </tr>
    `).join('') || '<tr><td colspan="3">No recent activity</td></tr>';

    // Show/Hide block buttons
    const isBlocked = (state.currentConfig.blocked_clients || []).includes(ip);
    const isCritical = ['DoH Proxy', '127.0.0.1', '::1', 'localhost'].includes(ip);
    getEl('ip-block-btn').style.display = (isBlocked || isCritical) ? 'none' : 'block';
    getEl('ip-unblock-btn').style.display = isBlocked ? 'block' : 'none';

    // Show block reason if blocked
    const blockInfo = (state.currentConfig.blocked_clients_info || {})[ip];
    const abuseBadge = getEl('ip-info-abuse-reason-badge');
    if (abuseBadge) {
        if (blockInfo) {
            abuseBadge.classList.remove('hidden');
            const type = blockInfo.auto ? 'Threat Intelligence' : 'Manual Block';
            abuseBadge.innerHTML = `<i class="fas ${blockInfo.auto ? 'fa-robot' : 'fa-user-shield'}"></i> <strong>${type}</strong>: ${blockInfo.reason}`;
            abuseBadge.className = 'badge ' + (blockInfo.auto ? 'danger' : 'secondary');
        } else if (isBlocked) {
            // Fallback for cases where reason is missing
            abuseBadge.classList.remove('hidden');
            abuseBadge.innerHTML = `<i class="fas fa-user-shield"></i> <strong>Manual Block</strong>`;
            abuseBadge.className = 'badge secondary';
        } else {
            abuseBadge.classList.add('hidden');
        }
    }

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

    getEl('domain-info-clients-list').innerHTML = (clients || []).map(c => {
        const display = c.alias ? `${helpers.escapeHTML(c.alias)} (${helpers.escapeHTML(c.ip)})` : helpers.escapeHTML(c.ip);
        return `
            <tr>
                <td><a href="#" onclick="window.showIPDetails('${helpers.escapeHTML(c.ip)}'); return false;" style="color: var(--accent);">${display}</a></td>
                <td style="text-align:right">${c.count}</td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="2">No data</td></tr>';

    getEl('domain-info-history').innerHTML = (history || []).map(q => `
        <tr>
            <td>${new Date(q.time).toLocaleTimeString()}</td>
            <td><a href="#" onclick="window.showIPDetails('${helpers.escapeHTML(q.client_ip)}'); return false;" style="color: var(--accent);">${helpers.escapeHTML(q.client_alias || q.client_ip)}</a></td>
            <td><span class="badge ${q.status.includes('Blocked') ? 'danger' : 'success'}">${helpers.escapeHTML(q.status)}</span></td>
        </tr>
    `).join('') || '<tr><td colspan="3">No recent activity</td></tr>';
    ;

    getEl('domain-block-btn').style.display = isCustomBlocked ? 'none' : 'block';
    getEl('domain-allow-btn').style.display = isCustomBlocked ? 'block' : 'none';

    getEl('domain-info-modal').classList.remove('hidden');
}

export function renderProtectionResult(res, domain) {
    const el = getEl('search-result');
    if (!el) return;

    el.classList.remove('hidden');
    if (res.blocked) {
        const lists = (res.lists || []).join(', ') || 'Custom Blocklist';
        el.innerHTML = `
            <div class="result-card blocked" style="animation: slideUp 0.3s ease-out;">
                <i class="fas fa-shield-alt icon-blocked"></i>
                <div class="result-details">
                    <span class="url-text">${helpers.escapeHTML(domain)}</span>
                    <span class="status-msg" style="color: var(--danger);">is <strong>BLOCKED</strong> by ${lists}</span>
                </div>
                <button class="btn btn-sm secondary" onclick="window.addCustomRule('allowed', '${helpers.escapeHTML(domain)}', event)">Whitelist</button>
            </div>
        `;
    } else {
        const allowedBy = (res.allowlists || []).join(', ');
        let msg = 'is <strong>ALLOWED</strong>';
        if (allowedBy) {
            msg += ` by ${allowedBy}`;
        } else {
            msg += ' (not in any active blocklist)';
        }

        el.innerHTML = `
            <div class="result-card allowed" style="animation: slideUp 0.3s ease-out;">
                <i class="fas fa-check-circle icon-allowed"></i>
                <div class="result-details">
                    <span class="url-text">${helpers.escapeHTML(domain)}</span>
                    <span class="status-msg" style="color: var(--accent);">${msg} and secure.</span>
                </div>
                <button class="btn btn-sm secondary" onclick="window.addCustomRule('blocked', '${helpers.escapeHTML(domain)}', event)">Block</button>
            </div>
        `;
    }
}
