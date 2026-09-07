/**
 * Modals & Detail Dialog Renderers
 */
import { state, getEl } from '../core/state.js';
import * as helpers from './helpers.js';
import { getFlagHTML } from './helpers.js';
import * as charts from './charts.js';

export function renderBlockedClientsModal(blockedClients, infoMap) {
    const list = getEl('blocked-clients-table-body');
    const filter = getEl('blocked-clients-country-filter');
    const dateFilter = getEl('blocked-clients-date-filter')?.value || '';
    const search = getEl('blocked-clients-search')?.value.toLowerCase() || '';
    const countryFilter = filter?.value || 'ALL';

    if (!list) return;

    // Collect all countries for the filter dropdown
    const countriesInList = new Set();
    let hasUnresolved = false;
    const rows = (blockedClients || []).map(ip => {
        const info = infoMap[ip] || {};
        const countryCode = info.country_code || '';

        // Track unresolved for background polling
        if (countryCode === '-' || countryCode === '') hasUnresolved = true;

        // Only add resolved codes to the filter dropdown (not '-', not 'geo')
        if (countryCode && countryCode !== 'geo' && countryCode !== '-') countriesInList.add(countryCode);

        // Apply filters
        if (countryFilter !== 'ALL' && countryCode !== countryFilter) return null;
        if (search && !ip.includes(search) && !info.reason?.toLowerCase().includes(search)) return null;
        if (dateFilter && info.blocked_at && !info.blocked_at.startsWith(dateFilter)) return null;

        const dateStr = info.blocked_at ? new Date(info.blocked_at).toLocaleString() : 'Unknown';
        const isResolved = countryCode && countryCode !== '-' && countryCode !== '';
        const countryName = isResolved ? ((state.allCountries || {})[countryCode] || countryCode) : (ip.includes(':') || !ip.match(/^\d+\./) ? 'Local/Internal' : '');
        const reason = info.reason || 'Manual block';
        const type = info.auto ? '<i class="fas fa-robot" title="Auto-Blocked"></i> ' : '<i class="fas fa-user-shield" title="Manually Blocked"></i> ';

        return `
            <tr>
                <td><span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(ip)}')">${helpers.escapeHTML(ip)}</span></td>
                <td class="help" style="font-size: 0.75rem;">${dateStr}</td>
                <td>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        ${getFlagHTML(isResolved ? countryCode : '')}
                        <span>${helpers.escapeHTML(countryName)}</span>
                    </div>
                </td>
                <td style="font-size: 0.85rem;">${type}${helpers.escapeHTML(reason)}</td>
                <td>
                    <button type="button" class="btn btn-sm secondary danger" onclick="unblockClient('${helpers.escapeHTML(ip)}', event)" title="Unblock Client">
                        <i class="fas fa-unlock"></i>
                    </button>
                </td>
            </tr>
        `;
    }).filter(Boolean);

    // If there are still unresolved IPs, poll the backend after 5s and re-render
    clearTimeout(state._blockedClientsRefreshTimer);
    if (hasUnresolved) {
        state._blockedClientsRefreshTimer = setTimeout(async () => {
            try {
                const { apiFetch, endpoints } = await import('../services/api.js');
                const fresh = await apiFetch(endpoints.blockedClients);
                if (fresh && fresh.blocked_clients) {
                    renderBlockedClientsModal(fresh.blocked_clients, fresh.blocked_clients_info || {});
                }
            } catch(e) { /* silent — will retry next render */ }
        }, 5000);
    }

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
            
            const dot = deviceCard.querySelector('span[style*="opacity: 0.5"]');
            if (dot) dot.style.display = (!os || isOSUnknown || !mac || isMACUnavailable) ? 'none' : '';
        }
    }

    // Provider & ASN
    const provider = stats.isp || stats.org;
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
