/**
 * UI Renderers Module
 * Core dashboard, queries, config, analytics, and MFA lists
 */
import { state, uiRefs, getEl } from '../core/state.js';
import * as helpers from './helpers.js';
import { getFlagHTML } from './helpers.js';
import { VirtualScroller } from './scroller.js';

// Re-export specialized renderers to maintain backward compatibility for existing callers
export {
    renderBlockedClientsModal,
    renderIPDetails,
    renderDomainDetails,
    renderProtectionResult
} from './renderers_details.js';

export {
    renderDiagnostics,
    renderAboutData,
    renderClusterStatus
} from './renderers_system.js';

export function renderDashStats(data) {
    const c = uiRefs.statsContainer;
    if (!c.total) return;

    helpers.countTo(c.total, data.total_queries);
    helpers.countTo(c.blocked, data.blocked_queries);

    const ratio = data.total_queries > 0 ? (data.blocked_queries / data.total_queries * 100) : 0;
    helpers.countTo(c.ratio, ratio, 800, ' %', 1);

    const cache = data.total_queries > 0 ? (data.cache_hits / data.total_queries * 100) : 0;
    helpers.countTo(c.cache, cache, 800, ' %', 1);

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
    if (appVer) {
        appVer.textContent = data.version;
        const appVerLink = getEl('app-version-link');
        if (appVerLink && data.version) {
            const tag = data.version.startsWith('v') ? data.version : `v${data.version}`;
            appVerLink.href = `https://github.com/FaserF/ShieldDNS/releases/tag/${tag}`;
        }
    }
    const aboutAppVer = getEl('about-shielddns-ver');
    if (aboutAppVer) aboutAppVer.textContent = data.version;

    const latestVer = getEl('update-latest-ver');
    if (latestVer) {
        latestVer.textContent = data.latest_version || 'Unknown';
        const btnUpdate = getEl('btn-update-now');
        if (btnUpdate) {
            if (data.version && data.latest_version && data.version !== data.latest_version) {
                btnUpdate.style.display = 'block';
            } else {
                btnUpdate.style.display = 'none';
            }
        }
    }
}

export function renderQueries(queries) {
    const filtered = state.filterDohProxy ?
        queries.filter(q => q.client_ip !== '127.0.0.1' && q.client_ip !== '::1' && q.client_ip !== '::ffff:127.0.0.1') :
        queries;

    if (uiRefs.queryLogItems) {
        uiRefs.queryLogItems.innerHTML = '';
        filtered.slice(0, 20).forEach(q => uiRefs.queryLogItems.appendChild(createQueryRow(q)));
    }

    if (uiRefs.fullQueryLogItems) {
        if (!state.fullQueryScroller) {
            state.fullQueryScroller = new VirtualScroller('full-query-log-items', 48, createQueryRow);
        }
        state.cachedQueries = queries;
        state.fullQueryScroller.setData(filtered);
    }
}

export function createQueryRow(q) {
    const row = document.createElement('tr');
    const time = q.time ? new Date(q.time).toLocaleTimeString() : 'Unknown';
    const actionBtn = q.status.includes('Blocked') ?
        `<button class="btn btn-sm secondary" onclick="addCustomRule('allowed', '${helpers.escapeHTML(q.domain)}', event)" title="Whitelist Domain">Allow</button>` :
        `<button class="btn btn-sm secondary" onclick="addCustomRule('blocked', '${helpers.escapeHTML(q.domain)}', event)" title="Blacklist Domain">Block</button>`;

    let statusClass = 'official';
    if (q.status.includes('Blocked')) {
        statusClass = 'danger';
    } else if (q.status === 'Allowed') {
        statusClass = 'success';
    }
    const escapedAlias = q.client_alias ? helpers.escapeHTML(q.client_alias) : '';
    const displayIp = q.client_alias ? `${escapedAlias} (${helpers.escapeHTML(q.client_ip)})` : helpers.escapeHTML(q.client_ip);

    let nodeBadge = '';
    if (q.node_name) {
        nodeBadge = `<span class="badge" style="background: rgba(59, 130, 246, 0.15); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.35); font-size: 0.72rem; padding: 2px 6px; margin-left: 6px; border-radius: 4px; vertical-align: middle;" title="Origin Node: ${helpers.escapeHTML(q.node_name)}"><i class="fas fa-server" style="font-size: 0.65rem; margin-right: 3px;"></i>${helpers.escapeHTML(q.node_name)}</span>`;
    }

    row.innerHTML = `
        <td>${time}</td>
        <td><span class="domain-link" onclick="showDomainDetails('${helpers.escapeHTML(q.domain)}')">${helpers.escapeHTML(q.domain)}</span>${nodeBadge}</td>
        <td><span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(q.client_ip)}')">${displayIp}</span></td>
        <td class="hide-mobile">${helpers.escapeHTML(q.type) || 'A'}</td>
        <td><span class="badge ${statusClass}">${helpers.escapeHTML(q.status)}</span></td>
        <td class="hide-mobile">${actionBtn}</td>
    `;
    return row;
}

export function renderConfig(cfg) {
    const domain = cfg.admin_domain || window.location.hostname;

    const dotHost = getEl('guide-dot-host');
    const dotUrl = getEl('guide-dot-url');
    const dohUrl = getEl('guide-doh-url');
    const doqUrl = getEl('guide-doq-url');
    const clusterNote = getEl('guide-cluster-note');
    const clusterWorkerHost = getEl('guide-cluster-worker-host');

    if (dotHost) dotHost.value = domain;
    if (dotUrl) dotUrl.value = `tls://${domain}`;
    if (doqUrl) doqUrl.value = `quic://${domain}`;

    const workerDomain = cfg.cluster_worker_domain;
    if (workerDomain) {
        if (dohUrl) dohUrl.value = `https://${workerDomain}/dns-query`;
        if (clusterNote) clusterNote.classList.remove('hidden');
        if (clusterWorkerHost) clusterWorkerHost.textContent = workerDomain;
    } else {
        if (dohUrl) dohUrl.value = `https://${domain}/dns-query`;
        if (clusterNote) clusterNote.classList.add('hidden');
    }

    const g = uiRefs.guide;
    if (g && g.mobileBtn && g.mobileQR) {
        const fullUrl = `https://${domain}/api/mobileconfig`;
        g.mobileBtn.href = fullUrl;
        g.mobileQR.src = `../api/qr?data=${encodeURIComponent(fullUrl)}`;
    }

    const lastLoginEl = getEl('dashboard-last-login');
    if (lastLoginEl && cfg.previous_login) {
        const prev = new Date(cfg.previous_login);
        if (prev.getTime() > 0) {
            lastLoginEl.textContent = `Last login: ${prev.toLocaleString()}`;
        }
    }

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

    const upstreamsInput = getEl('upstreams-input');
    if (upstreamsInput) upstreamsInput.value = (cfg.upstreams || []).join(', ');
    const dotInput = getEl('dot-upstreams-input');
    if (dotInput) dotInput.value = (cfg.upstream_dot || []).join(', ');
    const adminDomainInput = getEl('admin-domain-input');
    if (adminDomainInput) adminDomainInput.value = cfg.admin_domain || '';
    const blockIpInput = getEl('block-ip-input');
    if (blockIpInput) blockIpInput.value = cfg.block_page_ip || '';

    if (getEl('prefer-encrypted-check')) getEl('prefer-encrypted-check').checked = !!cfg.prefer_encrypted;
    if (getEl('doh3-enabled-check')) getEl('doh3-enabled-check').checked = cfg.doh3_enabled !== false;
    if (getEl('ech-optimization-check')) getEl('ech-optimization-check').checked = cfg.ech_optimization_enabled !== false;
    if (getEl('debug-mode-check')) getEl('debug-mode-check').checked = !!cfg.debug_mode;
    if (getEl('sign-mobileconfig-check')) {
        const signEl = getEl('sign-mobileconfig-check');
        const signHint = getEl('sign-mobileconfig-private-hint');
        const isPurePrivate = cfg.cluster_instance_type === 'private';
        if (isPurePrivate) {
            signEl.checked = false;
            signEl.disabled = true;
            if (signHint) signHint.style.display = 'inline';
        } else {
            signEl.disabled = false;
            signEl.checked = !!cfg.sign_mobileconfig;
            if (signHint) signHint.style.display = 'none';
        }
    }
    if (getEl('abuse-detection-check')) getEl('abuse-detection-check').checked = !!cfg.abuse_detection_enabled;
    if (getEl('dnssec-check')) getEl('dnssec-check').checked = !!cfg.dnssec_enabled;
    if (getEl('serve-stale-check')) getEl('serve-stale-check').checked = !!cfg.serve_stale;
    if (getEl('smart-upstream-check')) getEl('smart-upstream-check').checked = !!cfg.use_fastest_upstream;
    if (getEl('smart-selection-policy-input')) getEl('smart-selection-policy-input').value = cfg.smart_selection_policy || 'fastest';
    if (getEl('latency-interval-input')) getEl('latency-interval-input').value = cfg.latency_test_interval || 10;
    if (getEl('diagnostics-interval-input')) getEl('diagnostics-interval-input').value = cfg.diagnostics_refresh_interval || 30;
    if (getEl('retention-input')) getEl('retention-input').value = cfg.retention_days || 30;
    if (getEl('doh-rate-limit-input')) getEl('doh-rate-limit-input').value = cfg.doh_rate_limit || 30;
    if (getEl('rate-limit-rate-input')) getEl('rate-limit-rate-input').value = cfg.rate_limit_rate !== undefined ? cfg.rate_limit_rate : 100;
    if (getEl('rate-limit-burst-input')) getEl('rate-limit-burst-input').value = cfg.rate_limit_burst !== undefined ? cfg.rate_limit_burst : 250;
    if (getEl('abuse-dga-threshold-input')) getEl('abuse-dga-threshold-input').value = cfg.abuse_dga_threshold || 3.8;
    if (getEl('abuse-dga-min-len-input')) getEl('abuse-dga-min-len-input').value = cfg.abuse_dga_min_len || 8;

    if (getEl('malicious-check')) getEl('malicious-check').checked = cfg.malicious_ip_blocking_enabled;
    if (getEl('malicious-interval-input')) getEl('malicious-interval-input').value = cfg.malicious_ip_interval || 8;

    renderAutoblockWhitelist(cfg.autoblock_whitelist || []);

    if (getEl('verify-upstream-tls-check')) getEl('verify-upstream-tls-check').checked = !!cfg.verify_upstream_tls;
    if (getEl('mcp-server-enabled-check')) getEl('mcp-server-enabled-check').checked = !!cfg.mcp_server_enabled;
    if (getEl('anonymize-client-ips-check')) getEl('anonymize-client-ips-check').checked = !!cfg.anonymize_client_ips;
    if (getEl('dns-rebinding-protection-check')) getEl('dns-rebinding-protection-check').checked = !!cfg.dns_rebinding_protection;
    if (getEl('strip-ecs-check')) getEl('strip-ecs-check').checked = !!cfg.strip_ecs;

    const currentOrigin = (cfg && cfg.admin_domain) ? `https://${cfg.admin_domain}` : (window.location.origin || 'https://shielddns.local');

    if (getEl('mcp-endpoint-url')) {
        getEl('mcp-endpoint-url').textContent = `${currentOrigin}/api/mcp?token=<YOUR_API_TOKEN>`;
    }
    if (getEl('mcp-antigravity-config-code')) {
        const agyConfig = JSON.stringify({
            mcpServers: {
                shielddns: {
                    url: `${currentOrigin}/api/mcp?token=<YOUR_API_TOKEN>`
                }
            }
        });
        getEl('mcp-antigravity-config-code').textContent = agyConfig;
    }

    if (getEl('update-channel')) getEl('update-channel').value = cfg.update_channel || 'stable';
    if (getEl('auto-update-enabled')) {
        const autoUpCheck = getEl('auto-update-enabled');
        autoUpCheck.checked = !!cfg.auto_update_enabled;
        const timeContainer = getEl('auto-update-time-container');
        if (timeContainer) {
            timeContainer.style.display = autoUpCheck.checked ? 'flex' : 'none';
        }
    }
    if (getEl('auto-update-hour')) getEl('auto-update-hour').value = cfg.auto_update_hour !== undefined ? cfg.auto_update_hour.toString() : '3';

    updateMFAStatus(cfg);

    const renderCustomList = (id, items) => {
        const el = getEl(id);
        if (!el) return;
        el.innerHTML = items?.map(domain => `
            <div class="preset-selection-item">
                <span>${helpers.escapeHTML(domain)}</span>
                <button type="button" class="btn btn-sm secondary" onclick="removeCustomRule('${helpers.escapeHTML(domain)}', event)" title="Remove Rule"><i class="fas fa-trash"></i></button>
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

    const routingList = getEl('routing-rules-list');
    if (routingList) {
        const rules = cfg.routing_rules || [];
        if (rules.length === 0) {
            routingList.innerHTML = '<p class="help" style="margin: 8px 0;">No routing rules configured. Queries use standard default routing.</p>';
        } else {
            routingList.innerHTML = rules.map(rule => {
                let badgeClass = 'secondary';
                let targetText = 'Normal Routing';
                if (rule.target === 'host') {
                    badgeClass = 'official';
                    targetText = `Host: ${rule.host_target || 'Master/Slave'}`;
                } else if (rule.target === 'wireguard') {
                    badgeClass = 'success';
                    targetText = `WireGuard: ${rule.wireguard_config || cfg.wireguard_gateway || 'VPN'}`;
                }
                const matchIcon = rule.match_type === 'client_ip' ? 'fa-laptop' : 'fa-globe';
                return `
                <div class="preset-selection-item" style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 8px; flex: 1;">
                        <i class="fas ${matchIcon}" style="color: var(--accent); font-size: 0.9rem;"></i>
                        <strong style="font-family: monospace;">${helpers.escapeHTML(rule.match)}</strong>
                        ${rule.name ? `<span class="help">(${helpers.escapeHTML(rule.name)})</span>` : ''}
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span class="badge ${badgeClass}">${helpers.escapeHTML(targetText)}</span>
                        <button class="btn btn-sm secondary" onclick="removeRoutingRule('${helpers.escapeHTML(rule.id || rule.match)}', event)" title="Remove Routing Rule"><i class="fas fa-trash"></i></button>
                    </div>
                </div>`;
            }).join('');
        }
    }

    const activeBlocks = getEl('active-blocklists-list');
    if (activeBlocks) {
        activeBlocks.innerHTML = (cfg.lists || []).map((list, i) => {
            const ramMB = Math.round((list.entries || 0) * 1.1 / 1024);
            const ramBadge = list.enabled ? `<span class="badge secondary" style="margin-left: 10px; font-weight: 500;">~${ramMB} MB RAM</span>` : '';
            return `
            <div class="list-item" onclick="window.openListDetailsModal(${i}, 'block')">
                <div class="list-info">
                    <h3 style="display: flex; align-items: center; flex-wrap: wrap; gap: 8px;">${helpers.escapeHTML(list.name)}${ramBadge}</h3>
                    <p>${helpers.escapeHTML(list.url)}</p>
                </div>
                <div class="list-actions">
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'block', event)">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm secondary danger" onclick="event.stopPropagation(); window.removeList(${i}, 'block', event)" title="Remove List"><i class="fas fa-trash"></i></button>
                </div>
            </div>
            `;
        }).join('') || '<p class="help">No active blocklists.</p>';
    }

    const activeAllows = getEl('active-allowlists-list');
    if (activeAllows) {
        activeAllows.innerHTML = (cfg.allowlists || []).map((list, i) => {
            const ramMB = Math.round((list.entries || 0) * 1.1 / 1024);
            const ramBadge = list.enabled ? `<span class="badge secondary" style="margin-left: 10px; font-weight: 500;">~${ramMB} MB RAM</span>` : '';
            return `
            <div class="list-item" onclick="window.openListDetailsModal(${i}, 'allow')">
                <div class="list-info">
                    <h3 style="display: flex; align-items: center; flex-wrap: wrap; gap: 8px;">${helpers.escapeHTML(list.name)}${ramBadge}</h3>
                    <p>${helpers.escapeHTML(list.url)}</p>
                </div>
                <div class="list-actions">
                    <button class="btn btn-sm secondary" onclick="event.stopPropagation(); window.toggleList(${i}, ${!list.enabled}, 'allow', event)">${list.enabled ? 'Disable' : 'Enable'}</button>
                    <button class="btn btn-sm secondary danger" onclick="event.stopPropagation(); window.removeList(${i}, 'allow', event)" title="Remove List"><i class="fas fa-trash"></i></button>
                </div>
            </div>
            `;
        }).join('') || '<p class="help">No active allowlists.</p>';
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

    const blockedBadge = getEl('blocked-clients-count-badge');
    if (blockedBadge) {
        const count = cfg.blocked_clients?.length || 0;
        blockedBadge.textContent = `${count} Client${count !== 1 ? 's' : ''} Blocked`;
        blockedBadge.style.display = count > 0 ? 'inline-block' : 'none';
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
        topClientsList.innerHTML = (clients || [])
            .filter(c => c.client_ip !== 'DoH Proxy')
            .map(c => {
                const display = c.client_alias ? `${helpers.escapeHTML(c.client_alias)} (${helpers.escapeHTML(c.client_ip)})` : helpers.escapeHTML(c.client_ip);
                let countryCell = '<span style="color:var(--text-secondary)">🏠 Local</span>';
                if (c.country_code && c.country_code.length === 2 && c.country_code.toLowerCase() !== 'ge') {
                    const flag = getFlagHTML(c.country_code);
                    countryCell = `${flag} <span style="margin-left: 4px;">${helpers.escapeHTML(c.country_code.toUpperCase())}</span>`;
                } else if (c.country_code === '') {
                    countryCell = '<span style="color:var(--text-secondary)">—</span>';
                }
                return `<tr>
                    <td><span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(c.client_ip)}')">${display}</span></td>
                    <td>${countryCell}</td>
                    <td class="text-right">${helpers.escapeHTML(c.count?.toString() || '0')}</td>
                </tr>`;
            }).join('') || '<tr><td colspan="3">No data available</td></tr>';
    }
}

export function renderAPIKeys(keys) {
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
                        <button type="button" class="btn btn-sm secondary" onclick="window.editAPIKey('${k.id}')"><i class="fas fa-edit"></i></button>
                        <button type="button" class="btn btn-sm secondary danger" onclick="window.deleteAPIKey('${k.id}', event)" title="Delete Key"><i class="fas fa-trash"></i></button>
                    </div>
                </td>
            </tr>
        `;
    }).join('') || '<tr><td colspan="5" class="help">No API keys generated.</td></tr>';
}

export function renderAutoblockWhitelist(whitelist) {
    const container = getEl('autoblock-whitelist-tags');
    if (!container) return;

    if (!whitelist || whitelist.length === 0) {
        container.innerHTML = '<p class="help">No IP addresses whitelisted.</p>';
        return;
    }

    container.innerHTML = whitelist.map(ip => `
        <div class="tag">
            <span>${helpers.escapeHTML(ip)}</span>
            <button type="button" class="tag-remove" onclick="removeWhitelistIP('${helpers.escapeHTML(ip)}')" title="Remove from Whitelist">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `).join('');
}

export function updateMFAStatus(cfg) {
    const config = cfg || state.currentConfig;
    const badge = getEl('mfa-status-badge');
    const toggleBtn = getEl('mfa-toggle-btn');
    if (!badge || !toggleBtn) return;

    if (config.mfa_enabled) {
        badge.textContent = 'ENABLED';
        badge.className = 'badge success';
        toggleBtn.textContent = 'Manage MFA';
    } else {
        badge.textContent = 'DISABLED';
        badge.className = 'badge secondary';
        toggleBtn.textContent = 'Set Up MFA';
    }
    
    if (getEl('mfa-manage-area') && !getEl('mfa-manage-area').classList.contains('hidden')) {
        renderTOTPList(config);
        renderPasskeys(config);
    }
}

export function renderTOTPList(cfg) {
    const list = getEl('mfa-totp-list');
    if (!list) return;

    const config = cfg || state.currentConfig;
    const totps = config.totp_configs || [];
    if (totps.length === 0) {
        list.innerHTML = 'No authenticator apps registered.';
        return;
    }

    list.innerHTML = totps.map(c => `
        <div class="mfa-item">
            <div class="mfa-item-info">
                <i class="fas fa-mobile-alt"></i>
                <div class="mfa-item-text">
                    <div class="mfa-item-name">${helpers.escapeHTML(c.name || 'Authenticator App')}</div>
                    <div class="mfa-item-meta">Added ${helpers.formatDate(c.created_at)}</div>
                </div>
            </div>
            <button type="button" class="btn btn-sm secondary danger" onclick="window.deleteMFAMethod('totp', '${c.id}', event)" title="Remove TOTP">
                <i class="fas fa-trash"></i>
            </button>
        </div>
    `).join('');
}

export function renderPasskeys(cfg) {
    const list = getEl('mfa-passkey-list');
    if (!list) return;

    const config = cfg || state.currentConfig;
    const creds = config.webauthn_credentials || [];
    if (creds.length === 0) {
        list.innerHTML = 'No passkeys registered.';
        return;
    }

    list.innerHTML = creds.map(c => {
        const idStr = typeof c.id === 'string' ? c.id : helpers.base64FromBuffer(c.id);
        return `
            <div class="mfa-item">
                <div class="mfa-item-info">
                    <i class="fas fa-key"></i>
                    <div class="mfa-item-text">
                        <div class="mfa-item-name">${helpers.escapeHTML(c.name || 'Security Key')}</div>
                        <div class="mfa-item-meta">Added ${helpers.formatDate(c.created_at)}</div>
                    </div>
                </div>
                <button type="button" class="btn btn-sm secondary danger" onclick="window.deleteMFAMethod('webauthn', '${idStr}', event)" title="Remove Passkey">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        `;
    }).join('');
}
