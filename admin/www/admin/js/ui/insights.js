/**
 * Insights, Explainability, Simulation, Services, Device Fingerprinting, Anomalies, Agent Inbox, and Wall Display
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { renderFlowSVG } from '../core/help.js';

// Client identity cache (ip -> DeviceIdentity)
export const deviceIdentityCache = new Map();

export async function refreshDeviceIdentities() {
    try {
        const res = await api.apiFetch(api.endpoints.clientIdentities);
        if (res && Array.isArray(res.identities)) {
            res.identities.forEach((ident) => {
                if (ident && ident.client_ip) {
                    deviceIdentityCache.set(ident.client_ip, ident);
                }
            });
        }
    } catch {
        // Non-critical enrichment; ignore on cold start
    }
}

export function renderClientChipHTML(ip, alias) {
    const safeIP = helpers.escapeHTML(ip || '');
    const safeAlias = alias ? helpers.escapeHTML(alias) : '';
    const ident = deviceIdentityCache.get(ip);
    const icon = (ident && ident.icon) ? ident.icon : 'fas fa-network-wired';
    const title = ident && ident.product && ident.product !== 'Unknown Device' ?
        `${ident.product} (${ident.confidence}) — Click to inspect or rename` :
        'Click to inspect, fingerprint, or name this device';
    const label = safeAlias ? `${safeAlias} <span class="chip-ip">(${safeIP})</span>` : safeIP;
    const kindBadge = (ident && ident.product && ident.product !== 'Unknown Device') ?
        `<span class="chip-kind-pill" title="${helpers.escapeHTML(ident.product)}">${helpers.escapeHTML(ident.product)}</span>` :
        '';

    return `<span class="client-chip ip-link" onclick="showIPDetails('${safeIP}')" title="${helpers.escapeHTML(title)}"><i class="${helpers.escapeHTML(icon)} chip-icon"></i><span class="chip-label">${label}</span>${kindBadge}</span>`;
}

// =============================================================================
// 1. Explainable Decision Engine UI
// =============================================================================
export async function runExplainQuery() {
    const domainInput = getEl('explain-domain-input');
    const clientInput = getEl('explain-client-input');
    const qtypeSel = getEl('explain-qtype-select');
    const askAICheck = getEl('explain-ask-ai-check');
    const outBox = getEl('explain-result-box');
    const btn = getEl('explain-run-btn');
    if (!domainInput || !outBox) return;

    const domain = domainInput.value.trim();
    if (!domain) {
        helpers.showAlert('Please enter a domain name to explain.');
        return;
    }

    const params = new URLSearchParams({
        domain,
        client_ip: clientInput?.value.trim() || '',
        qtype: qtypeSel?.value || 'A',
        ask_ai: askAICheck?.checked ? 'true' : 'false'
    });

    helpers.setBtnLoading(btn, true, 'Explaining...');
    outBox.classList.remove('hidden');
    outBox.innerHTML = '<div class="help"><i class="fas fa-spinner fa-spin"></i> Evaluating filtering rules and routes...</div>';

    try {
        const exp = await api.apiFetch(`${api.endpoints.explain}?${params.toString()}`);
        const isBad = exp.outcome === 'blocked';
        const badgeCls = isBad ? 'danger' : (exp.outcome === 'rewritten' || exp.outcome === 'routed' ? 'official' : 'success');

        const stagesHTML = (exp.stages || []).map((st) => {
            const stIcon = st.status === 'matched' ? '<i class="fas fa-check-circle" style="color:var(--accent)"></i>'
                : st.status === 'skipped' ? '<i class="fas fa-forward" style="opacity:0.45"></i>'
                : '<i class="far fa-circle" style="opacity:0.45"></i>';
            return `<div class="explain-stage-row">
                <span class="explain-stage-name">${stIcon} <strong>${helpers.escapeHTML(st.stage)}</strong></span>
                <span class="explain-stage-detail">${helpers.escapeHTML(st.detail)}</span>
            </div>`;
        }).join('');

        let aiHTML = '';
        if (exp.ai_verdict) {
            const v = exp.ai_verdict;
            aiHTML = `<div class="explain-ai-box">
                <strong><i class="fas fa-robot"></i> Omniroute AI Guardian Verdict:</strong>
                <span class="badge ${v.is_threat ? 'danger' : 'success'}">${helpers.escapeHTML(v.threat_type)} (${Math.round((v.confidence || 0) * 100)}%)</span>
                <span>${helpers.escapeHTML(v.reason || '')}</span>
            </div>`;
        }

        outBox.innerHTML = `
            <div class="explain-summary-banner ${isBad ? 'bad' : 'ok'}">
                <span class="badge ${badgeCls}">${helpers.escapeHTML((exp.outcome || '').toUpperCase())} • ${helpers.escapeHTML(exp.action || '')}</span>
                <strong>${helpers.escapeHTML(exp.summary || '')}</strong>
            </div>
            <div class="explain-diagram-wrap">
                ${renderFlowSVG(exp.flow_highlight || 'upstream', exp.client_alias || exp.client_ip || 'Any Client', exp.domain)}
            </div>
            <div class="explain-meta-grid">
                <div><span class="help">Winning Rule:</span> <strong>${helpers.escapeHTML(exp.winning_rule || '—')}</strong></div>
                <div><span class="help">Upstream Route:</span> <strong>${helpers.escapeHTML(exp.upstream_route || 'Local / Sinkholed')}</strong></div>
            </div>
            ${aiHTML}
            <div class="explain-stages-list">${stagesHTML}</div>
        `;
    } catch (err) {
        outBox.innerHTML = `<div class="badge danger">Explain failed: ${helpers.escapeHTML(err.message)}</div>`;
    } finally {
        helpers.setBtnLoading(btn, false);
    }
}

// =============================================================================
// 2. 24h Change Simulation Preview
// =============================================================================
export async function runRuleSimulation(action, inputId, btnEl) {
    const input = getEl(inputId);
    const previewBox = getEl('rule-simulation-preview');
    if (!input || !previewBox) return;

    const domain = input.value.trim();
    if (!domain) {
        helpers.showAlert('Enter a domain first to simulate its 24h impact.');
        return;
    }

    helpers.setBtnLoading(btnEl, true, 'Simulating...');
    previewBox.classList.remove('hidden');
    previewBox.innerHTML = '<div class="help"><i class="fas fa-spinner fa-spin"></i> Replaying last 24h queries...</div>';

    try {
        const res = await api.apiFetch(api.endpoints.simulateRule, {
            method: 'POST',
            body: JSON.stringify({
                action,
                domain,
                window_hours: 24,
                ask_ai: !!(state.currentConfig && state.currentConfig.ai_enabled)
            })
        });

        const clientsEntries = Object.entries(res.affected_clients || {});
        const clientsHTML = clientsEntries.length > 0 ?
            clientsEntries.slice(0, 6).map(([c, cnt]) => `<span class="badge">${helpers.escapeHTML(c)}: ${cnt}</span>`).join(' ') :
            '<span class="help">No devices impacted in the last 24h</span>';

        const aiNote = res.ai_blast_assessment ?
            `<div class="sim-ai-note"><i class="fas fa-robot"></i> <strong>AI Blast Assessment:</strong> ${helpers.escapeHTML(res.ai_blast_assessment)}</div>` :
            '';

        previewBox.innerHTML = `
            <div class="sim-preview-header">
                <strong><i class="fas fa-vial"></i> What-If 24h Simulation Preview</strong>
                <button type="button" class="btn btn-sm secondary" onclick="document.getElementById('rule-simulation-preview').classList.add('hidden')">Dismiss</button>
            </div>
            <p class="sim-summary">${helpers.escapeHTML(res.summary_sentence || '')}</p>
            <div class="sim-metrics-row">
                <span class="badge">Analyzed: ${res.queries_analyzed || 0}</span>
                <span class="badge danger">Newly Blocked: ${res.newly_blocked || 0}</span>
                <span class="badge success">Newly Allowed: ${res.newly_allowed || 0}</span>
            </div>
            <div class="sim-clients-row">${clientsHTML}</div>
            ${aiNote}
        `;
    } catch (err) {
        previewBox.innerHTML = `<div class="badge danger">Simulation failed: ${helpers.escapeHTML(err.message)}</div>`;
    } finally {
        helpers.setBtnLoading(btnEl, false);
    }
}

// =============================================================================
// 3. Parental Controls: SafeSearch & Blocked Services Catalog
// =============================================================================
let currentBlockedServices = new Set();

export async function loadServicesCatalog() {
    const grid = getEl('services-catalog-grid');
    if (!grid) return;

    try {
        const res = await api.apiFetch(api.endpoints.servicesCatalog);
        currentBlockedServices = new Set(res.blocked_services || []);
        const ssCheck = getEl('safesearch-enabled-check');
        if (ssCheck) ssCheck.checked = !!res.safesearch_enabled;
        const ytSel = getEl('youtube-restriction-select');
        if (ytSel) ytSel.value = res.youtube_restriction || 'none';

        grid.innerHTML = '';
        (res.presets || []).forEach((svc) => {
            const active = currentBlockedServices.has(svc.id);
            const chip = document.createElement('button');
            chip.type = 'button';
            chip.className = `service-chip ${active ? 'active' : ''}`;
            chip.dataset.serviceId = svc.id;
            chip.innerHTML = `<i class="${helpers.escapeHTML(svc.icon || 'fas fa-ban')}"></i> <span>${helpers.escapeHTML(svc.name)}</span>`;
            chip.title = `${svc.category}: ${(svc.domains || []).slice(0, 4).join(', ')}`;
            chip.addEventListener('click', () => {
                if (currentBlockedServices.has(svc.id)) {
                    currentBlockedServices.delete(svc.id);
                    chip.classList.remove('active');
                } else {
                    currentBlockedServices.add(svc.id);
                    chip.classList.add('active');
                }
            });
            grid.appendChild(chip);
        });
    } catch (err) {
        grid.innerHTML = `<p class="help">Unable to load service catalog: ${helpers.escapeHTML(err.message)}</p>`;
    }
}

export async function saveServicesSelection(btnEl) {
    const ssCheck = getEl('safesearch-enabled-check');
    const ytSel = getEl('youtube-restriction-select');
    helpers.setBtnLoading(btnEl, true, 'Applying...');

    try {
        await api.apiFetch(api.endpoints.servicesUpdate, {
            method: 'POST',
            body: JSON.stringify({
                blocked_services: Array.from(currentBlockedServices),
                safesearch_enabled: !!ssCheck?.checked,
                youtube_restriction: ytSel?.value || 'none'
            })
        });
        helpers.showToast('Parental controls & blocked services updated.');
    } catch (err) {
        helpers.showAlert('Failed to update services: ' + err.message);
    } finally {
        helpers.setBtnLoading(btnEl, false);
    }
}

// =============================================================================
// 4. Behavioral Anomalies & Beaconing Panel
// =============================================================================
export async function loadAnomalies() {
    const container = getEl('anomalies-list-container');
    if (!container) return;

    try {
        const res = await api.apiFetch(api.endpoints.anomalies);
        const items = res.anomalies || [];
        if (items.length === 0) {
            container.innerHTML = '<div class="help" style="padding:10px 0;"><i class="fas fa-check-circle" style="color:var(--success)"></i> No anomalous periodic beacons, DGA bursts, or block storms detected in the last 3 hours.</div>';
            return;
        }

        container.innerHTML = items.map((f) => {
            const sevCls = f.severity === 'high' ? 'danger' : (f.severity === 'medium' ? 'warning' : 'official');
            const clientLabel = f.client_alias ? `${f.client_alias} (${f.client_ip})` : f.client_ip;
            const ackBtn = f.acknowledged ?
                `<span class="badge success">Acknowledged</span>` :
                `<button class="btn btn-sm secondary" onclick="acknowledgeAnomaly('${helpers.escapeHTML(f.id)}')">Acknowledge</button>`;
            return `<div class="anomaly-row">
                <div class="anomaly-main">
                    <div class="anomaly-title">
                        <span class="badge ${sevCls}">${helpers.escapeHTML(f.kind)}</span>
                        <strong>${helpers.escapeHTML(f.summary)}</strong>
                    </div>
                    <div class="help">Client: <span class="ip-link" onclick="showIPDetails('${helpers.escapeHTML(f.client_ip)}')">${helpers.escapeHTML(clientLabel)}</span> • ${helpers.escapeHTML(f.evidence)}</div>
                </div>
                <div class="anomaly-actions">
                    ${ackBtn}
                    <button class="btn btn-sm secondary" onclick="muteAnomaly('${helpers.escapeHTML(f.client_ip)}', '${helpers.escapeHTML(f.kind)}')" title="Mute this anomaly kind for this device">Mute</button>
                </div>
            </div>`;
        }).join('');
    } catch (err) {
        container.innerHTML = `<div class="help">Failed to scan anomalies: ${helpers.escapeHTML(err.message)}</div>`;
    }
}

export async function acknowledgeAnomaly(id) {
    try {
        await api.apiFetch(api.endpoints.acknowledgeAnomaly, {
            method: 'POST',
            body: JSON.stringify({ id })
        });
        loadAnomalies();
    } catch (err) {
        helpers.showAlert('Acknowledge failed: ' + err.message);
    }
}

export async function muteAnomaly(clientIP, kind) {
    try {
        await api.apiFetch(api.endpoints.muteAnomaly, {
            method: 'POST',
            body: JSON.stringify({ client_ip: clientIP, kind })
        });
        loadAnomalies();
    } catch (err) {
        helpers.showAlert('Mute failed: ' + err.message);
    }
}

// =============================================================================
// 5. Pending Agent Plans Inbox
// =============================================================================
export async function loadAgentPlans() {
    try {
        const res = await api.apiFetch(api.endpoints.agentPlans);
        const badge = getEl('agent-plans-badge');
        const btn = getEl('agent-plans-btn');
        const count = res.pending_count || 0;
        if (badge) {
            badge.textContent = count;
            badge.classList.toggle('hidden', count === 0);
        }
        if (btn) {
            btn.classList.toggle('has-pending', count > 0);
        }

        const listEl = getEl('agent-plans-list');
        if (listEl) {
            const plans = res.plans || [];
            if (plans.length === 0) {
                listEl.innerHTML = '<p class="help">No staged AI agent plans.</p>';
            } else {
                listEl.innerHTML = plans.map((p) => {
                    const stCls = p.status === 'pending' ? 'warning' : (p.status === 'applied' ? 'success' : 'secondary');
                    const simTxt = p.simulation ? `<div class="help" style="margin-top:4px;"><i class="fas fa-vial"></i> ${helpers.escapeHTML(p.simulation.summary_sentence || '')}</div>` : '';
                    const actions = p.status === 'pending' ?
                        `<div class="plan-actions">
                            <button class="btn btn-sm primary" onclick="applyAgentPlan('${helpers.escapeHTML(p.id)}')">Approve & Apply</button>
                            <button class="btn btn-sm danger" onclick="discardAgentPlan('${helpers.escapeHTML(p.id)}')">Reject</button>
                           </div>` :
                        '';
                    return `<div class="agent-plan-card">
                        <div class="plan-head">
                            <span class="badge ${stCls}">${helpers.escapeHTML(p.status.toUpperCase())}</span>
                            <strong>${helpers.escapeHTML(p.action)}: <code>${helpers.escapeHTML(p.target)}</code></strong>
                            <span class="help">by ${helpers.escapeHTML(p.agent_name)}</span>
                        </div>
                        <div class="plan-reason">${helpers.escapeHTML(p.reason)}</div>
                        ${simTxt}
                        ${actions}
                    </div>`;
                }).join('');
            }
        }
    } catch {
        // Ignore background poll error
    }
}

export async function applyAgentPlan(planID) {
    try {
        await api.apiFetch(api.endpoints.applyAgentPlan, {
            method: 'POST',
            body: JSON.stringify({ plan_id: planID })
        });
        helpers.showToast('Agent plan applied cleanly.');
        loadAgentPlans();
    } catch (err) {
        helpers.showAlert('Failed to apply plan: ' + err.message);
    }
}

export async function discardAgentPlan(planID) {
    try {
        await api.apiFetch(api.endpoints.discardAgentPlan, {
            method: 'POST',
            body: JSON.stringify({ plan_id: planID })
        });
        loadAgentPlans();
    } catch (err) {
        helpers.showAlert('Failed to discard plan: ' + err.message);
    }
}

// =============================================================================
// 6. Diagnostic Support Package Download
// =============================================================================
export function downloadSupportPackage() {
    const level = getEl('support-pkg-level')?.value || 'strict';
    window.location.href = `${api.endpoints.supportPackage}?level=${encodeURIComponent(level)}`;
}

// =============================================================================
// 7. Wall / Kiosk Display Updater
// =============================================================================
let wallTimer = null;

export async function refreshWallView() {
    try {
        const [statsData, queriesData] = await Promise.all([
            api.apiFetch(api.endpoints.stats),
            api.apiFetch(`${api.endpoints.queries}?limit=12`)
        ]);
        const set = (id, v) => { const el = getEl(id); if (el) el.textContent = v; };
        const total = statsData.total_queries || 0;
        const blocked = statsData.blocked_queries || 0;
        const cache = statsData.cache_hits || 0;

        set('wall-qps', (statsData.active_qps || 0).toFixed(1));
        set('wall-total', total.toLocaleString());
        set('wall-blocked-pct', total > 0 ? `${(blocked / total * 100).toFixed(1)}%` : '0.0%');
        set('wall-cache-pct', total > 0 ? `${(cache / total * 100).toFixed(1)}%` : '0.0%');
        set('wall-latency', `${(statsData.average_latency || 0).toFixed(1)} ms`);
        set('wall-clients', (statsData.unique_clients || 0).toLocaleString());
        set('wall-clock', new Date().toLocaleTimeString());

        const ticker = getEl('wall-ticker-body');
        if (ticker && Array.isArray(queriesData)) {
            ticker.innerHTML = queriesData.slice(0, 10).map((q) => {
                const isBlk = q.status && q.status.includes('Blocked');
                return `<tr>
                    <td>${q.time ? new Date(q.time).toLocaleTimeString() : ''}</td>
                    <td><strong>${helpers.escapeHTML(q.domain)}</strong></td>
                    <td>${helpers.escapeHTML(q.client_alias || q.client_ip)}</td>
                    <td><span class="badge ${isBlk ? 'danger' : 'success'}">${helpers.escapeHTML(q.status)}</span></td>
                </tr>`;
            }).join('');
        }
    } catch {
        // Ignore transient refresh error on wall display
    }
}

export function startWallMode() {
    stopWallMode();
    document.body.classList.add('wall-fullscreen');
    refreshWallView();
    wallTimer = setInterval(refreshWallView, 5000);
}

export function stopWallMode() {
    document.body.classList.remove('wall-fullscreen');
    if (wallTimer) {
        clearInterval(wallTimer);
        wallTimer = null;
    }
}

// Expose global bindings for HTML handlers
window.runExplainQuery = runExplainQuery;
window.runRuleSimulation = runRuleSimulation;
window.saveServicesSelection = saveServicesSelection;
window.acknowledgeAnomaly = acknowledgeAnomaly;
window.muteAnomaly = muteAnomaly;
window.applyAgentPlan = applyAgentPlan;
window.discardAgentPlan = discardAgentPlan;
window.downloadSupportPackage = downloadSupportPackage;
window.openAgentPlansModal = () => {
    loadAgentPlans();
    getEl('agent-plans-modal')?.classList.remove('hidden');
};
window.closeAgentPlansModal = () => {
    getEl('agent-plans-modal')?.classList.add('hidden');
};
