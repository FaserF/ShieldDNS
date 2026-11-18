/**
 * Extended Policy, Observability, Privacy/Audit, SIEM, and Cluster Ops UI
 */
import * as api from '../services/api.js';

function esc(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// =========================================================================
// 1. Extended Analytics (Flow, SLO, 7x24 Rhythm Heatmap, Latency Heatmap)
// =========================================================================

export async function loadExtendedAnalytics() {
    await Promise.allSettled([
        loadFlowChart(),
        loadSLOCard(),
        loadRhythmHeatmap(),
        loadLatencyHeatmap()
    ]);
}

async function loadFlowChart() {
    const el = document.getElementById('flow-diagram-container');
    if (!el) return;
    try {
        const data = await api.apiFetch(api.endpoints.statsFlow);
        const links = data.links || [];
        if (links.length === 0) {
            el.innerHTML = '<p class="help">No query flow data recorded yet.</p>';
            return;
        }
        const maxVal = Math.max(...links.map(l => l.value), 1);
        el.innerHTML = links.slice(0, 15).map(l => {
            const pct = Math.max(6, Math.round((l.value / maxVal) * 100));
            return `<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;font-size:0.85rem;">
                <span style="min-width:130px;color:var(--text-secondary);">${esc(l.source)}</span>
                <span style="color:var(--accent);">→</span>
                <span style="min-width:130px;">${esc(l.target)}</span>
                <div style="flex:1;background:rgba(255,255,255,0.06);border-radius:4px;height:10px;overflow:hidden;">
                    <div style="width:${pct}%;height:100%;background:var(--accent);"></div>
                </div>
                <span style="min-width:45px;text-align:right;font-variant-numeric:tabular-nums;">${l.value}</span>
            </div>`;
        }).join('');
    } catch (e) {
        el.innerHTML = `<p class="help">Failed to load flow: ${esc(e.message)}</p>`;
    }
}

async function loadSLOCard() {
    const el = document.getElementById('slo-budget-container');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.statsSLO);
        const avail = (d.actual_availability_pct ?? 100).toFixed(3);
        const target = (d.target_availability_pct ?? 99.9).toFixed(2);
        const burn = (d.burn_rate ?? 0).toFixed(2);
        const badgeCls = d.burn_rate > 2 ? 'danger' : (d.burn_rate > 1 ? 'warning' : 'success');
        const clients = (d.top_offender_clients || []).map(c => `${esc(c.name)} (${c.count})`).join(', ') || 'None';
        const domains = (d.top_offender_domains || []).map(c => `${esc(c.name)} (${c.count})`).join(', ') || 'None';
        el.innerHTML = `
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:12px;">
                <div class="diag-item"><span>Availability</span><strong>${avail}% / ${target}%</strong></div>
                <div class="diag-item"><span>Burn Rate</span><span class="badge ${badgeCls}">${burn}x</span></div>
                <div class="diag-item"><span>Slow (&gt;${d.target_latency_ms}ms)</span><strong>${d.slow_queries || 0}</strong></div>
                <div class="diag-item"><span>Errors</span><strong>${d.error_queries || 0}</strong></div>
            </div>
            <div style="font-size:0.82rem;color:var(--text-secondary);">
                <div><strong>Top Budget Clients:</strong> ${clients}</div>
                <div><strong>Top Budget Domains:</strong> ${domains}</div>
            </div>`;
    } catch (e) {
        el.innerHTML = `<p class="help">Failed to load SLO: ${esc(e.message)}</p>`;
    }
}

async function loadRhythmHeatmap() {
    const el = document.getElementById('rhythm-heatmap-container');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.statsHeatmap);
        const days = d.days || ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        const mat = d.total || [];
        let maxVal = 1;
        for (const row of mat) for (const v of row) if (v > maxVal) maxVal = v;
        let html = '<div style="display:grid;grid-template-columns:42px repeat(24,1fr);gap:2px;font-size:0.7rem;">';
        html += '<div></div>' + Array.from({ length: 24 }, (_, h) => `<div style="text-align:center;color:var(--text-secondary);">${h}</div>`).join('');
        days.forEach((day, di) => {
            html += `<div style="color:var(--text-secondary);display:flex;align-items:center;">${day}</div>`;
            for (let hr = 0; hr < 24; hr++) {
                const v = (mat[di] && mat[di][hr]) || 0;
                const alpha = v === 0 ? 0.06 : Math.min(1, 0.2 + (v / maxVal) * 0.8);
                html += `<div title="${day} ${hr}:00 — ${v} queries" style="height:16px;border-radius:2px;background:rgba(56,189,248,${alpha.toFixed(2)});"></div>`;
            }
        });
        html += '</div>';
        el.innerHTML = html;
    } catch (e) {
        el.innerHTML = `<p class="help">Failed to load heatmap: ${esc(e.message)}</p>`;
    }
}

async function loadLatencyHeatmap() {
    const el = document.getElementById('latency-heatmap-container');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.statsLatencyHeatmap);
        const buckets = d.buckets || [];
        const series = d.series || [];
        if (series.length === 0) {
            el.innerHTML = '<p class="help">No latency distribution samples yet.</p>';
            return;
        }
        const totals = new Array(buckets.length).fill(0);
        for (const s of series) {
            (s.counts || []).forEach((c, i) => { totals[i] += c; });
        }
        const maxVal = Math.max(...totals, 1);
        el.innerHTML = '<div style="display:flex;align-items:flex-end;gap:4px;height:110px;padding-top:10px;">' +
            buckets.map((lbl, i) => {
                const h = Math.max(4, Math.round((totals[i] / maxVal) * 90));
                return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;" title="${esc(lbl)}: ${totals[i]}">
                    <div style="width:100%;height:${h}px;background:var(--accent);border-radius:3px 3px 0 0;"></div>
                    <span style="font-size:0.62rem;color:var(--text-secondary);writing-mode:vertical-rl;transform:rotate(180deg);">${esc(lbl)}</span>
                </div>`;
            }).join('') + '</div>';
    } catch (e) {
        el.innerHTML = `<p class="help">Failed to load latency heatmap: ${esc(e.message)}</p>`;
    }
}

// =========================================================================
// 2. Policy Extensions (Groups, Schedules, Typed Local Records, Quick Rules)
// =========================================================================

export async function loadPolicyExtensions() {
    await Promise.allSettled([
        loadGroupsList(),
        loadSchedulesList(),
        loadLocalRecordsList(),
        loadQuickRulesList()
    ]);
}

async function loadGroupsList() {
    const el = document.getElementById('groups-list');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.groups);
        const groups = d.groups || [];
        if (groups.length === 0) {
            el.innerHTML = '<p class="help">No client groups configured.</p>';
            return;
        }
        el.innerHTML = groups.map(g => `<div class="diag-item">
            <div><strong>${esc(g.name)}</strong> <span class="help">(${esc((g.members || []).join(', '))})</span></div>
            <button class="btn btn-sm danger" onclick="deleteGroup('${esc(g.id)}')">Delete</button>
        </div>`).join('');
    } catch (e) { el.innerHTML = `<p class="help">${esc(e.message)}</p>`; }
}

async function loadSchedulesList() {
    const el = document.getElementById('schedules-list');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.schedules);
        const items = d.schedules || [];
        if (items.length === 0) {
            el.innerHTML = '<p class="help">No schedules configured.</p>';
            return;
        }
        el.innerHTML = items.map(s => `<div class="diag-item">
            <div><strong>${esc(s.name)}</strong> <span class="help">${esc(s.start_time)}–${esc(s.end_time)} (${esc(s.action)})</span></div>
            <button class="btn btn-sm danger" onclick="deleteSchedule('${esc(s.id)}')">Delete</button>
        </div>`).join('');
    } catch (e) { el.innerHTML = `<p class="help">${esc(e.message)}</p>`; }
}

async function loadLocalRecordsList() {
    const el = document.getElementById('local-records-list');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.localRecords);
        const items = d.records || [];
        if (items.length === 0) {
            el.innerHTML = '<p class="help">No typed local DNS records configured.</p>';
            return;
        }
        el.innerHTML = items.map(r => `<div class="diag-item">
            <div><span class="badge official">${esc(r.type)}</span> <strong>${esc(r.domain)}</strong> → <code>${esc(r.value)}</code></div>
            <button class="btn btn-sm danger" onclick="deleteLocalRecord('${esc(r.id)}')">Delete</button>
        </div>`).join('');
    } catch (e) { el.innerHTML = `<p class="help">${esc(e.message)}</p>`; }
}

async function loadQuickRulesList() {
    const el = document.getElementById('quick-rules-list');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.quickRules);
        const items = d.rules || [];
        if (items.length === 0) {
            el.innerHTML = '<p class="help">No active quick/regex rules.</p>';
            return;
        }
        el.innerHTML = items.map(r => `<div class="diag-item">
            <div><span class="badge ${r.is_allowlist ? 'success' : 'danger'}">${r.is_allowlist ? 'ALLOW' : 'BLOCK'}</span> <code>${esc(r.domain)}</code> ${r.expires_at ? `<span class="help">(expires ${new Date(r.expires_at).toLocaleTimeString()})</span>` : ''}</div>
            <button class="btn btn-sm danger" onclick="deleteQuickRule('${esc(r.id)}')">Delete</button>
        </div>`).join('');
    } catch (e) { el.innerHTML = `<p class="help">${esc(e.message)}</p>`; }
}

// =========================================================================
// 3. Privacy Levels & Audit Log
// =========================================================================

export async function loadPrivacyAndAudit() {
    try {
        const cfg = await api.apiFetch(api.endpoints.config);
        const sel = document.getElementById('privacy-level-select');
        if (sel && typeof cfg.privacy_level === 'number') {
            sel.value = String(cfg.privacy_level);
        }
    } catch (_) {}

    const el = document.getElementById('audit-log-tbody');
    if (!el) return;
    try {
        const d = await api.apiFetch(api.endpoints.auditLog + '?limit=50');
        const entries = d.entries || [];
        if (entries.length === 0) {
            el.innerHTML = '<tr><td colspan="5" class="help">No audit entries recorded yet.</td></tr>';
            return;
        }
        el.innerHTML = entries.map(e => `<tr>
            <td>${e.seq}</td>
            <td>${esc(new Date(e.timestamp).toLocaleString())}</td>
            <td>${esc(e.actor)} (${esc(e.remote_ip)})</td>
            <td><code>${esc(e.action)}</code></td>
            <td>${esc(e.target)} ${e.detail ? `<span class="help">— ${esc(e.detail)}</span>` : ''}</td>
        </tr>`).join('');
    } catch (e) {
        el.innerHTML = `<tr><td colspan="5" class="help">${esc(e.message)}</td></tr>`;
    }
}

// =========================================================================
// 4. Cluster Maintenance, Node Comparison & SIEM/Webhook UI
// =========================================================================

export async function loadClusterAndSIEM() {
    try {
        const m = await api.apiFetch(api.endpoints.clusterMaintenance);
        const chk = document.getElementById('cluster-maintenance-toggle');
        const rsn = document.getElementById('cluster-maintenance-reason');
        if (chk) chk.checked = !!m.maintenance_mode;
        if (rsn && m.maintenance_reason) rsn.value = m.maintenance_reason;
    } catch (_) {}

    const cmpEl = document.getElementById('cluster-compare-tbody');
    if (cmpEl) {
        try {
            const c = await api.apiFetch(api.endpoints.clusterCompare);
            const nodes = c.nodes || [];
            cmpEl.innerHTML = nodes.map(n => `<tr>
                <td><strong>${esc(n.node_name)}</strong> ${n.outlier ? '<span class="badge danger">Outlier</span>' : ''}</td>
                <td>${esc(n.role)}</td>
                <td>${n.total_queries}</td>
                <td>${(n.blocked_pct || 0).toFixed(1)}%</td>
                <td>${(n.cache_hit_pct || 0).toFixed(1)}%</td>
                <td>${(n.avg_latency_ms || 0).toFixed(2)} ms</td>
                <td><span class="badge ${n.maintenance ? 'warning' : (n.online ? 'success' : 'danger')}">${n.maintenance ? 'Maintenance' : (n.online ? 'Online' : 'Offline')}</span></td>
            </tr>`).join('');
        } catch (_) {}
    }

    try {
        const cfg = await api.apiFetch(api.endpoints.config);
        const whEn = document.getElementById('webhook-enabled-check');
        const whUrl = document.getElementById('webhook-url-input');
        const otlp = document.getElementById('otlp-endpoint-input');
        if (whEn) whEn.checked = !!cfg.webhook_enabled;
        if (whUrl) whUrl.value = cfg.webhook_url || '';
        if (otlp) otlp.value = cfg.otlp_endpoint || '';
    } catch (_) {}
}

// Expose global handlers for inline onclick buttons
window.addClientGroup = async () => {
    const name = document.getElementById('group-name-input')?.value?.trim();
    const members = (document.getElementById('group-members-input')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    const scheduleIds = (document.getElementById('group-schedules-input')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!name) return;
    await api.apiFetch(api.endpoints.groups, { method: 'POST', body: JSON.stringify({ name, members, schedule_ids: scheduleIds }) });
    loadGroupsList();
};
window.deleteGroup = async (id) => {
    await api.apiFetch(api.endpoints.groups + '?id=' + encodeURIComponent(id), { method: 'DELETE' });
    loadGroupsList();
};
window.addScheduleRule = async () => {
    const name = document.getElementById('sched-name-input')?.value?.trim();
    const start_time = document.getElementById('sched-start-input')?.value?.trim();
    const end_time = document.getElementById('sched-end-input')?.value?.trim();
    const action = document.getElementById('sched-action-select')?.value || 'block_all';
    if (!name || !start_time || !end_time) return;
    await api.apiFetch(api.endpoints.schedules, { method: 'POST', body: JSON.stringify({ name, start_time, end_time, action, enabled: true, timezone: 'Local' }) });
    loadSchedulesList();
};
window.deleteSchedule = async (id) => {
    await api.apiFetch(api.endpoints.schedules + '?id=' + encodeURIComponent(id), { method: 'DELETE' });
    loadSchedulesList();
};
window.addLocalRecord = async () => {
    const type = document.getElementById('local-rec-type')?.value || 'A';
    const domain = document.getElementById('local-rec-domain')?.value?.trim();
    const value = document.getElementById('local-rec-value')?.value?.trim();
    if (!domain || !value) return;
    await api.apiFetch(api.endpoints.localRecords, { method: 'POST', body: JSON.stringify({ type, domain, value }) });
    loadLocalRecordsList();
};
window.deleteLocalRecord = async (id) => {
    await api.apiFetch(api.endpoints.localRecords + '?id=' + encodeURIComponent(id), { method: 'DELETE' });
    loadLocalRecordsList();
};
window.addQuickRule = async () => {
    const domain = document.getElementById('quick-rule-domain')?.value?.trim();
    const is_allowlist = document.getElementById('quick-rule-allow')?.value === 'true';
    const ttl_minutes = parseInt(document.getElementById('quick-rule-ttl')?.value || '0', 10) || 0;
    if (!domain) return;
    await api.apiFetch(api.endpoints.quickRules, { method: 'POST', body: JSON.stringify({ domain, is_allowlist, ttl_minutes }) });
    loadQuickRulesList();
};
window.deleteQuickRule = async (id) => {
    await api.apiFetch(api.endpoints.quickRules + '?id=' + encodeURIComponent(id), { method: 'DELETE' });
    loadQuickRulesList();
};
window.savePrivacyLevel = async () => {
    const lvl = parseInt(document.getElementById('privacy-level-select')?.value || '0', 10);
    await api.apiFetch(api.endpoints.config, { method: 'POST', body: JSON.stringify({ privacy_level: lvl }) });
};
window.verifyAuditChainUI = async () => {
    const badge = document.getElementById('audit-verify-badge');
    const res = await api.apiFetch(api.endpoints.auditVerify);
    if (badge) {
        badge.className = 'badge ' + (res.valid ? 'success' : 'danger');
        badge.textContent = res.valid ? `Valid (${res.entries} entries)` : `Tampered: ${res.error}`;
    }
};
window.saveClusterMaintenance = async () => {
    const enabled = !!document.getElementById('cluster-maintenance-toggle')?.checked;
    const reason = document.getElementById('cluster-maintenance-reason')?.value?.trim() || '';
    await api.apiFetch(api.endpoints.clusterMaintenance, { method: 'POST', body: JSON.stringify({ enabled, reason }) });
    loadClusterAndSIEM();
};
window.saveWebhookAndOTLP = async () => {
    const webhook_enabled = !!document.getElementById('webhook-enabled-check')?.checked;
    const webhook_url = document.getElementById('webhook-url-input')?.value?.trim() || '';
    const otlp_endpoint = document.getElementById('otlp-endpoint-input')?.value?.trim() || '';
    await api.apiFetch(api.endpoints.config, { method: 'POST', body: JSON.stringify({ webhook_enabled, webhook_url, otlp_endpoint }) });
};
