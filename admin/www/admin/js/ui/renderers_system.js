/**
 * System Diagnostics, About & Cluster Status Renderers
 */
import { state, getEl } from '../core/state.js';
import * as helpers from './helpers.js';

export function renderDiagnostics(d) {
    if (getEl('diag-cpu-load')) {
        const load = d.cpu_load ? d.cpu_load.map(n => {
            const val = parseFloat(n);
            return isNaN(val) ? '0.00' : val.toFixed(2);
        }).join(', ') : '0.00, 0.00, 0.00';
        getEl('diag-cpu-load').textContent = load;
    }
    if (getEl('diag-cpu-model')) {
        const model = d.cpu_model || '';
        getEl('diag-cpu-model').textContent = (model == '0' || !model) ? 'Standard CPU' : model;
    }

    if (d.ram && d.ram.total > 0) {
        const used = (d.ram.used / 1024).toFixed(0);
        const total = (d.ram.total / 1024).toFixed(0);
        const pct = (d.ram.used / d.ram.total * 100).toFixed(1);
        if (getEl('diag-ram-usage')) getEl('diag-ram-usage').textContent = `${used} / ${total} MB (${pct}%)`;
        const bar = getEl('diag-ram-bar');
        if (bar) bar.style.width = pct + '%';
    }

    if (d.disk && d.disk.total > 0) {
        const used = (d.disk.used / 1024 / 1024 / 1024).toFixed(1);
        const total = (d.disk.total / 1024 / 1024 / 1024).toFixed(1);
        const pct = (d.disk.used / d.disk.total * 100).toFixed(1);
        if (getEl('diag-disk-usage')) getEl('diag-disk-usage').textContent = `${used} / ${total} GB (${pct}%)`;
        const bar = getEl('diag-disk-bar');
        if (bar) bar.style.width = pct + '%';
    }

    if (getEl('diag-uptime')) {
        const up = d.uptime_seconds || 0;
        const d_time = Math.floor(up / 86400);
        const h = Math.floor((up % 86400) / 3600);
        const m = Math.floor((up % 3600) / 60);
        const s = up % 60;
        let uptimeStr = `${h.toString().padStart(2, '0')}h ${m.toString().padStart(2, '0')}m ${s.toString().padStart(2, '0')}s`;
        if (d_time > 0) {
            uptimeStr = `${d_time}d ` + uptimeStr;
        }
        getEl('diag-uptime').textContent = uptimeStr;
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

export function renderAboutData(stats, contributors) {
    const codeBody = getEl('about-stats-code-body');
    if (codeBody && stats && stats.code) {
        const c = stats.code;
        codeBody.innerHTML = `
            <tr>
                <td><strong>Backend (Go)</strong></td>
                <td style="text-align: right;">${(c.backend.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(c.backend.lines || 0).toLocaleString()}</td>
            </tr>
            <tr>
                <td><strong>Frontend (Admin UI)</strong></td>
                <td style="text-align: right;">${(c.frontend.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(c.frontend.lines || 0).toLocaleString()}</td>
            </tr>
            <tr>
                <td><strong>Other</strong></td>
                <td style="text-align: right;">${(c.other.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(c.other.lines || 0).toLocaleString()}</td>
            </tr>
            <tr style="border-top: 1px solid rgba(255,255,255,0.1); font-weight: bold; color: var(--color-primary);">
                <td>Total</td>
                <td style="text-align: right;">${(c.total.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(c.total.lines || 0).toLocaleString()}</td>
            </tr>
        `;
    }

    const testsBody = getEl('about-stats-tests-body');
    if (testsBody && stats && stats.tests) {
        const t = stats.tests;
        testsBody.innerHTML = `
            <tr>
                <td><strong>Backend (Go Tests)</strong></td>
                <td style="text-align: right;">${(t.backend.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(t.backend.tests || 0).toLocaleString()}</td>
            </tr>
            <tr>
                <td><strong>Frontend (UI Tests)</strong></td>
                <td style="text-align: right;">${(t.frontend.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(t.frontend.tests || 0).toLocaleString()}</td>
            </tr>
            <tr style="border-top: 1px solid rgba(255,255,255,0.1); font-weight: bold; color: var(--color-primary);">
                <td>Total</td>
                <td style="text-align: right;">${(t.total.files || 0).toLocaleString()}</td>
                <td style="text-align: right;">${(t.total.tests || 0).toLocaleString()}</td>
            </tr>
        `;
    }

    const generatedEl = getEl('about-stats-generated');
    if (generatedEl && stats && stats.generated_at) {
        const date = new Date(stats.generated_at);
        generatedEl.textContent = `Stats generated: ${date.toLocaleString()}`;
    }
    const commitEl = getEl('about-stats-commit');
    if (commitEl && stats && stats.commit_id && stats.commit_id !== 'unknown') {
        commitEl.innerHTML = `Commit: <a href="https://github.com/FaserF/ShieldDNS/commit/${stats.commit_id}" target="_blank" style="color: var(--color-primary); font-family: monospace;">${stats.commit_id}</a>`;
    }

    const contribBody = getEl('about-contributors-body');
    if (contribBody) {
        if (contributors && contributors.length > 0) {
            contribBody.innerHTML = contributors.map(c => `
                <tr>
                    <td>
                        ${c.profile_url ? `
                            <a href="${c.profile_url}" target="_blank" style="color: var(--color-primary); display: inline-flex; align-items: center; gap: 6px;">
                                <strong>${helpers.escapeHTML(c.username)}</strong>
                                ${c.is_bot ? `<span style="font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.05); color: var(--text-muted);">Bot</span>` : ''}
                                <i class="fas fa-external-link-alt" style="font-size: 0.65rem; opacity: 0.7;"></i>
                            </a>
                        ` : `
                            <span style="display: inline-flex; align-items: center; gap: 6px;">
                                <strong>${helpers.escapeHTML(c.username)}</strong>
                                ${c.is_bot ? `<span style="font-size: 0.7rem; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.05); color: var(--text-muted);">Bot</span>` : ''}
                            </span>
                        `}
                    </td>
                    <td style="font-family: monospace; color: var(--text-muted);">${c.last_commit_date || 'N/A'}</td>
                    <td style="text-align: right; font-family: monospace;">${(c.commit_count || 0).toLocaleString()}</td>
                </tr>
            `).join('');
        } else {
            contribBody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted);">No contributor data available.</td></tr>';
        }
    }
}

export function renderClusterStatus(cluster) {
    if (!cluster) return;

    const roleSelect = getEl('cluster-role-select');
    if (roleSelect && cluster.role) roleSelect.value = cluster.role;

    const instSelect = getEl('cluster-inst-type-select');
    if (instSelect && cluster.instance_type) instSelect.value = cluster.instance_type;

    const nodeNameInput = getEl('cluster-node-name-input');
    if (nodeNameInput && cluster.node_name !== undefined) nodeNameInput.value = cluster.node_name;

    const logSharingSelect = getEl('cluster-log-sharing-select');
    if (logSharingSelect && cluster.log_sharing_mode) logSharingSelect.value = cluster.log_sharing_mode;

    const workerInput = getEl('cluster-worker-domain-input');
    if (workerInput && cluster.worker_domain !== undefined) workerInput.value = cluster.worker_domain;

    const isReplica = cluster.role === 'replica';
    const pwdForm = getEl('password-form');
    let pwdBanner = getEl('replica-pwd-banner');
    if (pwdForm) {
        const inputs = pwdForm.querySelectorAll('input, button');
        inputs.forEach(el => el.disabled = isReplica);
        if (isReplica) {
            if (!pwdBanner) {
                pwdBanner = document.createElement('div');
                pwdBanner.id = 'replica-pwd-banner';
                pwdBanner.style.cssText = 'background: rgba(59, 130, 246, 0.1); border-left: 4px solid var(--accent); padding: 10px 14px; margin-bottom: 15px; border-radius: 4px; font-size: 0.85rem; color: var(--text-primary);';
                pwdBanner.innerHTML = '<strong>Managed by Primary:</strong> Administrator password is centrally managed on the Primary node and synchronized automatically.';
                pwdForm.parentNode.insertBefore(pwdBanner, pwdForm);
            }
        } else if (pwdBanner) {
            pwdBanner.remove();
        }
    }

    const mfaStatusContainer = getEl('mfa-status-container');
    const mfaSetupArea = getEl('mfa-setup-area');
    let mfaBanner = getEl('replica-mfa-banner');
    if (mfaStatusContainer) {
        const mfaBtns = mfaStatusContainer.querySelectorAll('button');
        mfaBtns.forEach(el => el.disabled = isReplica);
        if (isReplica) {
            if (mfaSetupArea) mfaSetupArea.classList.add('hidden');
            if (!mfaBanner) {
                mfaBanner = document.createElement('div');
                mfaBanner.id = 'replica-mfa-banner';
                mfaBanner.style.cssText = 'background: rgba(59, 130, 246, 0.1); border-left: 4px solid var(--accent); padding: 10px 14px; margin-top: 15px; border-radius: 4px; font-size: 0.85rem; color: var(--text-primary);';
                mfaBanner.innerHTML = '<strong>Managed by Primary:</strong> Multi-Factor Authentication credentials are synchronized from the Primary node. Setup and modifications are disabled on replicas.';
                mfaStatusContainer.parentNode.insertBefore(mfaBanner, mfaStatusContainer.nextSibling);
            }
        } else if (mfaBanner) {
            mfaBanner.remove();
        }
    }

    const primaryPanel = getEl('cluster-primary-panel');
    const replicaPanel = getEl('cluster-replica-panel');
    const warningBanner = getEl('cluster-warning-banner');

    if (primaryPanel) primaryPanel.classList.toggle('hidden', cluster.role !== 'primary');
    if (replicaPanel) replicaPanel.classList.toggle('hidden', cluster.role !== 'replica');

    if (warningBanner) {
        if (cluster.role === 'replica' && cluster.connection_lost) {
            warningBanner.classList.remove('hidden');
            const msgEl = getEl('cluster-warning-msg');
            if (msgEl) {
                msgEl.textContent = cluster.last_sync_error ?
                    `Error: ${cluster.last_sync_error}. Using cached settings and offline credentials.` :
                    'Primary node unreachable. Using cached settings and offline credentials.';
            }
        } else {
            warningBanner.classList.add('hidden');
        }
    }

    if (cluster.role === 'replica') {
        const urlInput = getEl('cluster-primary-url-input');
        if (urlInput && cluster.primary_url) urlInput.value = cluster.primary_url;

        const failoverCheck = getEl('cluster-failover-check');
        if (failoverCheck) failoverCheck.checked = !!cluster.failover_mode;

        const syncSelect = getEl('cluster-sync-interval');
        if (syncSelect) syncSelect.value = String(cluster.sync_interval || 0);

        const statusText = getEl('cluster-sync-status');
        if (statusText) {
            if (cluster.last_sync && cluster.last_sync !== '0001-01-01T00:00:00Z') {
                const date = new Date(cluster.last_sync);
                statusText.textContent = `Last sync: ${date.toLocaleTimeString()} ${date.toLocaleDateString()}`;
            } else {
                statusText.textContent = 'Not yet synced';
            }
        }
    }

    if (cluster.role === 'primary') {
        const listContainer = getEl('cluster-replicas-list');
        if (listContainer) {
            const reps = cluster.replicas || [];
            if (reps.length === 0) {
                listContainer.innerHTML = '<div class="help">No replicas connected yet.</div>';
            } else {
                listContainer.innerHTML = reps.map(rep => {
                    const lastSeen = rep.last_seen ? new Date(rep.last_seen).toLocaleString() : 'Never';
                    const isOnline = rep.last_seen && (Date.now() - new Date(rep.last_seen).getTime() < 10 * 60 * 1000);
                    return `
                        <div style="display:flex; align-items:center; justify-content:space-between; padding:10px 12px; background:var(--card-bg); border:1px solid var(--border); border-radius:6px; margin-bottom:8px;">
                            <div>
                                <div style="font-weight:600; display:flex; align-items:center; gap:8px;">
                                    <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:${isOnline ? '#22c55e' : '#eab308'};"></span>
                                    ${helpers.escapeHTML(rep.name)}
                                    <span style="font-size:0.75rem; padding:2px 6px; border-radius:4px; background:rgba(255,255,255,0.06); text-transform:uppercase;">${rep.instance_type}</span>
                                </div>
                                <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:2px;">
                                    ${helpers.escapeHTML(rep.url || 'No URL')} &bull; Last seen: ${lastSeen}
                                </div>
                            </div>
                            <button type="button" class="btn btn-sm danger" onclick="window.revokeClusterReplica('${rep.id}')">Revoke</button>
                        </div>
                    `;
                }).join('');
            }
        }
    }
}
