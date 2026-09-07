/**
 * Cluster & Multi-Node UI Handlers
 */
import { getEl } from '../core/state.js';
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import * as fetchService from '../services/fetch.js';

export function initClusterUI() {
    // Revoke replica
    window.revokeClusterReplica = async (replicaId) => {
        if (!confirm('Are you sure you want to disconnect this replica? It will no longer receive synchronized updates.')) return;
        try {
            await api.apiFetch(`${api.endpoints.clusterRevokeReplica}?id=${encodeURIComponent(replicaId)}`, { method: 'POST' });
            helpers.showToast('Replica disconnected');
            fetchService.fetchClusterStatus();
        } catch (err) {
            helpers.showAlert('Failed to revoke replica: ' + err.message);
        }
    };

    // Manual Sync button
    getEl('cluster-manual-sync-btn')?.addEventListener('click', async (e) => {
        const btn = e.currentTarget;
        helpers.setBtnLoading(btn, true, 'Syncing...');
        try {
            const res = await api.apiFetch(api.endpoints.clusterSync, { method: 'POST' });
            helpers.showToast(res.message || 'Configuration synced successfully');
            await fetchService.fetchConfig();
        } catch (err) {
            helpers.showAlert('Sync failed: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    // Leave Cluster button
    getEl('cluster-leave-btn')?.addEventListener('click', async (e) => {
        if (!confirm('Disconnect from Cluster and revert to Standalone node?')) return;
        const btn = e.currentTarget;
        helpers.setBtnLoading(btn, true, 'Leaving...');
        try {
            await api.apiFetch(api.endpoints.clusterLeave, { method: 'POST' });
            helpers.showToast('Node reverted to Standalone');
            await fetchService.fetchConfig();
        } catch (err) {
            helpers.showAlert('Failed to leave cluster: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    // Save profile on form changes
    const saveClusterProfile = async () => {
        const role = getEl('cluster-role-select')?.value;
        const instType = getEl('cluster-inst-type-select')?.value;
        const nodeName = getEl('cluster-node-name-input')?.value;
        const logSharing = getEl('cluster-log-sharing-select')?.value;
        const workerDomain = getEl('cluster-worker-domain-input')?.value;
        const failover = getEl('cluster-failover-check')?.checked;
        const syncInt = parseInt(getEl('cluster-sync-interval')?.value || '0', 10);
        try {
            await api.apiFetch(api.endpoints.clusterSettings, {
                method: 'POST',
                body: JSON.stringify({
                    role,
                    instance_type: instType,
                    node_name: nodeName,
                    log_sharing_mode: logSharing,
                    worker_domain: workerDomain,
                    failover_mode: failover,
                    sync_interval: syncInt
                })
            });
            helpers.showToast('Cluster settings saved');
            fetchService.fetchClusterStatus();
        } catch (err) {
            helpers.showAlert('Failed to save cluster settings: ' + err.message);
        }
    };

    getEl('cluster-role-select')?.addEventListener('change', saveClusterProfile);
    getEl('cluster-inst-type-select')?.addEventListener('change', saveClusterProfile);
    getEl('cluster-node-name-input')?.addEventListener('blur', saveClusterProfile);
    getEl('cluster-worker-domain-input')?.addEventListener('blur', saveClusterProfile);
    getEl('cluster-sync-interval')?.addEventListener('change', saveClusterProfile);

    // Generate and view prefilled Cloudflare Worker Script
    getEl('cluster-worker-generate-btn')?.addEventListener('click', async (e) => {
        const btn = e.currentTarget;
        helpers.setBtnLoading(btn, true, 'Generating...');
        try {
            const resp = await fetch(api.endpoints.clusterWorkerScript, {
                headers: {
                    'X-Shield-Request': 'true'
                }
            });
            if (!resp.ok) {
                const txt = await resp.text();
                throw new Error(txt || `Server error: ${resp.status}`);
            }
            const script = await resp.text();
            const textarea = getEl('worker-script-code');
            if (textarea) textarea.value = script;
            getEl('worker-script-modal')?.classList.remove('hidden');
        } catch (err) {
            helpers.showAlert('Failed to generate Cloudflare Worker script: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('worker-script-close-x')?.addEventListener('click', () => {
        getEl('worker-script-modal')?.classList.add('hidden');
    });

    getEl('worker-script-copy-btn')?.addEventListener('click', () => {
        const script = getEl('worker-script-code')?.value;
        if (!script) return;
        navigator.clipboard.writeText(script);
        helpers.showToast('Cloudflare Worker script copied to clipboard!');
    });

    getEl('worker-script-download-btn')?.addEventListener('click', () => {
        const script = getEl('worker-script-code')?.value;
        if (!script) return;
        const blob = new Blob([script], { type: 'application/javascript;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'worker.js';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        helpers.showToast('Downloaded worker.js');
    });
}
