/**
 * API Key Management Event Listeners & Modals
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import * as fetchService from '../services/fetch.js';

export function initAPIKeyEvents() {
    // API Key creation
    getEl('create-api-key-btn')?.addEventListener('click', () => {
        const modal = getEl('api-key-modal');
        const form = getEl('api-key-form');
        const result = getEl('api-key-result');
        if (!modal || !form || !result) return;
        getEl('api-key-modal-title').textContent = 'Generate API Key';
        getEl('api-key-name').value = '';
        getEl('save-api-key-btn').textContent = 'Generate';
        delete getEl('save-api-key-btn').dataset.editId;
        setPerms(['perm-stats', 'perm-health']);
        form.classList.remove('hidden');
        result.classList.add('hidden');
        modal.classList.remove('hidden');
    });

    getEl('save-api-key-btn')?.addEventListener('click', async (e) => {
        const btn = e.target;
        const name = getEl('api-key-name').value.trim();
        if (!name) return helpers.showToast('Please enter a name for the API key', 'info');

        const perms = [];
        if (getEl('perm-admin').checked) perms.push('admin:all');
        if (getEl('perm-stats').checked) perms.push('read:stats');
        if (getEl('perm-logs').checked) perms.push('read:logs');
        if (getEl('perm-health').checked) perms.push('read:health');
        if (getEl('perm-config-read').checked) perms.push('read:config');
        if (getEl('perm-config-write').checked) perms.push('write:config');
        if (getEl('perm-diag').checked) perms.push('read:diagnostics');
        if (getEl('perm-rules-read').checked) perms.push('read:rules');
        if (getEl('perm-rules-write').checked) perms.push('write:rules');
        if (getEl('perm-maint').checked) perms.push('write:maintenance');
        if (getEl('perm-system').checked) perms.push('read:system');
        if (getEl('perm-mcp')?.checked) perms.push('exec:mcp');
        if (getEl('perm-cluster-sync')?.checked) perms.push('cluster:sync');
        if (getEl('perm-proxy-worker')?.checked) perms.push('proxy:worker');

        const currentEditId = getEl('save-api-key-btn').dataset.editId;
        const endpoint = currentEditId ? `${api.endpoints.createToken}?id=${currentEditId}` : api.endpoints.createToken;
        const method = currentEditId ? 'PUT' : 'POST';

        helpers.setBtnLoading(btn, true, currentEditId ? 'Updating...' : 'Generating...');
        try {
            const res = await api.apiFetch(endpoint, {
                method: method,
                body: JSON.stringify({ name, permissions: perms })
            });
            
            // The backend returns { token: "...", id: "..." } or similar
            if (res.token || currentEditId) {
                getEl('api-key-modal').classList.add('hidden');
                if (res.token) {
                    getEl('api-key-form').classList.add('hidden');
                    getEl('api-key-result').classList.remove('hidden');
                    getEl('api-key-value').textContent = res.token;
                    getEl('api-key-modal').classList.remove('hidden');
                }
                helpers.showToast(currentEditId ? 'API Key updated' : 'API Key generated!');
                // Immediate refresh of the table
                fetchService.fetchAPIKeys();
            } else {
                throw new Error('No token returned from server');
            }
        } catch (err) {
            helpers.showAlert('Failed to generate API Key: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('copy-api-key-btn')?.addEventListener('click', () => {
        const val = getEl('api-key-value').textContent;
        navigator.clipboard.writeText(val);
        helpers.showToast('Token copied to clipboard');
    });

    getEl('cancel-api-key-btn')?.addEventListener('click', () => getEl('api-key-modal')?.classList.add('hidden'));
    getEl('close-api-key-modal-btn')?.addEventListener('click', () => getEl('api-key-modal')?.classList.add('hidden'));

    // API Key Presets
    const setPerms = (perms) => {
        const ids = [
            'perm-admin', 'perm-cluster-sync', 'perm-proxy-worker', 'perm-stats', 'perm-logs', 'perm-health',
            'perm-config-read', 'perm-config-write', 'perm-diag',
            'perm-rules-read', 'perm-rules-write', 'perm-maint', 'perm-system', 'perm-mcp'
        ];
        ids.forEach(id => {
            const el = getEl(id);
            if (el) {
                el.checked = perms.includes(id);
            }
        });
        updatePermissionStates();
    };

    const updatePermissionStates = () => {
        const admin = getEl('perm-admin');
        const clusterSync = getEl('perm-cluster-sync');
        const proxyWorker = getEl('perm-proxy-worker');
        const stats = getEl('perm-stats');
        const logs = getEl('perm-logs');
        const health = getEl('perm-health');
        const configRead = getEl('perm-config-read');
        const configWrite = getEl('perm-config-write');
        const diag = getEl('perm-diag');
        const rulesRead = getEl('perm-rules-read');
        const rulesWrite = getEl('perm-rules-write');
        const maint = getEl('perm-maint');
        const system = getEl('perm-system');
        const mcp = getEl('perm-mcp');

        if (!admin) return;

        const allInputs = [
            clusterSync, proxyWorker, stats, logs, health, configRead, configWrite,
            diag, rulesRead, rulesWrite, maint, system, mcp
        ];

        // Reset state & clear custom visual highlighting classes
        allInputs.forEach(el => {
            if (el) {
                el.disabled = false;
                const parentItem = el.closest('.perm-item') || el.closest('.checkbox-group') || el.parentElement;
                if (parentItem) {
                    parentItem.style.opacity = '1';
                    parentItem.style.pointerEvents = 'auto';
                    parentItem.classList.remove('perm-included-locked', 'perm-disabled-locked');
                }
            }
        });

        // 1. Master admin:all overrides everything
        if (admin.checked) {
            allInputs.forEach(el => {
                if (el) {
                    el.checked = true;
                    el.disabled = true;
                    const parentItem = el.closest('.perm-item') || el.parentElement;
                    if (parentItem) {
                        parentItem.style.opacity = '0.7';
                        parentItem.classList.add('perm-included-locked');
                    }
                }
            });
            return;
        }

        // 2. Cloudflare Worker Dedicated Scope (Least Privilege: proxy:worker only)
        if (proxyWorker && proxyWorker.checked) {
            const excludedForWorker = [clusterSync, stats, logs, configRead, configWrite, diag, rulesRead, rulesWrite, maint, system, mcp];
            excludedForWorker.forEach(el => {
                if (el) {
                    el.checked = false;
                    el.disabled = true;
                    const item = el.closest('.perm-item') || el.parentElement;
                    if (item) {
                        item.style.opacity = '0.35';
                        item.style.background = 'transparent';
                        item.style.border = 'none';
                        item.style.padding = '0';
                    }
                }
            });
            if (health) {
                health.checked = true;
                health.disabled = true;
                const item = health.closest('.perm-item') || health.parentElement;
                if (item) {
                    item.style.opacity = '0.9';
                    item.style.background = 'rgba(243, 128, 32, 0.12)';
                    item.style.border = '1px solid rgba(243, 128, 32, 0.4)';
                    item.style.borderRadius = '4px';
                    item.style.padding = '4px 8px';
                }
            }
            return;
        }

        // 3. Cluster Sync Dedicated Scope:
        // Automatically locks out other rights. Required minimal permissions (read:config, read:health)
        // are pre-selected and highlighted as implicitly included & locked, while unrelated rights are greyed out.
        if (clusterSync && clusterSync.checked) {
            // Permissions that are included because needed for replication
            const includedForCluster = [configRead, health];
            includedForCluster.forEach(el => {
                if (el) {
                    el.checked = true;
                    el.disabled = true;
                    const item = el.closest('.perm-item') || el.parentElement;
                    if (item) {
                        item.style.opacity = '0.9';
                        item.style.background = 'rgba(59, 130, 246, 0.12)';
                        item.style.border = '1px solid rgba(59, 130, 246, 0.4)';
                        item.style.borderRadius = '4px';
                        item.style.padding = '4px 8px';
                    }
                }
            });

            // Permissions that are excluded & greyed out to enforce minimal privilege
            const excludedForCluster = [proxyWorker, stats, logs, configWrite, diag, rulesRead, rulesWrite, maint, system, mcp];
            excludedForCluster.forEach(el => {
                if (el) {
                    el.checked = false;
                    el.disabled = true;
                    const item = el.closest('.perm-item') || el.parentElement;
                    if (item) {
                        item.style.opacity = '0.35';
                        item.style.background = 'transparent';
                        item.style.border = 'none';
                        item.style.padding = '0';
                    }
                }
            });
            return;
        } else {
            // Clean up any inline highlight styling when cluster:sync / proxy:worker is unchecked
            [configRead, health, stats, logs, configWrite, diag, rulesRead, rulesWrite, maint, system, mcp].forEach(el => {
                if (el) {
                    const item = el.closest('.perm-item') || el.parentElement;
                    if (item) {
                        item.style.background = 'transparent';
                        item.style.border = 'none';
                        item.style.padding = '0';
                    }
                }
            });
        }

        if (configWrite && configWrite.checked) {
            if (configRead) {
                configRead.checked = true;
                configRead.disabled = true;
            }
        }

        if (rulesWrite && rulesWrite.checked) {
            if (rulesRead) {
                rulesRead.checked = true;
                rulesRead.disabled = true;
            }
        }

        const healthImplied =
            (stats && stats.checked) ||
            (system && system.checked) ||
            (diag && diag.checked) ||
            (configRead && configRead.checked) ||
            (configWrite && configWrite.checked);

        if (healthImplied) {
            if (health) {
                health.checked = true;
                health.disabled = true;
            }
        }
    };

    [
        'perm-admin', 'perm-cluster-sync', 'perm-proxy-worker', 'perm-stats', 'perm-logs', 'perm-health',
        'perm-config-read', 'perm-config-write', 'perm-diag',
        'perm-rules-read', 'perm-rules-write', 'perm-maint', 'perm-system', 'perm-mcp'
    ].forEach(id => {
        getEl(id)?.addEventListener('change', updatePermissionStates);
    });

    getEl('preset-cluster-btn')?.addEventListener('click', () => {
        setPerms(['perm-cluster-sync']);
        const keyName = getEl('api-key-name');
        if (keyName && !keyName.value.trim()) {
            keyName.value = 'Cluster Replica Token';
        }
    });

    getEl('preset-worker-btn')?.addEventListener('click', () => {
        setPerms(['perm-proxy-worker']);
        const keyName = getEl('api-key-name');
        if (keyName && !keyName.value.trim()) {
            keyName.value = 'Cloudflare Worker Dispatcher';
        }
    });

    getEl('preset-ha-btn')?.addEventListener('click', () => {
        setPerms(['perm-stats', 'perm-health', 'perm-config-read', 'perm-config-write', 'perm-rules-read', 'perm-rules-write']);
        const keyName = getEl('api-key-name');
        if (keyName && !keyName.value.trim()) {
            keyName.value = 'Home Assistant';
        }
    });

    getEl('preset-monitoring-btn')?.addEventListener('click', () => {
        setPerms(['perm-stats', 'perm-health', 'perm-diag', 'perm-system']);
        const keyName = getEl('api-key-name');
        if (keyName && !keyName.value.trim()) {
            keyName.value = 'Monitoring';
        }
    });

    getEl('preset-clear-btn')?.addEventListener('click', () => {
        setPerms([]);
    });

    getEl('mcp-copy-antigravity-config-btn')?.addEventListener('click', () => {
        const host = (state.currentConfig && state.currentConfig.admin_domain) ? `https://${state.currentConfig.admin_domain}` : (window.location.origin || 'https://shielddns.local');
        const cfg = JSON.stringify({
            mcpServers: {
                shielddns: {
                    url: `${host}/api/mcp?token=<YOUR_API_TOKEN>`
                }
            }
        }, null, 2);
        navigator.clipboard.writeText(cfg);
        helpers.showToast('Antigravity MCP configuration copied to clipboard!');
    });

    // API Key search
    getEl('api-keys-search')?.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const keys = state.allTokens || [];
        const filtered = keys.filter(k => k.name.toLowerCase().includes(query));
        import('./renderers.js').then(m => m.renderAPIKeys(filtered));
    });

    window.editAPIKey = (id) => {
        const key = state.allTokens?.find(k => k.id === id);
        if (!key) return;
        
        const modal = getEl('api-key-modal');
        const form = getEl('api-key-form');
        const result = getEl('api-key-result');
        const saveBtn = getEl('save-api-key-btn');
        
        if (!modal || !form || !result || !saveBtn) return;
        
        getEl('api-key-modal-title').textContent = 'Edit API Key';
        getEl('api-key-name').value = key.name;
        saveBtn.textContent = 'Update';
        saveBtn.dataset.editId = id;
        
        getEl('perm-admin').checked = key.permissions.includes('admin:all');
        getEl('perm-stats').checked = key.permissions.includes('read:stats');
        getEl('perm-logs').checked = key.permissions.includes('read:logs');
        getEl('perm-health').checked = key.permissions.includes('read:health');
        getEl('perm-config-read').checked = key.permissions.includes('read:config');
        getEl('perm-config-write').checked = key.permissions.includes('write:config');
        getEl('perm-diag').checked = key.permissions.includes('read:diagnostics');
        getEl('perm-rules-read').checked = key.permissions.includes('read:rules');
        getEl('perm-rules-write').checked = key.permissions.includes('write:rules');
        getEl('perm-maint').checked = key.permissions.includes('write:maintenance');
        getEl('perm-system').checked = key.permissions.includes('read:system');
        if (getEl('perm-mcp')) getEl('perm-mcp').checked = key.permissions.includes('exec:mcp');
        if (getEl('perm-cluster-sync')) getEl('perm-cluster-sync').checked = key.permissions.includes('cluster:sync');
        
        updatePermissionStates();
        
        form.classList.remove('hidden');
        result.classList.add('hidden');
        modal.classList.remove('hidden');
    };

    window.deleteAPIKey = async (id, event) => {
        if (!await helpers.showConfirm('Delete this API key forever?', 'Delete API Key', true)) return;
        const btn = event?.currentTarget;
        if (btn) helpers.setBtnLoading(btn, true, '');
        try {
            await api.apiFetch(`${api.endpoints.deleteToken}?id=${id}`, { 
                method: 'DELETE'
            });
            helpers.showToast('API Key deleted');
            fetchService.fetchAPIKeys();
        } catch (err) {
            helpers.showAlert('Failed to delete token: ' + err.message);
            if (btn) helpers.setBtnLoading(btn, false);
        }
    };

}
