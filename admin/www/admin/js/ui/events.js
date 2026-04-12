/**
 * Event Listeners and Button Handlers
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { renderConfig } from './renderers.js';

export function initEvents(fetchConfig) {
    // General Update/Refresh
    const refreshBtn = getEl('refresh-btn');
    refreshBtn?.addEventListener('click', async () => {
        helpers.setBtnLoading(refreshBtn, true, 'Updating...');
        try {
            await api.apiFetch(api.endpoints.refresh, { method: 'POST' });
            helpers.showToast('Update started in background...');
        } catch (e) { 
            helpers.showAlert('Failed to start update: ' + e.message); 
        } finally {
            helpers.setBtnLoading(refreshBtn, false);
        }
    });

    const updateBtn = getEl('check-updates-btn');
    updateBtn?.addEventListener('click', async () => {
        helpers.setBtnLoading(updateBtn, true, 'Checking...');
        try {
            await api.apiFetch(api.endpoints.refresh, { method: 'POST' });
            helpers.showToast('Update check started...');
        } catch (e) { 
            helpers.showAlert('Failed to check updates: ' + e.message); 
        } finally {
            helpers.setBtnLoading(updateBtn, false);
        }
    });

    const fullRefreshBtn = getEl('full-system-refresh-btn');
    fullRefreshBtn?.addEventListener('click', async () => {
        const confirmed = await helpers.showConfirm('Are you sure you want to perform a full system refresh? This will re-download all lists and restart the DNS server.');
        if (!confirmed) return;

        helpers.setBtnLoading(fullRefreshBtn, true, 'Restarting System...');
        try {
             await api.apiFetch(api.endpoints.fullReload, { method: 'POST' });
             helpers.showToast('Full system refresh initiated. CoreDNS is restarting.', 'info');
        } catch (e) { 
            helpers.setBtnLoading(fullRefreshBtn, false);
            helpers.showAlert('Failed to start full refresh: ' + e.message); 
        }
    });

    // Filtering Toggle
    const toggleBtn = getEl('toggle-protection-btn');
    toggleBtn?.addEventListener('click', async () => {
        const newStatus = !state.currentConfig.filtering_enabled;
        helpers.setBtnLoading(toggleBtn, true, 'Toggling...');
        try {
            await api.apiFetch(api.endpoints.toggleFiltering, {
                method: 'POST',
                body: JSON.stringify({ enabled: newStatus })
            });
            state.currentConfig.filtering_enabled = newStatus;
            renderConfig(state.currentConfig);
            helpers.showToast(newStatus ? 'Protection Enabled' : 'Protection Disabled', newStatus ? 'success' : 'info');
        } catch (e) { 
            helpers.showAlert('Failed to toggle protection: ' + e.message); 
        } finally {
            helpers.setBtnLoading(toggleBtn, false);
        }
    });

    // Config Save
    getEl('settings-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        saveConfig(fetchConfig);
    });

    // API Key creation
    getEl('create-api-key-btn')?.addEventListener('click', () => {
        const modal = getEl('api-key-modal');
        const form = getEl('api-key-form');
        const result = getEl('api-key-result');
        if (!modal || !form || !result) return;
        getEl('api-key-modal-title').textContent = 'Generate API Key';
        getEl('api-key-name').value = '';
        getEl('save-api-key-btn').textContent = 'Generate';
        form.classList.remove('hidden');
        result.classList.add('hidden');
        modal.classList.remove('hidden');
    });

    getEl('save-api-key-btn')?.addEventListener('click', async (e) => {
        const btn = e.target;
        const name = getEl('api-key-name').value.trim();
        if (!name) return helpers.showToast('Please enter a name for the API key', 'info');

        const perms = [];
        if (getEl('perm-stats').checked) perms.push('read:stats');
        if (getEl('perm-logs').checked) perms.push('read:logs');
        if (getEl('perm-system').checked) perms.push('read:system');
        if (getEl('perm-filtering').checked) perms.push('write:filtering');

        helpers.setBtnLoading(btn, true, 'Generating...');
        try {
            const res = await api.apiFetch(api.endpoints.createToken, {
                method: 'POST',
                body: JSON.stringify({ name, permissions: perms })
            });
            
            // The backend returns { token: "...", id: "..." } or similar
            if (res.token) {
                getEl('api-key-form').classList.add('hidden');
                getEl('api-key-result').classList.remove('hidden');
                getEl('api-key-value').textContent = res.token;
                helpers.showToast('API Key generated!');
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

    // List Management Modals
    getEl('add-list-btn')?.addEventListener('click', () => {
        getEl('modal-title').textContent = 'Add Blocklist';
        getEl('list-type').value = 'block';
        getEl('list-name').value = '';
        getEl('list-url').value = '';
        getEl('modal')?.classList.remove('hidden');
    });

    getEl('add-allowlist-btn')?.addEventListener('click', () => {
        getEl('modal-title').textContent = 'Add Allowlist';
        getEl('list-type').value = 'allow';
        getEl('list-name').value = '';
        getEl('list-url').value = '';
        getEl('modal')?.classList.remove('hidden');
    });

    getEl('modal-cancel')?.addEventListener('click', () => getEl('modal')?.classList.add('hidden'));

    getEl('modal-confirm')?.addEventListener('click', async (e) => {
        const type = getEl('list-type').value;
        const name = getEl('list-name').value.trim();
        const url = getEl('list-url').value.trim();
        const category = getEl('list-category').value;

        if (!name || !url) return helpers.showAlert('Name and URL are required');

        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Adding...');

        const listObj = { name, url, enabled: true, category };
        if (type === 'block') state.currentConfig.lists.push(listObj);
        else state.currentConfig.allowlists.push(listObj);

        try {
            await api.apiFetch(api.endpoints.config, {
                method: 'POST',
                body: JSON.stringify(state.currentConfig)
            });
            getEl('modal').classList.add('hidden');
            helpers.showToast(`${name} added!`);
            fetchConfig();
        } catch (err) {
            helpers.showAlert('Failed to add list: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('apply-recommended-btn')?.addEventListener('click', async (e) => {
        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Applying...');
        try {
            await api.apiFetch(api.endpoints.refresh, { method: 'POST', body: JSON.stringify({ action: 'recommended' }) });
            helpers.showToast('Recommended lists are being applied...');
            fetchConfig();
        } catch (err) {
            helpers.showAlert('Failed to apply recommended lists: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('reset-lists-btn')?.addEventListener('click', async (e) => {
        if (!await helpers.showConfirm('Reset all lists to factory defaults? Your custom lists will be removed.')) return;
        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Resetting...');
        try {
            await api.apiFetch(api.endpoints.resetLists, { method: 'POST' });
            helpers.showToast('Lists restored to defaults');
            // Force immediate reload to update UI
            setTimeout(fetchConfig, 800);
        } catch (err) {
            helpers.showAlert('Failed to reset lists: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    // Window hooks for dynamic elements
    window.deleteAPIKey = async (id, event) => {
        if (!await helpers.showConfirm('Delete this API key forever?')) return;
        const btn = event.currentTarget;
        helpers.setBtnLoading(btn, true, '');
        try {
            await api.apiFetch(`${api.endpoints.deleteToken}?id=${id}`, { 
                method: 'DELETE'
            });
            helpers.showToast('API Key deleted');
            fetchService.fetchAPIKeys();
        } catch (err) {
            helpers.showAlert('Failed to delete token: ' + err.message);
            helpers.setBtnLoading(btn, false);
        }
    };

    window.unblockClient = async (ip) => {
        if (!await helpers.showConfirm(`Unblock client ${ip}?`)) return;
        try {
            await api.apiFetch(api.endpoints.clientBlock, {
                method: 'POST',
                body: JSON.stringify({ ip, action: 'unblock' })
            });
            helpers.showToast(`Client ${ip} unblocked`);
            setTimeout(fetchConfig, 500);
        } catch (err) {
            helpers.showAlert('Failed to unblock client: ' + err.message);
        }
    };

    window.addCustomRule = async (type, domain) => {
        const action = type === 'blocked' ? 'block' : 'allow';
        try {
            await api.apiFetch(api.endpoints.addRule, {
                method: 'POST',
                body: JSON.stringify({ domain, action })
            });
            helpers.showToast(`${domain} added to ${type} list`);
            setTimeout(fetchConfig, 500);
        } catch (err) {
            helpers.showAlert('Failed to add rule: ' + err.message);
        }
    };

    // Maintenance Handlers
    getEl('manual-client-block-btn')?.addEventListener('click', async () => {
        const ip = getEl('manual-client-block-input').value.trim();
        if (!ip) return helpers.showToast('Please enter an IP address', 'info');
        
        try {
            await api.apiFetch(api.endpoints.clientBlock, {
                method: 'POST',
                body: JSON.stringify({ ip, action: 'block' })
            });
            helpers.showToast(`Client ${ip} blocked`);
            getEl('manual-client-block-input').value = '';
            setTimeout(fetchConfig, 500);
        } catch (err) {
            helpers.showAlert('Failed to block client: ' + err.message);
        }
    });

    // Geo-Blocking Search Setup
    const countrySearch = getEl('country-search');
    const countryDropdown = getEl('country-dropdown');
    
    if (countrySearch && countryDropdown) {
        countrySearch.addEventListener('input', (e) => {
            const val = e.target.value.toLowerCase();
            if (!val) {
                countryDropdown.classList.add('hidden');
                return;
            }
            // state.allCountries is loaded via fetchCountries()
            const allCountries = state.allCountries || {};
            if (Object.keys(allCountries).length === 0) {
                // Try fetching if missing
                return;
            }
            
            const matches = Object.entries(state.allCountries).filter(([code, name]) => 
                name.toLowerCase().includes(val) || code.toLowerCase().includes(val)
            ).slice(0, 10);
            
            if (matches.length > 0) {
                countryDropdown.innerHTML = matches.map(([code, name]) => `
                    <div class="dropdown-item" data-code="${code}" style="padding: 10px; cursor: pointer; display: flex; align-items: center; border-bottom: 1px solid var(--border);">
                        <img src="https://flagcdn.com/w20/${code.toLowerCase()}.png" alt="${code}" style="margin-right: 12px;">
                        <span>${name} (${code})</span>
                    </div>
                `).join('');
                countryDropdown.classList.remove('hidden');
            } else {
                countryDropdown.classList.add('hidden');
            }
        });

        countryDropdown.addEventListener('mousedown', async (e) => {
            e.preventDefault(); // Prevent input onblur if it exists
            const item = e.target.closest('.dropdown-item');
            if (!item) return;
            const code = item.dataset.code;
            countrySearch.value = '';
            countryDropdown.classList.add('hidden');
            
            if (!state.currentConfig.blocked_countries) state.currentConfig.blocked_countries = [];
            if (!state.currentConfig.blocked_countries.includes(code)) {
                state.currentConfig.blocked_countries.push(code);
                try {
                    await saveConfig(fetchConfig);
                } catch (err) {
                    helpers.showAlert('Failed to add country geo-block');
                }
            } else {
                helpers.showToast('Country is already blocked', 'info');
            }
        });

        // Hide dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target !== countrySearch && !countryDropdown.contains(e.target)) {
                countryDropdown.classList.add('hidden');
            }
        });
    }

    getEl('backup-btn')?.addEventListener('click', async () => {
        try {
            const token = localStorage.getItem('api_token');
            window.location.href = `${api.endpoints.backup}?token=${token}`;
        } catch (err) {
            helpers.showAlert('Backup failed: ' + err.message);
        }
    });

    getEl('restore-file-input')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const formData = new FormData();
        formData.append('file', file);

        helpers.showToast('Restoring configuration...', 'info');
        try {
            await api.apiFetch(api.endpoints.restore, {
                method: 'POST',
                body: formData
            });
            helpers.showToast('Configuration restored successfully! System is restarting...');
            setTimeout(() => window.location.reload(), 2000);
        } catch (err) {
            helpers.showAlert('Restore failed: ' + err.message);
        }
    });

    getEl('reset-system-btn')?.addEventListener('click', async () => {
        if (!await helpers.showConfirm('FACTORY RESET: This will wipe your configuration and password. The system will revert to setup mode. Are you absolutely sure?')) return;
        
        try {
            await api.apiFetch(api.endpoints.reset, { 
                method: 'POST', 
                body: JSON.stringify({ scope: 'all' }) 
            });
            helpers.showToast('Factory reset successful. Redirecting to setup...');
            setTimeout(() => window.location.reload(), 2000);
        } catch (err) {
            helpers.showAlert('Factory reset failed: ' + err.message);
        }
    });

    getEl('password-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const current = getEl('current-password').value;
        const newPass = getEl('new-password').value;
        
        if (newPass.length < 12) return helpers.showAlert('New password must be at least 12 characters');

        const btn = e.target.querySelector('button[type="submit"]');
        helpers.setBtnLoading(btn, true, 'Updating...');
        try {
            await api.apiFetch(api.endpoints.changePassword, {
                method: 'POST',
                body: JSON.stringify({ current_password: current, new_password: newPass })
            });
            helpers.showToast('Password updated successfully');
            e.target.reset();
        } catch (err) {
            helpers.showAlert('Failed to update password: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });
}

export async function saveConfig(fetchConfig) {
    const saveBtn = document.querySelector('#settings-form button[type="submit"]');
    helpers.setBtnLoading(saveBtn, true, 'Saving...');

    const upstreams = getEl('upstreams-input')?.value.split(',').map(s => s.trim()).filter(Boolean);
    const dotUpstreams = getEl('dot-upstreams-input')?.value.split(',').map(s => s.trim()).filter(Boolean);
    
    const newConfig = {
        ...state.currentConfig,
        upstreams,
        upstream_dot: dotUpstreams,
        prefer_encrypted: getEl('prefer-encrypted-check')?.checked,
        admin_domain: getEl('admin-domain-input')?.value.trim() || state.currentConfig.admin_domain,
        block_page_ip: getEl('block-ip-input')?.value.trim() || state.currentConfig.block_page_ip,
        debug_mode: getEl('debug-mode-check')?.checked,
        sign_mobileconfig: getEl('sign-mobileconfig-check')?.checked,
        abuse_detection_enabled: getEl('abuse-detection-check')?.checked,
        dnssec_enabled: getEl('dnssec-check')?.checked,
        serve_stale: getEl('serve-stale-check')?.checked,
        use_fastest_upstream: getEl('smart-upstream-check')?.checked,
        smart_selection_policy: getEl('smart-selection-policy-input')?.value || 'fastest',
        latency_test_interval: parseInt(getEl('latency-interval-input')?.value) || 10,
        diagnostics_refresh_interval: parseInt(getEl('diagnostics-interval-input')?.value) || 600,
        retention_days: parseInt(getEl('retention-input')?.value) || 30,
    };

    try {
        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify(newConfig)
        });
        state.currentConfig = newConfig;
        helpers.showToast('Configuration saved successfully!');
        renderConfig(state.currentConfig);
    } catch (e) {
        helpers.showAlert('Failed to save configuration: ' + e.message);
    } finally {
        helpers.setBtnLoading(saveBtn, false);
    }
}
