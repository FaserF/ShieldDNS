/**
 * Event Listeners and Button Handlers
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { renderConfig } from './renderers.js';
import { showActivityOverlay, hideActivityOverlay } from './activity.js';
import * as fetchService from '../services/fetch.js';

function setSettingsDirty(dirty) {
    state.isDirty = dirty;
    const footer = document.querySelector('.settings-save-footer');
    const status = getEl('settings-save-status');
    if (!footer) return;

    if (dirty) {
        footer.classList.add('visible');
        if (status) {
            status.innerHTML = `<strong>UNSAVED</strong> Configuration changed. Please save to apply.`;
            status.classList.add('dirty');
        }
    } else {
        footer.classList.remove('visible');
        if (status) {
            status.classList.remove('dirty');
            status.innerHTML = `All changes must be saved. Reboot might be required for core changes.`;
        }
    }
}

export function initEvents(fetchConfig) {
    // Domain Protection Switcher
    const searchBtn = getEl('search-btn');
    const searchInput = getEl('domain-search');
    
    const handleCheck = async () => {
        const domain = searchInput.value.trim();
        if (!domain) return;
        
        const loader = getEl('search-loading');
        const result = getEl('search-result');
        
        helpers.setBtnLoading(searchBtn, true, 'Checking...');
        if (loader) loader.classList.remove('hidden');
        if (result) result.classList.add('hidden');
        
        try {
            const res = await api.apiFetch(`${api.endpoints.search}?q=${encodeURIComponent(domain)}`);
            import('./renderers.js').then(m => m.renderProtectionResult(res, domain));
        } catch (e) {
            helpers.showAlert('Check failed: ' + e.message);
        } finally {
            helpers.setBtnLoading(searchBtn, false);
            if (loader) loader.classList.add('hidden');
        }
    };

    searchBtn?.addEventListener('click', handleCheck);
    searchInput?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleCheck();
    });

    // Support legacy onclick handlers
    window.checkProtection = handleCheck;

    // Settings Search
    const settingsSearchInput = getEl('settings-search-input');
    settingsSearchInput?.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        const sections = document.querySelectorAll('#settings-form .settings-section, #settings .settings-section');
        
        sections.forEach(section => {
            let sectionHasMatch = false;
            const groups = section.querySelectorAll('.form-group, .checkbox-group, .table-header-actions, .card.overflow-x');
            const h2 = section.querySelector('h2');
            
            // Check section title itself
            const titleMatch = h2 && h2.textContent.toLowerCase().includes(query);
            
            if (titleMatch && query !== "") {
                sectionHasMatch = true;
                groups.forEach(g => g.style.display = '');
            } else {
                groups.forEach(group => {
                    const text = group.textContent.toLowerCase();
                    const isMatch = query === "" || text.includes(query);
                    group.style.display = isMatch ? '' : 'none';
                    if (isMatch) sectionHasMatch = true;
                });
            }
            
            section.style.display = sectionHasMatch ? '' : 'none';
        });
    });

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
        showActivityOverlay('Full System Refresh', 'Re-downloading lists and restarting CoreDNS...');
        try {
             await api.apiFetch(api.endpoints.fullReload, { method: 'POST' });
             helpers.showToast('Full system refresh initiated.', 'info');
             hideActivityOverlay(true);
        } catch (e) { 
            helpers.setBtnLoading(fullRefreshBtn, false);
            hideActivityOverlay(false);
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
    const settingsForm = getEl('settings-form');
    settingsForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        saveConfig(fetchConfig);
    });

    // Monitor all inputs in the settings form for changes to show the save bar
    settingsForm?.addEventListener('input', () => setSettingsDirty(true));
    settingsForm?.addEventListener('change', () => setSettingsDirty(true));

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

    // API Key search
    getEl('api-keys-search')?.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const keys = state.currentConfig.api_keys || [];
        const filtered = keys.filter(k => k.name.toLowerCase().includes(query));
        import('./renderers.js').then(m => m.renderAPIKeys(filtered));
    });

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
        showActivityOverlay('Applying Recommendations', 'Adding ShieldDNS official blocklists...');
        try {
            await api.apiFetch(api.endpoints.refresh, { method: 'POST', body: JSON.stringify({ action: 'recommended' }) });
            helpers.showToast('Recommended lists are being applied...');
            hideActivityOverlay(true);
            fetchConfig();
        } catch (err) {
            hideActivityOverlay(false);
            helpers.showAlert('Failed to apply recommended lists: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('deselect-all-blocklists')?.addEventListener('click', async (e) => {
        if (!await helpers.showConfirm('Deselect all blocklists?')) return;
        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Clearing...');
        state.currentConfig.lists.forEach(l => l.enabled = false);
        try {
            await api.apiFetch(api.endpoints.config, { method: 'POST', body: JSON.stringify(state.currentConfig) });
            helpers.showToast('All blocklists deseledted');
            fetchConfig();
        } catch (err) {
            helpers.showAlert('Failed to deselect lists: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('deselect-all-allowlists')?.addEventListener('click', async (e) => {
        if (!await helpers.showConfirm('Deselect all allowlists?')) return;
        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Clearing...');
        state.currentConfig.allowlists.forEach(l => l.enabled = false);
        try {
            await api.apiFetch(api.endpoints.config, { method: 'POST', body: JSON.stringify(state.currentConfig) });
            helpers.showToast('All allowlists deselected');
            fetchConfig();
        } catch (err) {
            helpers.showAlert('Failed to deselect allowlists: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    const resetListsBtn = getEl('reset-lists-btn');
    resetListsBtn?.addEventListener('click', async (e) => {
        if (!await helpers.showConfirm('Are you sure you want to restore all filtering lists to defaults? Your custom lists will be removed.', 'Restore Defaults', true)) return;
        
        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Resetting...');
        showActivityOverlay('Restoring Defaults', 'Downloading factory blocklist presets...');
        
        try {
            await api.apiFetch(api.endpoints.resetLists, { method: 'POST' });
            helpers.showToast('Filtering lists restored to defaults');
            hideActivityOverlay(true);
            setTimeout(() => fetchConfig(), 200); // Tiny delay to ensure server state is persisted
        } catch (err) {
            hideActivityOverlay(false);
            helpers.showAlert('Failed to restore lists: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    // Window hooks for dynamic elements
    window.copyText = (id) => {
        const el = getEl(id);
        if (el) {
            const val = el.value || el.textContent;
            navigator.clipboard.writeText(val);
            helpers.showToast('Copied to clipboard');
        }
    };

    window.exportLogs = async (type, event) => {
        const btn = event?.currentTarget;
        if (btn) helpers.setBtnLoading(btn, true, 'Exporting...');
        try {
            const token = localStorage.getItem('api_token');
            window.location.href = `${api.endpoints.exportLogs}?format=${type}&token=${token}`;
            helpers.showToast(`Log export (${type}) started`, 'info');
        } catch (err) {
            helpers.showAlert('Export failed: ' + err.message);
        } finally {
            if (btn) setTimeout(() => helpers.setBtnLoading(btn, false), 2000);
        }
    };

    window.editAPIKey = (id) => {
        const key = state.currentConfig.api_keys?.find(k => k.id === id);
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
        
        getEl('perm-stats').checked = key.permissions.includes('read:stats');
        getEl('perm-logs').checked = key.permissions.includes('read:logs');
        getEl('perm-system').checked = key.permissions.includes('read:system');
        getEl('perm-filtering').checked = key.permissions.includes('write:filtering');
        
        form.classList.remove('hidden');
        result.classList.add('hidden');
        modal.classList.remove('hidden');
    };

    window.deleteAPIKey = async (id, event) => {
        if (!await helpers.showConfirm('Delete this API key forever?', 'Delete API Key', true)) return;
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

    window.addCustomRule = async (action, domainArg, event) => {
        const type = action === 'blocked' ? 'block' : (action === 'allowed' ? 'allow' : action);
        const inputId = action === 'blocked' ? 'custom-block-input' : 'custom-allow-input';
        const domain = domainArg || getEl(inputId)?.value.trim();
        
        if (!domain) return;
        
        const btn = event?.currentTarget;
        helpers.setBtnLoading(btn, true, 'Saving...');
        
        try {
            await api.apiFetch(api.endpoints.addRule, {
                method: 'POST',
                body: JSON.stringify({ domain, type })
            });
            if (getEl(inputId)) getEl(inputId).value = '';
            helpers.showToast(`${domain} added to ${action} list.`);
            fetchConfig();
        } catch (err) {
            helpers.showAlert('Failed to add rule: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    };

    window.addCustomMapping = async (event) => {
        const domain = getEl('custom-map-domain')?.value.trim();
        const ip = getEl('custom-map-ip')?.value.trim();
        if (!domain || !ip) return helpers.showAlert('Both Domain and IP are required.');
        
        const btn = event?.currentTarget;
        helpers.setBtnLoading(btn, true, 'Adding Mapping...');

        try {
            await api.apiFetch(api.endpoints.addRule, {
                method: 'POST',
                body: JSON.stringify({ domain, ip, type: 'mapping' })
            });
            if (getEl('custom-map-domain')) getEl('custom-map-domain').value = '';
            if (getEl('custom-map-ip')) getEl('custom-map-ip').value = '';
            helpers.showToast(`Mapping ${domain} -> ${ip} created.`);
            fetchConfig();
        } catch (err) { 
            helpers.showAlert('Failed to add mapping: ' + err.message); 
        } finally {
            helpers.setBtnLoading(btn, false);
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

        // High-Risk Countries Button
        const highRiskBtn = getEl('block-high-risk-countries-btn');
        highRiskBtn?.addEventListener('click', async (e) => {
            const btn = e.target;
            helpers.setBtnLoading(btn, true, 'Analyzing...');
            try {
                const highRisk = await api.apiFetch(api.endpoints.highRiskCountries);
                if (!highRisk || highRisk.length === 0) return;

                if (!state.currentConfig.blocked_countries) state.currentConfig.blocked_countries = [];
                let added = 0;
                highRisk.forEach(code => {
                    if (!state.currentConfig.blocked_countries.includes(code)) {
                        // Skip if it's the server's own country (double protection UI-side)
                        if (state.serverCountryCode && code === state.serverCountryCode) return;
                        state.currentConfig.blocked_countries.push(code);
                        added++;
                    }
                });

                if (added > 0) {
                    await saveConfig(fetchConfig);
                    helpers.showToast(`Blocked ${added} high-risk countries`, 'success');
                } else {
                    helpers.showToast('All high-risk countries are already blocked', 'info');
                }
            } catch (err) {
                helpers.showAlert('Failed to block high-risk countries: ' + err.message);
            } finally {
                helpers.setBtnLoading(btn, false);
            }
        });

        const manualSelect = getEl('manual-server-country-select');
        manualSelect?.addEventListener('change', (e) => {
            const code = e.target.value;
            const warning = getEl('server-location-warning');
            const nameEl = getEl('server-country-name');
            if (warning && nameEl) {
                if (code) {
                    const countryName = (state.allCountries || {})[code] || code;
                    nameEl.textContent = countryName;
                    warning.style.display = 'block';
                    warning.style.color = '#f59e0b';
                } else if (state.serverCountryCodeDetected) {
                    const countryName = (state.allCountries || {})[state.serverCountryCodeDetected] || state.serverCountryCodeDetected;
                    nameEl.textContent = countryName;
                    warning.style.display = 'block';
                    warning.style.color = '#10b981';
                } else {
                    nameEl.textContent = 'None (Auto-detection failed)';
                    warning.style.display = 'block';
                    warning.style.color = '#ef4444';
                }
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
        formData.append('config', file); // API expects 'config' field

        helpers.showToast('Restoring system...', 'info');
        showActivityOverlay('System Restoration', 'Applying configuration and database backup...');
        try {
            await api.apiFetch(api.endpoints.restore, {
                method: 'POST',
                body: formData
            });
            helpers.showToast('System restored successfully!');
            hideActivityOverlay(true);
            setTimeout(() => window.location.reload(), 2500);
        } catch (err) {
            hideActivityOverlay(false);
            helpers.showAlert('Restore failed: ' + err.message);
        }
    });

    getEl('reset-system-btn')?.addEventListener('click', async () => {
        if (!await helpers.showConfirm('FACTORY RESET: This will wipe your configuration and password. The system will revert to setup mode. Are you absolutely sure?', 'Factory Reset', true)) return;
        
        showActivityOverlay('Factory Reset', 'Wiping all system data and configurations...');
        try {
            await api.apiFetch(api.endpoints.reset, { 
                method: 'POST', 
                body: JSON.stringify({ scope: 'all' }) 
            });
            helpers.showToast('Factory reset successful.');
            hideActivityOverlay(true);
            setTimeout(() => window.location.reload(), 2000);
        } catch (err) {
            hideActivityOverlay(false);
            helpers.showAlert('Factory reset failed: ' + err.message);
        }
    });
    
    getEl('clear-logs-btn')?.addEventListener('click', async () => {
        if (!await helpers.showConfirm('Are you sure you want to clear all query logs? This action is irreversible and will delete all historical query data.', 'Clear Logs', true)) return;
        
        const btn = getEl('clear-logs-btn');
        helpers.setBtnLoading(btn, true, 'Clearing...');
        try {
            await api.apiFetch(api.endpoints.clearLogs, { method: 'POST' });
            helpers.showToast('All query logs cleared', 'success');
            setTimeout(() => window.location.reload(), 1000);
        } catch (err) {
            helpers.showAlert('Failed to clear logs: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    // Detail Modal Shortcuts
    getEl('ip-info-view-all-btn')?.addEventListener('click', () => {
        const ip = getEl('ip-info-subtitle').textContent;
        if (!ip) return;
        getEl('ip-info-modal').classList.add('hidden');
        window.navigateTo('logs');
        setTimeout(() => {
            const search = getEl('query-log-search');
            if (search) {
                search.value = ip;
                search.dispatchEvent(new Event('input'));
            }
        }, 300);
    });

    getEl('domain-info-view-logs-btn')?.addEventListener('click', () => {
        const domain = getEl('domain-info-subtitle').textContent;
        if (!domain) return;
        getEl('domain-info-modal').classList.add('hidden');
        window.navigateTo('logs');
        setTimeout(() => {
            const search = getEl('query-log-search');
            if (search) {
                search.value = domain;
                search.dispatchEvent(new Event('input'));
            }
        }, 300);
    });

    const passForm = getEl('password-form');
    if (passForm) {
        passForm.addEventListener('submit', async (e) => {
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

    // Settings Change Tracking
    const settingsContainer = getEl('settings');
    if (settingsContainer) {
        ['input', 'change'].forEach(evt => {
            settingsContainer.addEventListener(evt, (e) => {
                // Ignore search typing for change tracking
                if (e.target.id === 'settings-search-input') return;
                setSettingsDirty(true);
            });
        });
        // Catch resets specifically if any
        settingsContainer.addEventListener('reset', () => setSettingsDirty(false));
    }

    // Export for external components (like country picker) to trigger dirty state
    window.setSettingsDirty = setSettingsDirty;
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
        doh_rate_limit: parseInt(getEl('doh-rate-limit-input')?.value) || 30,
        abuse_dga_threshold: parseFloat(getEl('abuse-dga-threshold-input')?.value) || 3.8,
        abuse_dga_min_len: parseInt(getEl('abuse-dga-min-len-input')?.value) || 8,
        malicious_ip_blocking_enabled: getEl('malicious-check')?.checked,
        malicious_ip_interval: parseInt(getEl('malicious-interval-input')?.value) || 8,
        verify_upstream_tls: getEl('verify-upstream-tls-check')?.checked,
        server_country: getEl('manual-server-country-select')?.value || ''
    };

    try {
        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify(newConfig)
        });
        state.currentConfig = newConfig;
        helpers.showToast('Configuration saved successfully!');
        setSettingsDirty(false);
        renderConfig(state.currentConfig);
    } catch (e) {
        helpers.showAlert('Failed to save configuration: ' + e.message);
    } finally {
        helpers.setBtnLoading(saveBtn, false);
    }
}

export async function detectServerLocation() {
    try {
        const res = await api.apiFetch(api.endpoints.serverCountry);
        const card = getEl('server-location-card');
        const nameEl = getEl('server-country-name');
        const manualBox = getEl('manual-server-country-box');
        const manualSelect = getEl('manual-server-country-select');

        // Populate manual select if not already done
        if (manualSelect && manualSelect.options.length <= 1) {
            const countries = state.allCountries || {};
            const sorted = Object.entries(countries).sort((a, b) => a[1].localeCompare(b[1]));
            sorted.forEach(([code, name]) => {
                const opt = document.createElement('option');
                opt.value = code;
                opt.textContent = name;
                manualSelect.appendChild(opt);
            });
        }

        if (manualSelect) manualSelect.value = res.manual || '';

        if (res.detected || res.manual) {
            state.serverCountryCodeDetected = res.detected;
            state.serverCountryCode = res.manual || res.detected;
            if (card && nameEl) {
                const effectiveCode = res.manual || res.detected;
                const countryName = (state.allCountries || {})[effectiveCode] || effectiveCode;
                nameEl.textContent = countryName;
                getEl('server-location-msg').innerHTML = `Server country: <span id="server-country-name" class="font-bold">${countryName}</span>`;
                card.classList.remove('hidden', 'success', 'warning', 'danger');
                card.classList.add(res.manual ? 'warning' : 'success');
                const helpText = card.querySelector('.help');
                if (helpText) helpText.textContent = 'This country is protected and cannot be blocked.';
            }
            if (manualBox) manualBox.classList.remove('hidden');
        } else {
            // Detection failed AND no manual entry
            if (card && nameEl) {
                getEl('server-location-msg').innerHTML = `<span class="font-bold">Action Required:</span> Set Manual Location`;
                card.classList.remove('hidden', 'success', 'warning', 'danger');
                card.classList.add('danger');
                const helpText = card.querySelector('.help');
                if (helpText) helpText.textContent = 'Auto-detection failed. Protect your server by selecting its location below.';
            }
            if (manualBox) manualBox.classList.remove('hidden');
        }
    } catch (e) {
        console.warn('Failed to detect server location:', e);
        getEl('manual-server-country-box')?.classList.remove('hidden');
    }
}
