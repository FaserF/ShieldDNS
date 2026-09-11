/**
 * Event Listeners and Button Handlers (Coordinator)
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { renderConfig } from './renderers.js';
import { showActivityOverlay, hideActivityOverlay } from './activity.js';
import * as fetchService from '../services/fetch.js';
import { initSettingsEvents, saveConfig, setSettingsDirty } from './events_settings.js';
import { initMFA } from './events_mfa.js';
import { initBackupEvents } from './events_backup.js';
import { initAPIKeyEvents } from './events_apikeys.js';
import { initGeoEvents, detectServerLocation } from './events_geo.js';

export { setSettingsDirty, saveConfig, detectServerLocation, initMFA };

export function initEvents(fetchConfig) {
    // Logout handler (moved to top for maximum reliability)
    const handleLogout = async (e) => {
        console.log('Logout triggered');
        if (e) e.preventDefault();
        const confirmed = await helpers.showConfirm('Are you sure you want to log out?', 'Logout', true);
        if (!confirmed) return;

        try {
            await api.apiFetch(api.endpoints.logout, { method: 'POST' });
            window.location.reload(); 
        } catch (err) {
            helpers.showAlert('Logout failed: ' + err.message);
        }
    };

    getEl('logout-btn')?.addEventListener('click', handleLogout);
    getEl('nav-logout-btn')?.addEventListener('click', handleLogout);
    window.handleLogout = handleLogout; // Global hook for debugging/failsafe

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

    // Settings Tabs & Search Logic
    let activeSettingsTab = 'all';

    const filterSettings = () => {
        const query = getEl('settings-search-input')?.value.toLowerCase().trim() || '';
        const sections = document.querySelectorAll('#settings-form .settings-section, #settings .settings-section');

        sections.forEach(section => {
            const category = section.getAttribute('data-category');
            const matchesTab = (activeSettingsTab === 'all' || category === activeSettingsTab || query !== '');
            
            if (!matchesTab) {
                section.style.display = 'none';
                return;
            }

            let sectionHasMatch = false;
            const groups = section.querySelectorAll('.form-group, .checkbox-group, .table-header-actions, .card.overflow-x');
            const h2 = section.querySelector('h2');
            const titleMatch = h2 && h2.textContent.toLowerCase().includes(query);

            if (titleMatch && query !== '') {
                sectionHasMatch = true;
                groups.forEach(g => g.style.display = '');
            } else {
                groups.forEach(group => {
                    const text = group.textContent.toLowerCase();
                    const isMatch = (query === '' || text.includes(query));
                    group.style.display = isMatch ? '' : 'none';
                    if (isMatch) sectionHasMatch = true;
                });
            }

            section.style.display = sectionHasMatch ? '' : 'none';
        });
    };

    // Tab buttons click handler
    const tabNav = getEl('settings-tabs-nav');
    tabNav?.querySelectorAll('.settings-tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            tabNav.querySelectorAll('.settings-tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeSettingsTab = btn.getAttribute('data-tab') || 'all';

            // Clear search when switching tabs for clean experience
            const searchInput = getEl('settings-search-input');
            if (searchInput && searchInput.value) {
                searchInput.value = '';
            }
            filterSettings();
        });
    });

    // Settings Search input
    const settingsSearchInput = getEl('settings-search-input');
    settingsSearchInput?.addEventListener('input', () => {
        filterSettings();
    });

    // Preset Selection Settings
    const settingsPresetSelector = getEl('settings-preset-selector');
    settingsPresetSelector?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (!val) return;
        
        const host = window.location.hostname || 'shielddns.local';
        
        if (val === 'shielddns') {
            state.currentConfig.upstreams = ["86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = host;
            state.currentConfig.block_page_ip = host;
            state.currentConfig.sign_mobileconfig = true;
            state.currentConfig.abuse_detection_enabled = true;
            state.currentConfig.dnssec_enabled = true;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 10;
            state.currentConfig.diagnostics_refresh_interval = 30;
            state.currentConfig.retention_days = 30;
            state.currentConfig.malicious_ip_blocking_enabled = true;
            state.currentConfig.malicious_ip_interval = 8;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = [];
        } else if (val === 'minimal') {
            state.currentConfig.upstreams = ["86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = host;
            state.currentConfig.block_page_ip = host;
            state.currentConfig.sign_mobileconfig = false;
            state.currentConfig.abuse_detection_enabled = false;
            state.currentConfig.dnssec_enabled = true;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 10;
            state.currentConfig.diagnostics_refresh_interval = 60;
            state.currentConfig.retention_days = 7;
            state.currentConfig.malicious_ip_blocking_enabled = false;
            state.currentConfig.malicious_ip_interval = 24;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = [];
        } else if (val === 'maxperf') {
            state.currentConfig.upstreams = ["86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = host;
            state.currentConfig.block_page_ip = host;
            state.currentConfig.sign_mobileconfig = true;
            state.currentConfig.abuse_detection_enabled = true;
            state.currentConfig.dnssec_enabled = true;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 5;
            state.currentConfig.diagnostics_refresh_interval = 300;
            state.currentConfig.retention_days = 14;
            state.currentConfig.malicious_ip_blocking_enabled = true;
            state.currentConfig.malicious_ip_interval = 12;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = [];
        } else if (val === 'faserf') {
            state.currentConfig.upstreams = ["86.54.11.100", "9.9.9.9", "1.1.1.1", "8.8.8.8", "1.0.0.1"];
            state.currentConfig.upstream_dot = ["unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"];
            state.currentConfig.prefer_encrypted = true;
            state.currentConfig.admin_domain = "dns.fabiseitz.de";
            state.currentConfig.block_page_ip = "89.168.74.120";
            state.currentConfig.sign_mobileconfig = true;
            state.currentConfig.abuse_detection_enabled = true;
            state.currentConfig.dnssec_enabled = false;
            state.currentConfig.serve_stale = true;
            state.currentConfig.use_fastest_upstream = true;
            state.currentConfig.smart_selection_policy = "fastest";
            state.currentConfig.latency_test_interval = 15;
            state.currentConfig.diagnostics_refresh_interval = 300;
            state.currentConfig.retention_days = 90;
            state.currentConfig.malicious_ip_blocking_enabled = true;
            state.currentConfig.malicious_ip_interval = 12;
            state.currentConfig.verify_upstream_tls = true;
            state.currentConfig.blocked_countries = ["CN", "RU", "IR", "KP", "VN", "BR", "BY", "IQ", "UA"];
        }
        
        renderConfig(state.currentConfig);
        setSettingsDirty(true);
        helpers.showToast(`Loaded preset: ${val}`);
        settingsPresetSelector.value = "";
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
            // Refresh stats to show impact
            fetchService.fetchStats();
        } catch (e) { 
            helpers.showAlert('Failed to toggle protection: ' + e.message); 
        } finally {
            helpers.setBtnLoading(toggleBtn, false);
        }
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
            const search = document.getElementById('query-search')?.value.trim() || '';
            const status = document.getElementById('query-filter-status')?.value || '';
            const fromTime = document.getElementById('query-time-from')?.value || '';
            const toTime = document.getElementById('query-time-to')?.value || '';
            
            let url = `${api.endpoints.exportLogs}?format=${type}&token=${token}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;
            if (status) url += `&status=${encodeURIComponent(status)}`;
            if (fromTime) url += `&from_time=${encodeURIComponent(fromTime)}`;
            if (toTime) url += `&to_time=${encodeURIComponent(toTime)}`;

            window.location.href = url;
            helpers.showToast(`Log export (${type}) started`, 'info');
        } catch (err) {
            helpers.showAlert('Export failed: ' + err.message);
        } finally {
            if (btn) setTimeout(() => helpers.setBtnLoading(btn, false), 2000);
        }
    };

    window.unblockClient = async (ip, event) => {
        if (!await helpers.showConfirm(`Unblock client ${ip}?`)) return;
        const btn = event?.currentTarget;
        helpers.setBtnLoading(btn, true, 'Unblocking...');
        try {
            await api.apiFetch(api.endpoints.clientBlock, {
                method: 'POST',
                body: JSON.stringify({ ip, action: 'unblock' })
            });
            helpers.showToast(`Client ${ip} unblocked`);
            
            // Refresh config and UI
            await fetchService.fetchConfig();
            fetchService.fetchStats();
            
            // If the modal is open, re-render it
            const modal = getEl('blocked-clients-modal');
            if (modal && !modal.classList.contains('hidden')) {
                const m = await import('./renderers.js');
                m.renderBlockedClientsModal(state.currentConfig.blocked_clients, state.currentConfig.blocked_clients_info || {});
            }
        } catch (err) {
            helpers.showAlert('Failed to unblock client: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
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
            fetchService.fetchStats();
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
            fetchService.fetchStats();
        } catch (err) { 
            helpers.showAlert('Failed to add mapping: ' + err.message); 
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    };

    window.addRoutingRule = async (event) => {
        const match = getEl('routing-match-input')?.value.trim();
        const target = getEl('routing-target-select')?.value;
        const targetParam = getEl('routing-target-param')?.value.trim();

        if (!match) return helpers.showAlert('Match criteria (Domain or IP) is required.');

        const btn = event?.currentTarget;
        helpers.setBtnLoading(btn, true, 'Adding Route...');

        const payload = {
            match,
            target: target || 'default',
            host_target: target === 'host' ? targetParam : '',
            wireguard_config: target === 'wireguard' ? targetParam : '',
            enabled: true
        };

        try {
            await api.apiFetch(api.endpoints.routingRules, {
                method: 'POST',
                body: JSON.stringify(payload)
            });
            if (getEl('routing-match-input')) getEl('routing-match-input').value = '';
            if (getEl('routing-target-param')) getEl('routing-target-param').value = '';
            helpers.showToast(`Routing rule for ${match} saved.`);
            fetchConfig();
            fetchService.fetchStats();
        } catch (err) {
            helpers.showAlert('Failed to add routing rule: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    };

    window.removeRoutingRule = async (ruleIdOrMatch, event) => {
        if (!await helpers.showConfirm(`Remove routing rule for ${ruleIdOrMatch}?`)) return;

        const btn = event?.currentTarget;
        helpers.setBtnLoading(btn, true, 'Removing...');

        try {
            await api.apiFetch(`${api.endpoints.routingRules}?id=${encodeURIComponent(ruleIdOrMatch)}`, {
                method: 'DELETE'
            });
            helpers.showToast('Routing rule removed');
            fetchConfig();
            fetchService.fetchStats();
        } catch (err) {
            helpers.showAlert('Failed to remove routing rule: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    };

    // Initialize modular event domains
    initSettingsEvents(fetchConfig);
    initAPIKeyEvents();
    initGeoEvents(fetchConfig);
    initBackupEvents(fetchConfig);
    initMFA();
}
