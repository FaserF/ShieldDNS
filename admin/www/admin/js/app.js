/**
 * ShieldDNS Main Application Entry Point
 * Refactored into a modular structure for improved maintainability.
 */
import { state, uiRefs, getEl, updateUIRefs } from './core/state.js';
import * as auth from './core/auth.js';
import * as nav from './core/navigation.js';
import * as fetchService from './services/fetch.js';
import * as events from './ui/events.js';
import * as render from './ui/renderers.js';
import * as api from './services/api.js';
import * as helpers from './ui/helpers.js';
import * as uiModules from './ui/ui.js';
import { showActivityOverlay, hideActivityOverlay } from './ui/activity.js';

/**
 * Global Initialization
 */
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    
    // Attach Setup/Auth listeners globally
    getEl('setup-finish-btn')?.addEventListener('click', auth.finishSetup);
    getEl('login-confirm-btn')?.addEventListener('click', auth.handleLogin);
    getEl('login-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') auth.handleLogin();
    });

    auth.checkAuthStatus(initializeApp);
});

/**
 * App Initialization
 */
function initializeApp() {
    // 0. Ensure UI references are captured
    updateUIRefs();
    initTheme();
    initModals();
    
    // 1. Init Navigation with view-specific handlers
    nav.initNavigation({
        'queries': () => fetchService.fetchQueries(),
        'analytics': () => fetchService.fetchAnalytics(),
        'system-logs': () => nav.startSystemLogStream(),
        'diagnostics': () => { fetchService.fetchDiagnostics(); nav.startDiagTimer(() => fetchService.fetchDiagnostics()); },
        'lists': () => { fetchService.fetchPresets(); fetchService.fetchAllowlistPresets(); },
        'settings': () => { fetchService.fetchConfig(); fetchService.fetchAPIKeys(); },
        'dashboard': () => fetchService.fetchStats()
    });

    // 2. Init global event listeners
    events.initEvents(fetchService.fetchConfig);
    
    // 3. Initial data load
    refreshAll();
    
    // 4. Start real-time stream
    nav.startSSE(render.createQueryRow, updateDashboardFeed, state.fullQueryScroller);
    
    // 5. Auto-refresh loops
    setInterval(fetchService.fetchStats, 10000);
    setInterval(fetchService.fetchHistory, 60000);
}

async function refreshAll() {
    await Promise.all([
        fetchService.fetchStats(),
        fetchService.fetchConfig(),
        fetchService.fetchQueries(true),
        fetchService.fetchHistory(),
        fetchService.fetchAPIKeys(),
        fetchService.fetchCountries()
    ]);
}

function updateDashboardFeed(query) {
    if (uiRefs.queryLogItems) {
        const row = render.createQueryRow(query);
        uiRefs.queryLogItems.prepend(row);
        if (uiRefs.queryLogItems.children.length > 20) uiRefs.queryLogItems.lastElementChild.remove();
    }
}

/**
 * Theme and Layout
 */
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    const toggleBtn = getEl('theme-toggle');
    const updateIcon = (theme) => {
        if (!toggleBtn) return;
        const icon = toggleBtn.querySelector('i');
        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
        }
    };

    document.body.classList.remove('dark', 'light');
    document.body.classList.add(savedTheme);
    updateIcon(savedTheme);

    toggleBtn?.addEventListener('click', () => {
        const isDark = document.body.classList.contains('dark');
        const newTheme = isDark ? 'light' : 'dark';
        
        document.body.classList.remove('dark', 'light');
        document.body.classList.add(newTheme);
        localStorage.setItem('theme', newTheme);
        updateIcon(newTheme);
    });

    const sidebar = document.querySelector('.sidebar');
    const sidebarOverlay = getEl('sidebar-overlay');
    const toggleSidebar = () => {
        sidebar?.classList.toggle('open');
        sidebarOverlay?.classList.toggle('open');
    };
    getEl('sidebar-toggle')?.addEventListener('click', toggleSidebar);
    sidebarOverlay?.addEventListener('click', toggleSidebar);
}

// =============================================================================
// Window Hooks for HTML inline onclick compatibility
// =============================================================================

window.nextSetupStep = auth.nextSetupStep;
window.fetchQueries = fetchService.fetchQueries;
window.refreshAll = refreshAll;
window.showDomainDetails = (domain) => fetchService.fetchDomainDetails(domain);
window.showIPDetails = (ip) => fetchService.fetchIPDetails(ip);

window.addPreset = async (name, url, event) => {
    const listUrl = (url || '').toLowerCase().trim();
    if ((state.currentConfig.lists || []).some(l => (l.url || '').toLowerCase().trim() === listUrl)) {
        return helpers.showToast('List already added', 'info');
    }
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, 'Adding...');
    showActivityOverlay('Adding Blocklist', `Downloading and processing ${name}...`);

    if (!state.currentConfig.lists) state.currentConfig.lists = [];
    state.currentConfig.lists.push({ name, url, enabled: true });
    try {
        await events.saveConfig(fetchService.fetchConfig);
        helpers.showToast(`${name} added!`);
        hideActivityOverlay(true);
    } catch (e) {
        hideActivityOverlay(false);
        helpers.showAlert('Failed to add preset: ' + e.message);
    } finally {
        helpers.setBtnLoading(btn, false);
        fetchService.fetchPresets(); // Refresh presets UI
    }
};

window.addAllowPreset = async (name, url, event) => {
    const listUrl = (url || '').toLowerCase().trim();
    if ((state.currentConfig.allowlists || []).some(l => (l.url || '').toLowerCase().trim() === listUrl)) {
        return helpers.showToast('Allowlist already added', 'info');
    }
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, 'Adding...');
    showActivityOverlay('Adding Allowlist', `Processing ${name} preset...`);

    if (!state.currentConfig.allowlists) state.currentConfig.allowlists = [];
    state.currentConfig.allowlists.push({ name, url, enabled: true, category: 'Official' });
    try {
        await events.saveConfig(fetchService.fetchConfig);
        helpers.showToast(`${name} added to Allowlist!`);
        hideActivityOverlay(true);
    } catch (e) {
        hideActivityOverlay(false);
        helpers.showAlert('Failed to add allow preset: ' + e.message);
    } finally {
        helpers.setBtnLoading(btn, false);
        fetchService.fetchAllowlistPresets(); // Refresh UI
    }
};

/**
 * Modal Management
 */
function initModals() {
    // Shared closing logic for all modals
    const closeModals = () => {
        document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
    };

    // Close buttons by ID
    const closeSelectors = [
        'modal-cancel', 'ip-info-close-btn', 'ip-info-close-btn-bottom', 'ip-info-done-btn',
        'domain-info-close-btn', 'domain-info-close-btn-bottom', 'close-list-details-btn',
        'close-list-details-btn-2'
    ];
    
    closeSelectors.forEach(id => getEl(id)?.addEventListener('click', closeModals));

    // Global closure: backdrop click
    window.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal')) {
            closeModals();
        }
    });

    // Global closure: Escape key
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModals();
        }
    });

    // Navigate to full logs from details
    getEl('ip-info-view-all-btn')?.addEventListener('click', () => {
        const ip = getEl('ip-info-subtitle').textContent || getEl('ip-info-title').textContent;
        const searchInput = getEl('query-search');
        if (searchInput) {
            searchInput.value = ip;
            fetchService.fetchQueries(true);
            getEl('nav-queries')?.click();
            closeModals();
        }
    });

    getEl('domain-info-view-logs-btn')?.addEventListener('click', () => {
        const domain = getEl('domain-info-subtitle').textContent || getEl('domain-info-title').textContent;
        const searchInput = getEl('query-search');
        if (searchInput) {
            searchInput.value = domain;
            fetchService.fetchQueries(true);
            getEl('nav-queries')?.click();
            closeModals();
        }
    });

    // IP Info UI logic
    getEl('edit-alias-btn')?.addEventListener('click', () => {
        getEl('alias-edit-box').classList.toggle('hidden');
        getEl('client-alias-input').value = getEl('ip-info-title').textContent === getEl('ip-info-subtitle').textContent ? '' : getEl('ip-info-title').textContent;
    });

    getEl('save-alias-btn')?.addEventListener('click', async () => {
        const ip = getEl('ip-info-subtitle').textContent || getEl('ip-info-title').textContent;
        const alias = getEl('client-alias-input').value.trim();
        const btn = getEl('save-alias-btn');
        
        helpers.setBtnLoading(btn, true, '');
        try {
            await api.apiFetch(api.endpoints.clientAlias, {
                method: 'POST',
                body: JSON.stringify({ ip, alias })
            });
            helpers.showToast('Alias updated');
            getEl('ip-info-title').textContent = alias || ip;
            getEl('alias-edit-box').classList.add('hidden');
            fetchService.fetchConfig();
        } catch (e) {
            helpers.showAlert('Failed to update alias: ' + e.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('ip-block-btn')?.addEventListener('click', async () => {
        const ip = getEl('ip-info-subtitle').textContent || getEl('ip-info-title').textContent;
        if (!await helpers.showConfirm(`Block client ${ip}?`)) return;
        try {
            await api.apiFetch(api.endpoints.clientBlock, { method: 'POST', body: JSON.stringify({ ip, action: 'block' }) });
            helpers.showToast('Client blocked');
            closeModals();
            fetchService.fetchConfig();
        } catch (e) { helpers.showAlert('Block failed: ' + e.message); }
    });

    getEl('ip-unblock-btn')?.addEventListener('click', async () => {
        const ip = getEl('ip-info-subtitle').textContent || getEl('ip-info-title').textContent;
        try {
            await api.apiFetch(api.endpoints.clientBlock, { method: 'POST', body: JSON.stringify({ ip, action: 'unblock' }) });
            helpers.showToast('Client unblocked');
            closeModals();
            fetchService.fetchConfig();
        } catch (e) { helpers.showAlert('Unblock failed: ' + e.message); }
    });

    getEl('domain-block-btn')?.addEventListener('click', async () => {
        const domain = getEl('domain-info-title').textContent;
        if (!domain || !await helpers.showConfirm(`Block domain ${domain}?`)) return;
        try {
            await api.apiFetch(api.endpoints.addRule, { method: 'POST', body: JSON.stringify({ domain, action: 'block' }) });
            helpers.showToast(`${domain} blocked`);
            closeModals();
            fetchService.fetchConfig();
        } catch (e) { helpers.showAlert('Block failed: ' + e.message); }
    });

    getEl('domain-allow-btn')?.addEventListener('click', async () => {
        const domain = getEl('domain-info-title').textContent;
        try {
            await api.apiFetch(api.endpoints.addRule, { method: 'POST', body: JSON.stringify({ domain, action: 'allow' }) });
            helpers.showToast(`${domain} allowed`);
            closeModals();
            fetchService.fetchConfig();
        } catch (e) { helpers.showAlert('Allow failed: ' + e.message); }
    });

    getEl('ip-info-view-all-btn')?.addEventListener('click', () => {
        const ip = getEl('ip-info-subtitle').textContent || getEl('ip-info-title').textContent;
        closeModals();
        nav.navigateTo('queries', { search: ip });
    });
}

window.showListDetails = (list) => {
    const modal = getEl('list-details-modal');
    if (!modal || !list) return;
    getEl('modal-list-name').textContent = list.name || 'List Details';
    const urlEl = getEl('modal-list-url');
    urlEl.textContent = list.url || 'No URL';
    urlEl.href = list.url || '#';
    getEl('modal-list-entries').textContent = (list.entries || 0).toLocaleString();
    getEl('modal-list-updated').textContent = (!list.updated_at || list.updated_at.startsWith('0001')) ? 'Never' : new Date(list.updated_at).toLocaleString();
    modal.classList.remove('hidden');
};

window.openListDetailsModal = (idx, type) => {
    const list = type === 'block' ? state.currentConfig.lists[idx] : state.currentConfig.allowlists[idx];
    window.showListDetails(list);
};

window.showPresetDetails = (idx, type) => {
    const list = type === 'block' ? (state.blockPresets || [])[idx] : (state.allowPresets || [])[idx];
    window.showListDetails(list);
};

window.removeList = async (idx, type, event) => {
    if (!await helpers.showConfirm(`Remove this ${type}list?`)) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, '');

    if (type === 'block') state.currentConfig.lists.splice(idx, 1);
    else state.currentConfig.allowlists.splice(idx, 1);
    
    try {
        await api.apiFetch(api.endpoints.config, { method: 'POST', body: JSON.stringify(state.currentConfig) });
        helpers.showToast('List removed');
        fetchService.fetchConfig();
    } catch(e) { 
        helpers.setBtnLoading(btn, false);
        helpers.showAlert('Failed to remove list: ' + e.message); 
    }
};


window.addCustomRule = async (action, domainArg, event) => {
    const type = action === 'blocked' ? 'block' : 'allow';
    const inputId = action === 'blocked' ? 'custom-block-input' : 'custom-allow-input';
    const domain = domainArg || getEl(inputId)?.value.trim();
    
    if (!domain) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, 'Saving...');
    
    try {
        await api.apiFetch('/api/rules/add', {
            method: 'POST',
            body: JSON.stringify({ domain, type })
        });
        if (getEl(inputId)) getEl(inputId).value = '';
        helpers.showToast(`${domain} added to ${action} list.`);
        fetchService.fetchConfig();
    } catch (e) {
        helpers.showAlert(`Failed to add rule: ${e.message}`);
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
        await api.apiFetch('/api/rules/add', {
            method: 'POST',
            body: JSON.stringify({ domain, ip, type: 'mapping' })
        });
        getEl('custom-map-domain').value = '';
        getEl('custom-map-ip').value = '';
        helpers.showToast(`Mapping ${domain} -> ${ip} created.`);
        fetchService.fetchConfig();
    } catch (e) { 
        helpers.showAlert(`Failed to add mapping: ${e.message}`); 
    } finally {
        helpers.setBtnLoading(btn, false);
    }
};

window.removeCustomRule = async (domain, event) => {
    if (!await helpers.showConfirm(`Are you sure you want to remove the rule for ${domain}?`)) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, '');

    try {
        await api.apiFetch('/api/rules/remove', {
            method: 'POST',
            body: JSON.stringify({ domain })
        });
        helpers.showToast('Rule removed');
        fetchService.fetchConfig();
    } catch (e) { 
        helpers.setBtnLoading(btn, false);
        helpers.showAlert(`Failed to remove rule: ${e.message}`); 
    }
};

window.removeCustomMapping = async (domain, event) => {
    if (!await helpers.showConfirm(`Are you sure you want to remove the mapping for ${domain}?`)) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, '');

    try {
        await api.apiFetch('/api/rules/remove', {
            method: 'POST',
            body: JSON.stringify({ domain })
        });
        helpers.showToast('Mapping removed');
        fetchService.fetchConfig();
    } catch (e) { 
        helpers.setBtnLoading(btn, false);
        helpers.showAlert(`Failed to remove mapping: ${e.message}`); 
    }
};

window.toggleList = async (idx, enabled, type, event) => {
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, '');

    if (type === 'block') state.currentConfig.lists[idx].enabled = enabled;
    else state.currentConfig.allowlists[idx].enabled = enabled;
    
    try {
        await api.apiFetch('/api/config', { method: 'POST', body: JSON.stringify(state.currentConfig) });
        helpers.showToast(enabled ? 'List enabled' : 'List disabled');
        fetchService.fetchConfig();
    } catch(e) { 
        helpers.setBtnLoading(btn, false);
        helpers.showAlert('Failed to toggle list: ' + e.message); 
    }
};

window.removeList = async (idx, type, event) => {
    if (!await helpers.showConfirm('Are you sure you want to remove this list?')) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, '');

    if (type === 'block') state.currentConfig.lists.splice(idx, 1);
    else state.currentConfig.allowlists.splice(idx, 1);
    
    try {
        await api.apiFetch('/api/config', { method: 'POST', body: JSON.stringify(state.currentConfig) });
        helpers.showToast('List removed');
        fetchService.fetchConfig();
    } catch(e) { 
        helpers.setBtnLoading(btn, false);
        helpers.showAlert('Failed to remove list: ' + e.message); 
    }
};

window.removeCountry = async (code, event) => {
    const btn = event?.currentTarget;
    // For small removal icons, we might not want a text spinner, but we can still disable
    if (btn) btn.style.pointerEvents = 'none';

    state.currentConfig.blocked_countries = (state.currentConfig.blocked_countries || []).filter(c => c !== code);
    try {
        await events.saveConfig(fetchService.fetchConfig);
        helpers.showToast(`${code} removed from Geo-Block`);
    } catch (e) {
        if (btn) btn.style.pointerEvents = 'auto';
        helpers.showAlert('Failed to remove country geo-block');
    }
};


window.clearSystemLogs = (event) => {
    const btn = event?.currentTarget;
    if (btn) {
        helpers.setBtnLoading(btn, true, 'Clearing...');
        setTimeout(() => helpers.setBtnLoading(btn, false), 500);
    }
    nav.stopSystemLogStream();
    getEl('system-log-terminal').textContent = 'Terminal cleared. Click a nav item to resume logs.';
};

window.recheckUpstreams = async (btn) => {
    if (btn) helpers.setBtnLoading(btn, true, 'Testing...');
    try {
        await api.apiFetch(api.endpoints.recheckDiagnostics, { method: 'POST' });
        helpers.showToast('Latency re-check triggered. Updating badges...', 'info');
        // Diagnostics are auto-refreshed via the diagnostics view timer, 
        // but we can trigger an immediate one if we are currently looking at it.
        setTimeout(fetchService.fetchDiagnostics, 1500);
    } catch (e) {
        helpers.showAlert('Failed to trigger re-check: ' + e.message);
    } finally {
        if (btn) helpers.setBtnLoading(btn, false);
    }
};
