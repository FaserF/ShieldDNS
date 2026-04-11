/**
 * ShieldDNS Main Application Entry Point
 * Refactored into a modular structure for improved maintainability.
 */
import { state, uiRefs, getEl } from './core/state.js';
import * as auth from './core/auth.js';
import * as nav from './core/navigation.js';
import * as fetchService from './services/fetch.js';
import * as events from './ui/events.js';
import * as render from './ui/renderers.js';
import * as api from './services/api.js';
import * as helpers from './ui/helpers.js';
import * as uiModules from './ui/ui.js';

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
    // 1. Init Navigation with view-specific handlers
    nav.initNavigation({
        'queries': () => fetchService.fetchQueries(),
        'analytics': () => fetchService.fetchAnalytics(),
        'system-logs': () => nav.startSystemLogStream(),
        'diagnostics': () => { fetchService.fetchDiagnostics(); nav.startDiagTimer(() => fetchService.fetchDiagnostics()); },
        'lists': () => { fetchService.fetchPresets(); fetchService.fetchAllowlistPresets(); },
        'settings': () => fetchService.fetchConfig(),
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
    document.body.className = savedTheme;
    getEl('theme-toggle')?.addEventListener('click', () => {
        const newTheme = document.body.classList.contains('dark') ? 'light' : 'dark';
        document.body.className = newTheme;
        localStorage.setItem('theme', newTheme);
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
window.showDomainDetails = (domain) => { /* logic to open modal */ console.log('Domain Details:', domain); };
window.showIPDetails = (ip) => { /* logic to open modal */ console.log('IP Details:', ip); };

window.addPreset = async (name, url) => {
    if (state.currentConfig.lists.some(l => l.url === url)) return helpers.showAlert('List already added');
    state.currentConfig.lists.push({ name, url, enabled: true });
    await events.saveConfig(fetchService.fetchConfig);
};

window.addAllowPreset = async (name, url) => {
    if (state.currentConfig.allowlists.some(l => l.url === url)) return helpers.showAlert('Allowlist already added');
    state.currentConfig.allowlists.push({ name, url, enabled: true, category: 'Official' });
    await events.saveConfig(fetchService.fetchConfig);
};

window.addCustomRule = async (action, domainArg) => {
    const type = action === 'blocked' ? 'block' : 'allow';
    const inputId = action === 'blocked' ? 'custom-block-input' : 'custom-allow-input';
    const domain = domainArg || getEl(inputId)?.value.trim();
    
    if (!domain) return;
    
    try {
        await api.apiFetch('/api/rules/add', {
            method: 'POST',
            body: JSON.stringify({ domain, type })
        });
        if (getEl(inputId)) getEl(inputId).value = '';
        helpers.showAlert(`${domain} added to ${action} list.`, 'Success');
        fetchService.fetchConfig();
    } catch (e) {
        helpers.showAlert(`Failed to add rule: ${e.message}`, 'Error');
    }
};

window.addCustomMapping = async () => {
    const domain = getEl('custom-map-domain')?.value.trim();
    const ip = getEl('custom-map-ip')?.value.trim();
    if (!domain || !ip) return helpers.showAlert('Both Domain and IP are required.');
    
    try {
        await api.apiFetch('/api/rules/add', {
            method: 'POST',
            body: JSON.stringify({ domain, ip, type: 'mapping' })
        });
        getEl('custom-map-domain').value = '';
        getEl('custom-map-ip').value = '';
        helpers.showAlert(`Mapping ${domain} -> ${ip} added.`, 'Success');
        fetchService.fetchConfig();
    } catch (e) { helpers.showAlert(`Failed to add mapping: ${e.message}`, 'Error'); }
};

window.removeCustomRule = async (domain) => {
    if (!await helpers.showConfirm(`Are you sure you want to remove the rule for ${domain}?`)) return;
    try {
        await api.apiFetch('/api/rules/remove', {
            method: 'POST',
            body: JSON.stringify({ domain })
        });
        fetchService.fetchConfig();
    } catch (e) { helpers.showAlert(`Failed to remove rule: ${e.message}`, 'Error'); }
};

window.removeCustomMapping = async (domain) => {
    if (!await helpers.showConfirm(`Are you sure you want to remove the mapping for ${domain}?`)) return;
    try {
        await api.apiFetch('/api/rules/remove', {
            method: 'POST',
            body: JSON.stringify({ domain })
        });
        fetchService.fetchConfig();
    } catch (e) { helpers.showAlert(`Failed to remove mapping: ${e.message}`, 'Error'); }
};

window.toggleList = async (idx, enabled, type) => {
    if (type === 'block') state.currentConfig.lists[idx].enabled = enabled;
    else state.currentConfig.allowlists[idx].enabled = enabled;
    try {
        await api.apiFetch('/api/config', { method: 'POST', body: JSON.stringify(state.currentConfig) });
        fetchService.fetchConfig();
    } catch(e) { helpers.showAlert('Failed to toggle list'); }
};

window.removeList = async (idx, type) => {
    if (!await helpers.showConfirm('Remove this list?')) return;
    if (type === 'block') state.currentConfig.lists.splice(idx, 1);
    else state.currentConfig.allowlists.splice(idx, 1);
    try {
        await api.apiFetch('/api/config', { method: 'POST', body: JSON.stringify(state.currentConfig) });
        fetchService.fetchConfig();
    } catch(e) { helpers.showAlert('Failed to remove list'); }
};

window.removeCountry = async (code) => {
    state.currentConfig.blocked_countries = (state.currentConfig.blocked_countries || []).filter(c => c !== code);
    await events.saveConfig(fetchService.fetchConfig);
};

window.openListDetailsModal = (idx, type) => {
    const list = type === 'block' ? state.currentConfig.lists[idx] : state.currentConfig.allowlists[idx];
    const modal = getEl('list-details-modal');
    if (!modal || !list) return;
    getEl('modal-list-name').textContent = list.name || 'List Details';
    const urlEl = getEl('modal-list-url');
    urlEl.textContent = list.url || 'No URL';
    urlEl.href = list.url || '#';
    getEl('modal-list-entries').textContent = (list.entries || 0).toLocaleString();
    getEl('modal-list-updated').textContent = list.updated_at ? new Date(list.updated_at).toLocaleString() : 'Never';
    modal.classList.remove('hidden');
};

window.clearSystemLogs = nav.stopSystemLogStream; // Or nav.clearSystemLogs if implemented
