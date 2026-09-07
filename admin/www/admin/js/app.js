/**
 * ShieldDNS Main Application Entry Point
 * Modular architecture for improved maintainability.
 */
import { state, uiRefs, getEl, updateUIRefs } from './core/state.js';
import * as auth from './core/auth.js';
import * as nav from './core/navigation.js';
import * as fetchService from './services/fetch.js';
import * as events from './ui/events.js';
import * as render from './ui/renderers.js';
import * as api from './services/api.js';
import * as helpers from './ui/helpers.js';
import { showActivityOverlay, hideActivityOverlay } from './ui/activity.js';
import { initClusterUI } from './ui/cluster.js';
import { initModalsUI } from './ui/modals.js';

/**
 * Global Initialization
 */
window.state = state; // Expose for testing/debugging

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    
    // Attach Setup/Auth listeners globally
    getEl('setup-finish-btn')?.addEventListener('click', auth.finishSetup);
    getEl('setup-join-cluster-btn')?.addEventListener('click', auth.joinClusterSetup);
    getEl('setup-preset-selector')?.addEventListener('change', (e) => {
        auth.applySetupPreset(e.target.value);
    });
    getEl('login-passkey-btn')?.addEventListener('click', auth.handlePasskeyLogin);
    getEl('login-confirm-btn')?.addEventListener('click', auth.handleLogin);
    getEl('login-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') auth.handleLogin();
    });
    
    getEl('mfa-confirm-btn')?.addEventListener('click', auth.handleMFAVerify);
    getEl('mfa-code')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') auth.handleMFAVerify();
    });
    getEl('mfa-use-passkey-btn')?.addEventListener('click', auth.handlePasskeyLogin);
    getEl('mfa-use-totp-btn')?.addEventListener('click', () => {
        getEl('mfa-method-selector').classList.add('hidden');
        getEl('mfa-totp-input-area').classList.remove('hidden');
        getEl('mfa-code').focus();
    });
    getEl('mfa-back-to-selector')?.addEventListener('click', () => {
        getEl('mfa-totp-input-area').classList.add('hidden');
        getEl('mfa-method-selector').classList.remove('hidden');
    });

    auth.checkAuthStatus(initializeApp);

    // Global cleanup on window close
    window.addEventListener('beforeunload', () => {
        nav.stopSSE();
        nav.stopSystemLogStream();
        nav.stopDiagTimer();
    });
});

/**
 * App Initialization
 */
function initializeApp() {
    // 0. Ensure UI references are captured
    updateUIRefs();
    initModalsUI();
    initClusterUI();
    
    // 1. Init Navigation with view-specific handlers
    nav.initNavigation({
        'queries': () => fetchService.fetchQueries(),
        'analytics': () => fetchService.fetchAnalytics(),
        'system-logs': () => nav.startSystemLogStream(),
        'diagnostics': () => { fetchService.fetchDiagnostics(); nav.startDiagTimer(() => fetchService.fetchDiagnostics()); },
        'lists': () => { fetchService.fetchPresets(); fetchService.fetchAllowlistPresets(); },
        'settings': () => { fetchService.fetchConfig(); fetchService.fetchAPIKeys(); },
        'dashboard': () => fetchService.fetchStats(),
        'about': () => loadAboutData(),
        'privacy': () => loadPrivacyStatus()
    });

    // 2. Init global event listeners
    events.initEvents(fetchService.fetchConfig);
    
    // 3. Initial data load
    refreshAll();
    
    // 4. Start real-time stream
    nav.startSSE(render.createQueryRow, updateDashboardFeed);
    
    // 5. Auto-refresh loops
    setInterval(fetchService.fetchStats, 30000);
    setInterval(fetchService.fetchHistory, 60000);

    // 6. Feature init
    initDohFilterToggle();
    initMobileTooltips();
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
    events.detectServerLocation();
}

function updateDashboardFeed(query) {
    if (!uiRefs.queryLogItems) return;
    // Skip DoH proxy entries when filter is active
    if (state.filterDohProxy &&
        (query.client_ip === '127.0.0.1' || query.client_ip === '::1' || query.client_ip === '::ffff:127.0.0.1')) {
        return;
    }
    const row = render.createQueryRow(query);
    uiRefs.queryLogItems.prepend(row);
    if (uiRefs.queryLogItems.children.length > 20) uiRefs.queryLogItems.lastElementChild.remove();
}

/**
 * Reveal the DoH-filter toggle once we've seen at least one 127.0.0.1 query,
 * meaning the DoH proxy is actually active on this installation.
 */
function initDohFilterToggle() {
    const toggle = getEl('doh-filter-toggle');
    const label = getEl('doh-filter-label');
    if (!toggle || !label) return;

    toggle.addEventListener('change', () => {
        state.filterDohProxy = toggle.checked;
        // Re-render current cached queries with new filter
        render.renderQueries(state.cachedQueries || []);
    });

    // Show the toggle once a DoH proxy request is detected in cached queries
    function checkForDohQueries() {
        const cached = state.cachedQueries || [];
        const hasDoh = cached.some(q =>
            q.client_ip === '127.0.0.1' || q.client_ip === '::1' || q.client_ip === '::ffff:127.0.0.1'
        );
        if (hasDoh) label.style.display = '';
    }

    // Poll once initially after data loads, then on each update
    setTimeout(checkForDohQueries, 2000);
    setInterval(checkForDohQueries, 30000);
}

/**
 * Mobile tooltip: tap .info-icon or [data-tooltip] to toggle tooltip visibility.
 * Tapping outside dismisses all open tooltips.
 */
function initMobileTooltips() {
    const isTouchDevice = () => window.matchMedia('(hover: none)').matches;

    document.addEventListener('click', (e) => {
        if (!isTouchDevice()) return;

        const target = e.target.closest('[data-tooltip]');
        if (target) {
            e.preventDefault();
            const wasActive = target.classList.contains('tooltip-active');
            // Close all open tooltips first
            document.querySelectorAll('[data-tooltip].tooltip-active')
                .forEach(el => el.classList.remove('tooltip-active'));
            if (!wasActive) target.classList.add('tooltip-active');
        } else {
            // Tap outside → close all
            document.querySelectorAll('[data-tooltip].tooltip-active')
                .forEach(el => el.classList.remove('tooltip-active'));
        }
    }, true);
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
window.navigateTo = nav.navigateTo;
window.refreshAll = refreshAll;
window.showDomainDetails = (domain) => fetchService.fetchDomainDetails(domain);
window.showIPDetails = (ip) => fetchService.fetchIPDetails(ip);

window.toggleLiveUpdate = () => {
    state.liveUpdatesEnabled = !state.liveUpdatesEnabled;
    const btn = document.getElementById('live-update-toggle');
    if (btn) {
        if (state.liveUpdatesEnabled) {
            btn.innerHTML = '<i class="fas fa-pause"></i> <span>Pause Live</span>';
            btn.classList.remove('primary');
        } else {
            btn.innerHTML = '<i class="fas fa-play"></i> <span>Resume Live</span>';
            btn.classList.add('primary');
        }
    }
};

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

window.removeCustomRule = async (domain, event) => {
    if (!await helpers.showConfirm(`Are you sure you want to remove the rule for ${domain}?`, 'Remove Rule', true)) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, 'Removing...');

    try {
        await api.apiFetch(api.endpoints.removeRule, {
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
    helpers.setBtnLoading(btn, true, 'Removing...');

    try {
        await api.apiFetch(api.endpoints.removeRule, {
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
    helpers.setBtnLoading(btn, true, 'Saving...');

    if (type === 'block') state.currentConfig.lists[idx].enabled = enabled;
    else state.currentConfig.allowlists[idx].enabled = enabled;
    
    try {
        await api.apiFetch(api.endpoints.config, { method: 'POST', body: JSON.stringify(state.currentConfig) });
        helpers.showToast(enabled ? 'List enabled' : 'List disabled');
        fetchService.fetchConfig();
    } catch(e) { 
        helpers.setBtnLoading(btn, false);
        helpers.showAlert('Failed to toggle list: ' + e.message); 
    }
};

window.removeList = async (idx, type, event) => {
    if (!await helpers.showConfirm(`Remove this ${type}list?`, 'Remove List', true)) return;
    
    const btn = event?.currentTarget;
    helpers.setBtnLoading(btn, true, 'Removing...');

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

window.removeCountry = async (code, event) => {
    const btn = event?.currentTarget;
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
        setTimeout(fetchService.fetchDiagnostics, 1500);
    } catch (e) {
        helpers.showAlert('Failed to trigger re-check: ' + e.message);
    } finally {
        if (btn) helpers.setBtnLoading(btn, false);
    }
};

async function loadAboutData() {
    try {
        const [statsRes, contribsRes] = await Promise.all([
            fetch('assets/project_stats.json').then(r => r.ok ? r.json() : null),
            fetch('assets/contributors.json').then(r => r.ok ? r.json() : null)
        ]);
        if (statsRes || contribsRes) {
            render.renderAboutData(statsRes, contribsRes);
        }
    } catch (e) {
        console.error('Failed to load about data:', e);
    }
}

function loadPrivacyStatus() {
    const cfg = state.currentConfig;
    if (!cfg) {
        fetchService.fetchConfig().then(() => loadPrivacyStatus());
        return;
    }

    const setBadge = (id, text, colorClass) => {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        el.className = 'badge';
        if (colorClass) el.classList.add(colorClass);
    };

    if (cfg.anonymize_client_ips) {
        setBadge('privacy-anon-badge', 'Active — /24 IPv4, /64 IPv6', 'success');
    } else {
        setBadge('privacy-anon-badge', 'Disabled — Full IPs stored', 'warning');
    }

    if (cfg.strip_ecs) {
        setBadge('privacy-ecs-badge', 'Active — No subnet forwarded', 'success');
    } else {
        setBadge('privacy-ecs-badge', 'Disabled — Subnet may be forwarded', 'warning');
    }

    const hasUpstreams = Array.isArray(cfg.upstream_dns) && cfg.upstream_dns.length > 0;
    const hasDoT = Array.isArray(cfg.upstream_dot) && cfg.upstream_dot.length > 0;
    if (hasDoT) {
        setBadge('privacy-encrypt-badge', 'DNS-over-TLS (DoT)', 'success');
    } else if (hasUpstreams) {
        setBadge('privacy-encrypt-badge', 'Configured', 'official');
    } else {
        setBadge('privacy-encrypt-badge', 'System default', 'official');
    }

    const days = cfg.retention_days;
    if (days === 0 || days === undefined) {
        setBadge('privacy-retention-badge', 'No logging (0 days)', 'success');
    } else {
        setBadge('privacy-retention-badge', `${days} day${days !== 1 ? 's' : ''} — auto-purged`, 'official');
    }

    if (cfg.filtering_enabled !== false) {
        setBadge('privacy-filter-badge', 'Active — Malware & Trackers Blocked', 'success');
    } else {
        setBadge('privacy-filter-badge', 'Disabled', 'warning');
    }
}
