/**
 * ShieldDNS Main Application Entry Point
 * Migrated to ES6 Modules for Phase 4 (Frontend Polish)
 */
import { VirtualScroller } from './modules/scroller.js';
import * as api from './modules/api.js';
import * as helpers from './modules/ui_helpers.js';
import * as charts from './modules/charts.js';
import * as ui from './modules/ui.js';

// Application State
let currentConfig = {};
let allTokens = [];
let cachedQueries = [];
let activeFetchId = 0;
let fullQueryScroller = null;
let systemLogEventSource = null;
let allCountries = {};

// UI References
const getEl = (id) => document.getElementById(id);
const uiRefs = {
    authOverlay: getEl('auth-overlay'),
    setupView: getEl('setup-view'),
    loginView: getEl('login-view'),
    queryLogItems: getEl('query-log-items'),
    fullQueryLogItems: getEl('full-query-log-items'),
    statsContainer: {
        total: getEl('stat-total'),
        blocked: getEl('stat-blocked'),
        ratio: getEl('stat-ratio'),
        cache: getEl('stat-cache'),
        latency: getEl('stat-latency'),
        clients: getEl('stat-clients')
    }
};

/**
 * Global Initialization
 */
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initNavigation();
    
    // Attach Setup/Auth listeners globally
    getEl('setup-finish-btn')?.addEventListener('click', finishSetup);
    getEl('login-confirm-btn')?.addEventListener('click', handleLogin);
    getEl('login-password')?.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleLogin();
    });

    checkAuthStatus();
});

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
        sidebar.classList.toggle('open');
        sidebarOverlay.classList.toggle('open');
    };
    getEl('sidebar-toggle')?.addEventListener('click', toggleSidebar);
    sidebarOverlay?.addEventListener('click', toggleSidebar);
}

/**
 * Auth Logic
 */
async function checkAuthStatus() {
    try {
        const data = await api.apiFetch(api.endpoints.authStatus).catch(e => {
            if (e.message === 'SETUP_REQUIRED') {
                return { need_setup: true, logged_in: false };
            }
            throw e;
        });

        if (data.need_setup) {
            showView('setup');
        } else if (!data.logged_in) {
            showView('login');
        } else {
            uiRefs.authOverlay.classList.add('hidden');
            initializeApp();
        }
    } catch (e) {
        // Fallback for simple auth-status endpoint if token path isn't used
        const data = await api.apiFetch('/api/auth-status');
        if (data.need_setup) {
            uiRefs.authOverlay.classList.remove('hidden');
            uiRefs.setupView.classList.remove('hidden');
        } else if (!data.logged_in) {
            uiRefs.authOverlay.classList.remove('hidden');
            uiRefs.loginView.classList.remove('hidden');
        } else {
            uiRefs.authOverlay.classList.add('hidden');
            initializeApp();
        }
    }
}

function showView(viewId) {
    uiRefs.authOverlay.classList.remove('hidden');
    uiRefs.setupView.classList.toggle('hidden', viewId !== 'setup');
    uiRefs.loginView.classList.toggle('hidden', viewId !== 'login');

    if (viewId === 'setup') {
        const domainInput = getEl('setup-admin-domain');
        if (domainInput && !domainInput.value) {
            domainInput.value = window.location.hostname;
        }
    }
}

/**
 * App Initialization
 */
function initializeApp() {
    initNavigation();
    refreshAll();
    startSSE();
    
    // Auto-refresh loops
    setInterval(fetchStats, 10000);
    setInterval(fetchHistory, 60000);
}

async function refreshAll() {
    await Promise.all([
        fetchStats(),
        fetchConfig(),
        fetchQueries(true),
        fetchHistory(),
        fetchAPIKeys(),
        fetchCountries()
    ]);
}

/**
 * Navigation
 */
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-view');
            if (!target) return;
            
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
            document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
            getEl(target)?.classList.remove('hidden');
            
            if (window.innerWidth < 992) {
                document.querySelector('.sidebar').classList.remove('open');
                getEl('sidebar-overlay').classList.remove('open');
            }
        });
    });
}

/**
 * API Fetchers
 */
async function fetchStats() {
    try {
        const data = await api.apiFetch(api.endpoints.stats);
        renderDashStats(data);
        if (data.query_types) {
            charts.renderTypeChart(data.query_types, (type) => {
                const searchInput = getEl('query-search');
                if (searchInput) {
                    searchInput.value = type;
                    fetchQueries(true);
                    getEl('nav-queries')?.click(); // Jump to query view
                }
            });
        }
    } catch (e) { console.error('Stats fetch failed', e); }
}

async function fetchHistory() {
    try {
        const data = await api.apiFetch(api.endpoints.history);
        charts.renderTrafficChart(data, (hour) => {
             // Interactivity: Highlight or filter by hour
             const searchInput = getEl('query-search');
             if (searchInput) {
                 searchInput.value = hour.split(':')[0].padStart(2, '0'); // Filter by hour prefix
                 fetchQueries(true);
                 getEl('nav-queries')?.click();
             }
        });
    } catch (e) { console.error('History fetch failed', e); }
}

async function fetchQueries(immediate = false) {
    const search = getEl('query-search')?.value.trim() || '';
    const status = getEl('query-filter-status')?.value || '';
    
    const fetchId = ++activeFetchId;
    if (uiRefs.fullQueryLogItems) {
        uiRefs.fullQueryLogItems.innerHTML = '<tr><td colspan="6" class="help"><i class="fas fa-spinner fa-spin"></i> Searching...</td></tr>';
    }

    try {
        const queries = await api.apiFetch(`${api.endpoints.queries}?search=${encodeURIComponent(search)}&status=${status}`);
        if (fetchId === activeFetchId) {
            renderQueries(queries);
        }
    } catch (e) { console.error('Queries fetch failed', e); }
}

/**
 * Renderers
 */
function renderDashStats(data) {
    const c = uiRefs.statsContainer;
    if (!c.total) return;
    c.total.textContent = data.total_queries.toLocaleString();
    c.blocked.textContent = data.blocked_queries.toLocaleString();
    c.ratio.textContent = `${(data.total_queries > 0 ? (data.blocked_queries/data.total_queries*100) : 0).toFixed(1)} %`;
    c.cache.textContent = `${(data.total_queries > 0 ? (data.cache_hits/data.total_queries*100) : 0).toFixed(1)} %`;
    c.latency.textContent = `${(data.average_latency || 0).toFixed(2)} ms`;
    c.clients.textContent = data.unique_clients || 0;
    
    const appVer = getEl('app-version');
    if (appVer) appVer.textContent = data.version;
}

function renderQueries(queries) {
    if (!fullQueryScroller && uiRefs.fullQueryLogItems) {
        fullQueryScroller = new VirtualScroller('full-query-log-items', 48, createQueryRow);
    }

    if (uiRefs.queryLogItems) {
        uiRefs.queryLogItems.innerHTML = '';
        queries.slice(0, 15).forEach(q => uiRefs.queryLogItems.appendChild(createQueryRow(q)));
    }

    if (fullQueryScroller) {
        cachedQueries = queries;
        fullQueryScroller.setData(queries);
    }
}

function createQueryRow(q) {
    const row = document.createElement('tr');
    const time = new Date(q.time || Date.now()).toLocaleTimeString();
    const actionBtn = q.status === 'Allowed' ?
        `<button class="btn btn-sm secondary" data-action="block" data-domain="${q.domain}">Block</button>` :
        `<button class="btn btn-sm secondary" data-action="allow" data-domain="${q.domain}">Allow</button>`;

    const clientDisplay = q.client_alias ? `${q.client_alias} (${q.client_ip})` : q.client_ip;

    row.innerHTML = `
        <td>${time}</td>
        <td><span class="domain-link" title="${q.domain}">${q.domain}</span></td>
        <td><span class="ip-link" title="${q.client_ip}">${clientDisplay}</span></td>
        <td class="hide-mobile">${q.type}</td>
        <td><span class="status-badge ${q.status.toLowerCase()}">${q.status}</span></td>
        <td class="hide-mobile">${actionBtn}</td>
    `;
    
    // Add Event Listeners for links and buttons (better than inline onclick)
    row.querySelector('.domain-link').onclick = () => showDomainDetails(q.domain);
    row.querySelector('.ip-link').onclick = () => showIPDetails(q.client_ip);
    row.querySelector('button')?.addEventListener('click', async (e) => {
        const action = e.target.getAttribute('data-action');
        const domain = e.target.getAttribute('data-domain');
        // Logic for quick block/allow would go here
        console.log(`Log action: ${action} ${domain}`);
    });

    return row;
}

/**
 * SSE Real-time Events
 */
function startSSE() {
    if (systemLogEventSource) systemLogEventSource.close();
    systemLogEventSource = new EventSource(api.endpoints.events);
    systemLogEventSource.onmessage = (event) => {
        const query = JSON.parse(event.data);
        if (query.type === 'ping') return;
        
        if (uiRefs.queryLogItems) {
            const row = createQueryRow(query);
            uiRefs.queryLogItems.prepend(row);
            if (uiRefs.queryLogItems.children.length > 15) uiRefs.queryLogItems.lastElementChild.remove();
        }
        
        if (fullQueryScroller) {
            // Only prepend if it matches current filter (simplified for now)
            fullQueryScroller.prepend(query);
        }
    };
}

/**
 * Setup Wizard Logic
 */
async function nextSetupStep(step) {
    // Hide all panes
    document.querySelectorAll('.setup-pane').forEach(p => p.classList.add('hidden'));
    const targetPane = document.getElementById(`setup-pane-${step}`);
    if (targetPane) targetPane.classList.remove('hidden');
    
    // Update step indicators
    document.querySelectorAll('.w-step').forEach(s => s.classList.remove('active'));
    document.getElementById(`w-step-${step}`)?.classList.add('active');

    // If reaching step 3 (Blocklists), load presets to choose from
    if (step === 3) {
        await loadSetupPresets();
    }
}

async function loadSetupPresets() {
    const container = document.getElementById('setup-presets');
    if (!container || container.children.length > 0) return;
    
    try {
        const presets = await api.apiFetch(api.endpoints.presets);
        container.innerHTML = '';
        // Show first 6 popular presets as sensible defaults
        presets.slice(0, 6).forEach(p => {
            const div = document.createElement('div');
            div.className = 'preset-item-minimal';
            div.style.display = 'flex';
            div.style.alignItems = 'center';
            div.style.gap = '10px';
            div.style.marginBottom = '8px';
            div.innerHTML = `
                <input type="checkbox" id="setup-preset-${p.name}" data-url="${p.url}" data-name="${p.name}" checked>
                <label for="setup-preset-${p.name}" style="cursor:pointer;">${p.name} <span class="help" style="font-size:0.7rem; opacity:0.6;">(${p.category || 'General'})</span></label>
            `;
            container.appendChild(div);
        });
    } catch (e) {
        console.error('Failed to load setup presets', e);
    }
}

async function finishSetup() {
    const pwd = document.getElementById('setup-password').value;
    const confirm = document.getElementById('setup-confirm').value;
    
    if (pwd.length < 12) {
        helpers.showAlert('Password must be at least 12 characters long');
        return;
    }
    if (pwd !== confirm) {
        helpers.showAlert('Passwords do not match');
        return;
    }
    
    const finishBtn = document.getElementById('setup-finish-btn');
    const originalText = finishBtn.innerHTML;
    finishBtn.disabled = true;
    finishBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Finalizing...';
    
    try {
        // 1. Initial Setup (Password)
        await api.apiFetch('/api/setup', {
            method: 'POST',
            body: JSON.stringify({ password: pwd })
        });
        
        // 2. Immediate Login to authorize further config
        await api.apiFetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ password: pwd })
        });
        
        // 3. Save Wizard Selections (Upstreams & Blocklists)
        const upstreams = document.getElementById('setup-upstreams').value.split(',').map(s => s.trim()).filter(s => s);
        const dotUpstreams = document.getElementById('setup-dot-upstreams').value.split(',').map(s => s.trim()).filter(s => s);
        const adminDomain = document.getElementById('setup-admin-domain').value.trim() || 'shielddns.local';
        const preferEncrypted = document.getElementById('setup-prefer-encrypted').checked;
        
        const selectedLists = [];
        document.querySelectorAll('#setup-presets input:checked').forEach(input => {
            selectedLists.push({
                name: input.getAttribute('data-name'),
                url: input.getAttribute('data-url'),
                enabled: true
            });
        });

        // Use standard config endpoint to save wizard state
        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify({
                upstreams,
                upstream_dot: dotUpstreams,
                admin_domain: adminDomain,
                prefer_encrypted: preferEncrypted,
                lists: selectedLists,
                setup_done: true
            })
        });
        
        await helpers.showAlert('Setup completed! ShieldDNS is now active and securing your devices.', 'Success');
        window.location.reload(); 
        
    } catch (e) {
        helpers.showAlert('Setup failed: ' + e.message);
        finishBtn.disabled = false;
        finishBtn.innerHTML = originalText;
    }
}

async function handleLogin() {
    const pwd = document.getElementById('login-password').value;
    if (!pwd) return;

    try {
        await api.apiFetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ password: pwd })
        });
        window.location.reload();
    } catch (e) {
        helpers.showAlert('Login failed: ' + e.message);
    }
}

// Global window exposed functions for transition
window.nextSetupStep = nextSetupStep;
window.fetchQueries = fetchQueries;
window.refreshAll = refreshAll;
window.showDomainDetails = showDomainDetails;
window.showIPDetails = showIPDetails;
window.editAPIKey = editAPIKey;
window.deleteAPIKey = deleteAPIKey;
window.clearSystemLogs = () => {
    const term = getEl('system-log-terminal');
    if (term) term.innerHTML = '';
};

window.addCustomRule = async (action) => {
    const type = action === 'blocked' ? 'block' : 'allow';
    const inputId = action === 'blocked' ? 'custom-block-input' : 'custom-allow-input';
    const domain = getEl(inputId)?.value.trim();
    
    if (!domain) return;
    
    try {
        await api.apiFetch('/api/rules/add', {
            method: 'POST',
            body: JSON.stringify({ domain, type })
        });
        getEl(inputId).value = '';
        helpers.showAlert(`${domain} added to ${action} list.`, 'Success');
        fetchConfig(); // Reload config
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
        fetchConfig(); // Reload config
    } catch (e) {
        helpers.showAlert(`Failed to add mapping: ${e.message}`, 'Error');
    }
};

window.removeCustomRule = async (domain) => {
    if (!await helpers.showConfirm(`Are you sure you want to remove the rule for ${domain}?`)) return;
    try {
        await api.apiFetch('/api/rules/remove', {
            method: 'POST',
            body: JSON.stringify({ domain })
        });
        fetchConfig();
    } catch (e) {
        helpers.showAlert(`Failed to remove rule: ${e.message}`, 'Error');
    }
};

/**
 * Fetch Other Resources
 */
async function fetchConfig() {
    try {
        currentConfig = await api.apiFetch(api.endpoints.config);
        renderConfig(currentConfig);
    } catch(e) { console.error('Config fetch failed', e); }
}

function renderConfig(cfg) {
    const domain = cfg.admin_domain || window.location.hostname;

    // Connection Guide
    const dotHost = getEl('guide-dot-host');
    const dotUrl = getEl('guide-dot-url');
    const dohUrl = getEl('guide-doh-url');
    const doqUrl = getEl('guide-doq-url');
    if (dotHost) dotHost.value = domain;
    if (dotUrl) dotUrl.value = `tls://${domain}`;
    if (dohUrl) dohUrl.value = `https://${domain}/dns-query`;
    if (doqUrl) doqUrl.value = `quic://${domain}`;

    // Last Login
    const lastLoginEl = getEl('dashboard-last-login');
    if (lastLoginEl && cfg.previous_login) {
        const prev = new Date(cfg.previous_login);
        if (prev.getTime() > 0) {
            lastLoginEl.textContent = `Last login: ${prev.toLocaleString()}`;
        }
    }

    // Populate Settings form if visible
    const upstreamsInput = getEl('upstreams-input');
    if (upstreamsInput) upstreamsInput.value = (cfg.upstreams || []).join(', ');
    const dotInput = getEl('dot-upstreams-input');
    if (dotInput) dotInput.value = (cfg.upstream_dot || []).join(', ');
    const adminDomainInput = getEl('admin-domain-input');
    if (adminDomainInput) adminDomainInput.value = cfg.admin_domain || '';
    const blockIpInput = getEl('block-ip-input');
    if (blockIpInput) blockIpInput.value = cfg.block_page_ip || '';
    const preferEncCheck = getEl('prefer-encrypted-check');
    if (preferEncCheck) preferEncCheck.checked = !!cfg.prefer_encrypted;
    const debugCheck = getEl('debug-mode-check');
    if (debugCheck) debugCheck.checked = !!cfg.debug_mode;
    const signCheck = getEl('sign-mobileconfig-check');
    if (signCheck) signCheck.checked = !!cfg.sign_mobileconfig;
    const abuseCheck = getEl('abuse-detection-check');
    if (abuseCheck) abuseCheck.checked = !!cfg.abuse_detection_enabled;

    // Render Custom Rules Lists
    const blockList = getEl('custom-blocked-list');
    if (blockList) {
        blockList.innerHTML = '';
        (cfg.custom_blocked || []).forEach(domain => {
            const div = document.createElement('div');
            div.className = 'list-item';
            div.innerHTML = `<span>${domain}</span><button class="btn danger sm" onclick="removeCustomRule('${domain}')"><i class="fas fa-trash"></i></button>`;
            blockList.appendChild(div);
        });
    }

    const allowList = getEl('custom-allowed-list');
    if (allowList) {
        allowList.innerHTML = '';
        (cfg.custom_allowed || []).forEach(domain => {
            const div = document.createElement('div');
            div.className = 'list-item';
            div.innerHTML = `<span>${domain}</span><button class="btn danger sm" onclick="removeCustomRule('${domain}')"><i class="fas fa-trash"></i></button>`;
            allowList.appendChild(div);
        });
    }

    const mappingsList = getEl('custom-mappings-list');
    if (mappingsList && cfg.custom_mappings) {
        mappingsList.innerHTML = '';
        Object.entries(cfg.custom_mappings).forEach(([domain, ip]) => {
            const div = document.createElement('div');
            div.className = 'list-item';
            div.innerHTML = `<span>${domain} &rarr; ${ip}</span><button class="btn danger sm" onclick="removeCustomRule('${domain}')"><i class="fas fa-trash"></i></button>`;
            mappingsList.appendChild(div);
        });
    }
}

async function fetchAPIKeys() { try { allTokens = await api.apiFetch(api.endpoints.tokens); ui.renderAPIKeys(allTokens, allTokens, getEl('api-keys-list'), editAPIKey, deleteAPIKey); } catch(e) {} }
async function fetchCountries() { try { allCountries = await api.apiFetch(api.endpoints.countries); } catch(e) {} }

// Placeholder for remaining specialized logic (Aliases, Rules, etc)
// In a real implementation, these would be in js/modules/rules.js etc.
function showDomainDetails(d) { console.log('Domain Details', d); }
function showIPDetails(ip) { console.log('IP Details', ip); }
function editAPIKey(id) { console.log('Edit API Key', id); }
function deleteAPIKey(id) { console.log('Delete API Key', id); }
