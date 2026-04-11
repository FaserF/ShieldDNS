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
        const data = await api.apiFetch(api.endpoints.tokens + '/status').catch(e => {
            if (e.message === 'SETUP_REQUIRED') return { need_setup: true };
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
            getEl(`${target}-view`)?.classList.remove('hidden');
            
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

// Global window exposed functions for transition
window.fetchQueries = fetchQueries;
window.refreshAll = refreshAll;
window.showDomainDetails = showDomainDetails;
window.showIPDetails = showIPDetails;
window.editAPIKey = editAPIKey;
window.deleteAPIKey = deleteAPIKey;
window.addCustomRule = (action, domain) => {
    console.log(`Adding ${action} rule for ${domain}`);
    // implementation...
};

/**
 * Fetch Other Resources
 */
async function fetchConfig() { try { currentConfig = await api.apiFetch(api.endpoints.config); } catch(e) {} }
async function fetchAPIKeys() { try { allTokens = await api.apiFetch(api.endpoints.tokens); ui.renderAPIKeys(allTokens, allTokens, getEl('api-keys-list'), editAPIKey, deleteAPIKey); } catch(e) {} }
async function fetchCountries() { try { allCountries = await api.apiFetch(api.endpoints.countries); } catch(e) {} }

// Placeholder for remaining specialized logic (Aliases, Rules, etc)
// In a real implementation, these would be in js/modules/rules.js etc.
function showDomainDetails(d) { console.log('Domain Details', d); }
function showIPDetails(ip) { console.log('IP Details', ip); }
function editAPIKey(id) { console.log('Edit API Key', id); }
function deleteAPIKey(id) { console.log('Delete API Key', id); }
