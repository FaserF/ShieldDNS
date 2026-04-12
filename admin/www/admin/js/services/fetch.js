/**
 * High-level Data Fetching Service
 */
import * as api from './api.js';
import { state, getEl, uiRefs } from '../core/state.js';
import * as render from '../ui/renderers.js';
import * as charts from '../ui/charts.js';
import * as helpers from '../ui/helpers.js';

export async function fetchStats() {
    try {
        const data = await api.apiFetch(api.endpoints.stats);
        render.renderDashStats(data);
        if (data.query_types) {
            charts.renderTypeChart(data.query_types, (type) => {
                const searchInput = getEl('query-search');
                if (searchInput) {
                    searchInput.value = type;
                    fetchQueries(true);
                    getEl('nav-queries')?.click();
                }
            });
        }
    } catch (e) { console.error('Stats fetch failed', e); }
}

export async function fetchHistory() {
    try {
        const data = await api.apiFetch(api.endpoints.history);
        charts.renderTrafficChart(data, (hour) => {
             const searchInput = getEl('query-search');
             if (searchInput) {
                 searchInput.value = hour.split(':')[0].padStart(2, '0');
                 fetchQueries(true);
                 getEl('nav-queries')?.click();
             }
        });
    } catch (e) { console.error('History fetch failed', e); }
}

export async function fetchQueries(immediate = false) {
    const search = getEl('query-search')?.value.trim() || '';
    const status = getEl('query-filter-status')?.value || '';
    
    const fetchId = ++state.activeFetchId;
    if (uiRefs.fullQueryLogItems) {
        uiRefs.fullQueryLogItems.innerHTML = '<tr><td colspan="6" class="help"><i class="fas fa-spinner fa-spin"></i> Searching...</td></tr>';
    }

    try {
        const queries = await api.apiFetch(`${api.endpoints.queries}?search=${encodeURIComponent(search)}&status=${status}`);
        if (fetchId === state.activeFetchId) {
            render.renderQueries(queries);
        }
    } catch (e) { console.error('Queries fetch failed', e); }
}

export async function fetchAnalytics() {
    try {
        const [blocked, clients] = await Promise.all([
            api.apiFetch(api.endpoints.topBlocked),
            api.apiFetch(api.endpoints.topClients)
        ]);
        render.renderAnalytics(blocked, clients);
    } catch (e) { console.error('Analytics fetch failed', e); }
}

export async function fetchDiagnostics() {
    try {
        const d = await api.apiFetch(api.endpoints.diagnostics);
        render.renderDiagnostics(d);
    } catch (e) { console.error('Diagnostics fetch failed', e); }
}

export async function fetchPresets() {
    try {
        const presets = await api.apiFetch(api.endpoints.presets);
        state.blockPresets = presets; // Store for modal lookup
        const container = getEl('preset-items');
        if (!container) return;
        container.innerHTML = '';

        const grouped = {};
        (presets || []).forEach((p, idx) => {
            p._idx = idx; // Attach index for lookup
            const cat = p.category || 'Other';
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(p);
        });

        Object.keys(grouped).forEach(cat => {
            const catHeader = document.createElement('div');
            catHeader.className = 'preset-category-group';
            catHeader.style.cssText = 'grid-column: 1 / -1; margin-top: 20px;';
            catHeader.innerHTML = `<h2 style="font-size: 1.1rem; color: var(--accent); margin-bottom: 10px; display: flex; align-items: center; justify-content: flex-start; text-align: left; gap: 8px;">
                <i class="fas fa-folder-open"></i> ${cat}
            </h2>`;
            container.appendChild(catHeader);

            grouped[cat].forEach(preset => {
                const presetUrl = (preset.url || '').toLowerCase().trim();
                const isAdded = (state.currentConfig.lists || []).some(l => 
                    (l.url || '').toLowerCase().trim() === presetUrl
                );
                
                const card = document.createElement('div');
                card.className = 'preset-card';
                card.onclick = () => window.showPresetDetails(preset._idx, 'block');
                const btn = document.createElement('button');
                btn.className = 'btn btn-sm secondary';
                if (isAdded) {
                    btn.textContent = 'Added ✓';
                    btn.disabled = true;
                    btn.style.opacity = '0.7';
                } else {
                    btn.textContent = 'Add';
                    btn.onclick = (e) => {
                        e.stopPropagation();
                        window.addPreset(preset.name, preset.url, e);
                    };
                }
                card.innerHTML = `<div class="preset-info"><h3>${preset.name}</h3></div>`;
                card.appendChild(btn);
                container.appendChild(card);
            });
        });
    } catch (e) { console.error('Presets fetch failed', e); }
}

export async function fetchAllowlistPresets() {
    try {
        const presets = await api.apiFetch(api.endpoints.allowlistPresets);
        state.allowPresets = presets; // Store for modal lookup
        const container = getEl('preset-allow-items');
        if (!container) return;
        container.innerHTML = '';

        const grouped = {};
        (presets || []).forEach((p, idx) => {
            p._idx = idx;
            const cat = p.category || 'Official';
            if (!grouped[cat]) grouped[cat] = [];
            grouped[cat].push(p);
        });

        Object.keys(grouped).forEach(cat => {
            const catHeader = document.createElement('div');
            catHeader.className = 'preset-category-group';
            catHeader.style.cssText = 'grid-column: 1 / -1; margin-top: 20px;';
            catHeader.innerHTML = `<h2 style="font-size: 1.1rem; color: var(--accent); margin-bottom: 10px; display: flex; align-items: center; justify-content: flex-start; text-align: left; gap: 8px;">
                <i class="fas fa-folder-open"></i> ${cat}
            </h2>`;
            container.appendChild(catHeader);

            grouped[cat].forEach(preset => {
                const presetUrl = (preset.url || '').toLowerCase().trim();
                const isAdded = (state.currentConfig.allowlists || []).some(l => 
                    (l.url || '').toLowerCase().trim() === presetUrl
                );

                const card = document.createElement('div');
                card.className = 'preset-card';
                card.onclick = () => window.showPresetDetails(preset._idx, 'allow');
                const btn = document.createElement('button');
                btn.className = 'btn btn-sm secondary';
                if (isAdded) {
                    btn.textContent = 'Added ✓';
                    btn.disabled = true;
                    btn.style.opacity = '0.7';
                } else {
                    btn.textContent = 'Add';
                    btn.onclick = (e) => {
                        e.stopPropagation();
                        window.addAllowPreset(preset.name, preset.url, e);
                    };
                }
                card.innerHTML = `<div class="preset-info"><h3>${preset.name}</h3></div>`;
                card.appendChild(btn);
                container.appendChild(card);
            });
        });
    } catch (e) { console.error('Allowlist presets fetch failed', e); }
}

export async function fetchConfig() {
    try {
        state.currentConfig = await api.apiFetch(api.endpoints.config);
        render.renderConfig(state.currentConfig);
    } catch(e) { console.error('Config fetch failed', e); }
}

export async function fetchAPIKeys() {
    try {
        const keys = await api.apiFetch(api.endpoints.tokens);
        state.allTokens = keys;
        render.renderAPIKeys(keys);
    } catch(e) { console.error('API Keys fetch failed', e); }
}

export async function fetchCountries() {
    try {
        state.allCountries = await api.apiFetch(api.endpoints.countries);
    } catch(e) { console.error('Countries fetch failed', e); }
}

export async function fetchIPDetails(ip) {
    try {
        const [stats, ipInfo, topDomains, topBlocked, history] = await Promise.all([
            api.apiFetch(`${api.endpoints.clientStats}?ip=${ip}`),
            api.apiFetch(`${api.endpoints.ipInfo}?ip=${ip}`),
            api.apiFetch(`${api.endpoints.clientTopDomains}?ip=${ip}`),
            api.apiFetch(`${api.endpoints.clientTopBlocked}?ip=${ip}`),
            api.apiFetch(`${api.endpoints.queries}?client_ip=${ip}&limit=50`)
        ]);
        
        // Merge IP info into stats for the renderer
        const mergedStats = { ...stats, ...ipInfo };
        render.renderIPDetails(ip, mergedStats, topDomains, topBlocked, history.data || history || []);
    } catch (e) {
        console.error('IP details fetch failed', e);
        helpers.showAlert('Failed to fetch IP details: ' + e.message);
    }
}

export async function fetchDomainDetails(domain) {
    try {
        const [stats, clients, blockInfo, queries] = await Promise.all([
            api.apiFetch(`${api.endpoints.domainStats}?domain=${domain}`),
            api.apiFetch(`${api.endpoints.domainClients}?domain=${domain}`),
            api.apiFetch(`${api.endpoints.blockInfo}?domain=${domain}`),
            api.apiFetch(`${api.endpoints.queries}?search=${domain}&limit=20`)
        ]);
        render.renderDomainDetails(domain, stats, clients, blockInfo, queries.data || []);
    } catch (e) {
        console.error('Domain details fetch failed', e);
        helpers.showAlert('Failed to fetch domain details: ' + e.message);
    }
}

