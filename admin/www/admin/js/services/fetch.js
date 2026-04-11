/**
 * High-level Data Fetching Service
 */
import * as api from './api.js';
import { state, getEl, uiRefs } from '../core/state.js';
import * as render from '../ui/renderers.js';
import * as charts from '../ui/charts.js';

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
        const container = getEl('preset-items');
        if (!container) return;
        container.innerHTML = '';

        const grouped = {};
        (presets || []).forEach(p => {
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
                const card = document.createElement('div');
                card.className = 'preset-card';
                card.innerHTML = `
                    <div class="preset-info"><h3>${preset.name}</h3></div>
                    <button class="btn btn-sm secondary" onclick="addPreset('${preset.name}', '${preset.url}')">Add</button>
                `;
                container.appendChild(card);
            });
        });
    } catch (e) { console.error('Presets fetch failed', e); }
}

export async function fetchAllowlistPresets() {
    try {
        const presets = await api.apiFetch(api.endpoints.allowlistPresets);
        const container = getEl('preset-allow-items');
        if (!container) return;
        container.innerHTML = '';

        const grouped = {};
        (presets || []).forEach(p => {
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
                const isAdded = (state.currentConfig.allowlists || []).some(l => l.url === preset.url);
                const card = document.createElement('div');
                card.className = 'preset-card';
                card.innerHTML = `
                    <div class="preset-info"><h3>${preset.name}</h3></div>
                    <button class="btn btn-sm ${isAdded ? 'secondary' : 'primary'}" ${isAdded ? 'disabled' : ''} onclick="addAllowPreset('${preset.name}', '${preset.url}')">${isAdded ? 'Added ✓' : 'Add'}</button>
                `;
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
        const keys = await api.apiFetch(api.endpoints.apiKeys);
        state.allTokens = keys;
        // This renderer expects specific arguments, might need adaptation
        // For now, assume it's exposed or imported
        // ui.renderAPIKeys(keys, keys, getEl('api-keys-list'), window.editAPIKey, window.deleteAPIKey);
    } catch(e) { console.error('API Keys fetch failed', e); }
}

export async function fetchCountries() {
    try {
        state.allCountries = await api.apiFetch(api.endpoints.countries);
    } catch(e) { console.error('Countries fetch failed', e); }
}
