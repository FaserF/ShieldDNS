/**
 * Geo-Blocking & Client Blocking Event Handlers
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import * as fetchService from '../services/fetch.js';
import { saveConfig } from './events_settings.js';

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



export function initGeoEvents(fetchConfig) {
    // Blocked Clients Modal Handlers
    getEl('view-blocked-clients-btn')?.addEventListener('click', async () => {
        const modal = getEl('blocked-clients-modal');
        if (!modal) return;

        // Fetch latest config to ensure we have the most up-to-date block list
        await fetchService.fetchConfig();
        
        const m = await import('./renderers.js');
        m.renderBlockedClientsModal(state.currentConfig.blocked_clients, state.currentConfig.blocked_clients_info || {});
        modal.classList.remove('hidden');
    });

    getEl('blocked-clients-search')?.addEventListener('input', async () => {
        const m = await import('./renderers.js');
        m.renderBlockedClientsModal(state.currentConfig.blocked_clients, state.currentConfig.blocked_clients_info || {});
    });

    getEl('blocked-clients-country-filter')?.addEventListener('change', async () => {
        const m = await import('./renderers.js');
        m.renderBlockedClientsModal(state.currentConfig.blocked_clients, state.currentConfig.blocked_clients_info || {});
    });

    getEl('blocked-clients-date-filter')?.addEventListener('change', async () => {
        const m = await import('./renderers.js');
        m.renderBlockedClientsModal(state.currentConfig.blocked_clients, state.currentConfig.blocked_clients_info || {});
    });

    const closeBlockedModal = () => getEl('blocked-clients-modal')?.classList.add('hidden');
    getEl('blocked-clients-close-btn')?.addEventListener('click', closeBlockedModal);
    getEl('blocked-clients-done-btn')?.addEventListener('click', closeBlockedModal);

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
            setTimeout(() => {
                fetchConfig();
                fetchService.fetchStats();
            }, 500);
        } catch (err) {
            helpers.showAlert('Failed to block client: ' + err.message);
        }
    });

    getEl('add-whitelist-ip-btn')?.addEventListener('click', () => {
        const input = getEl('autoblock-whitelist-input');
        const ip = input?.value.trim();
        if (!ip) return;

        if (!state.currentConfig.autoblock_whitelist) state.currentConfig.autoblock_whitelist = [];
        if (state.currentConfig.autoblock_whitelist.includes(ip)) {
            helpers.showToast('IP already in whitelist', 'info');
            return;
        }

        state.currentConfig.autoblock_whitelist.push(ip);
        import('./renderers.js').then(m => m.renderAutoblockWhitelist(state.currentConfig.autoblock_whitelist));
        setSettingsDirty(true);
        input.value = '';
    });

    window.removeWhitelistIP = (ip) => {
        if (!state.currentConfig.autoblock_whitelist) return;
        state.currentConfig.autoblock_whitelist = state.currentConfig.autoblock_whitelist.filter(item => item !== ip);
        import('./renderers.js').then(m => m.renderAutoblockWhitelist(state.currentConfig.autoblock_whitelist));
        setSettingsDirty(true);
    };

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
                countryDropdown.innerHTML = matches.map(([code, name]) => {
                    const cleanCode = code.toLowerCase();
                    const invalidFlags = new Set(['ap', 'a1', 'a2', 'o1', 'xx', 'geo', 'unknown']);
                    const isInvalid = invalidFlags.has(cleanCode) || cleanCode.length !== 2;
                    const override = cleanCode === 'an' ? 'nl' : cleanCode;
                    const flagHTML = isInvalid ?
                        `<i class="fas fa-globe" style="color: var(--accent); opacity: 0.6; margin-right: 12px; width: 20px; text-align: center;"></i>` :
                        `<img src="https://flagcdn.com/w20/${override}.png" alt="${code}" style="margin-right: 12px; height: 15px; border-radius: 2px;" onerror="this.outerHTML='<i class=\'fas fa-globe\' style=\'color: var(--accent); opacity: 0.6; margin-right: 12px;\'></i>';">`;
                    return `
                    <div class="dropdown-item" data-code="${code}" style="padding: 10px; cursor: pointer; display: flex; align-items: center; border-bottom: 1px solid var(--border);">
                        ${flagHTML}
                        <span>${name} (${code})</span>
                    </div>
                `; }).join('');
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

}
