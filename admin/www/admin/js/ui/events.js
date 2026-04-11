/**
 * Event Listeners and Button Handlers
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { renderConfig } from './renderers.js';

export function initEvents(fetchConfig) {
    // General Update/Refresh
    getEl('refresh-btn')?.addEventListener('click', async () => {
        try {
            await api.apiFetch(api.endpoints.refresh, { method: 'POST' });
            helpers.showAlert('Update started in background...', 'Success');
        } catch (e) { helpers.showAlert('Failed to start update'); }
    });

    getEl('check-updates-btn')?.addEventListener('click', async () => {
        try {
            await api.apiFetch(api.endpoints.refresh, { method: 'POST' });
            helpers.showAlert('Update check started...', 'Success');
        } catch (e) { helpers.showAlert('Failed to check updates'); }
    });

    getEl('full-system-refresh-btn')?.addEventListener('click', async () => {
        if (!await helpers.showConfirm('Are you sure you want to perform a full system refresh? This will re-download all lists and restart the DNS server.')) return;
        try {
             await api.apiFetch(api.endpoints.fullReload, { method: 'POST' });
             helpers.showAlert('Full system refresh initiated. Check logs for progress.', 'Success');
        } catch (e) { helpers.showAlert('Failed to start full refresh'); }
    });

    // Filtering Toggle
    getEl('toggle-protection-btn')?.addEventListener('click', async () => {
        const newStatus = !state.currentConfig.filtering_enabled;
        try {
            await api.apiFetch(api.endpoints.toggleFiltering, {
                method: 'POST',
                body: JSON.stringify({ enabled: newStatus })
            });
            state.currentConfig.filtering_enabled = newStatus;
            renderConfig(state.currentConfig);
        } catch (e) { helpers.showAlert('Failed to toggle protection'); }
    });

    // Config Save
    getEl('settings-form')?.addEventListener('submit', async (e) => {
        e.preventDefault();
        saveConfig(fetchConfig);
    });

    // API Key creation
    getEl('create-api-key-btn')?.addEventListener('click', () => {
        const modal = getEl('api-key-modal');
        const form = getEl('api-key-form');
        const result = getEl('api-key-result');
        if (!modal || !form || !result) return;
        getEl('api-key-modal-title').textContent = 'Generate API Key';
        getEl('api-key-name').value = '';
        getEl('save-api-key-btn').textContent = 'Generate';
        form.classList.remove('hidden');
        result.classList.add('hidden');
        modal.classList.remove('hidden');
    });

    getEl('cancel-api-key-btn')?.addEventListener('click', () => getEl('api-key-modal')?.classList.add('hidden'));
    getEl('close-api-key-modal-btn')?.addEventListener('click', () => getEl('api-key-modal')?.classList.add('hidden'));
}

export async function saveConfig(fetchConfig) {
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
    };

    try {
        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify(newConfig)
        });
        state.currentConfig = newConfig;
        helpers.showAlert('Configuration saved!', 'Success');
        renderConfig(state.currentConfig);
    } catch (e) {
        helpers.showAlert('Failed to save configuration');
    }
}
