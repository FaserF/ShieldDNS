/**
 * Modals & Detail Dialogs UI Handlers
 */
import { state, getEl } from '../core/state.js';
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import * as nav from '../core/navigation.js';
import * as fetchService from '../services/fetch.js';

export function initModalsUI() {
    // Shared closing logic for all modals
    const closeModals = () => {
        document.querySelectorAll('.modal').forEach(m => m.classList.add('hidden'));
    };

    // Close buttons by ID
    const closeSelectors = [
        'modal-cancel', 'ip-info-close-btn', 'ip-info-close-btn-bottom', 'ip-info-done-btn',
        'domain-info-close-btn', 'domain-info-close-btn-bottom', 'domain-info-done-btn',
        'close-list-details-btn', 'close-list-details-btn-2', 'blocked-clients-close-btn',
        'close-api-key-modal-btn', 'cancel-api-key-btn', 'reset-cancel-1', 'reset-cancel-2',
        'alert-ok', 'confirm-cancel'
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
        if (!await helpers.showConfirm(`Block client ${ip}?`, 'Block Client', true)) return;
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
        if (!domain || !await helpers.showConfirm(`Block domain ${domain}?`, 'Block Domain', true)) return;
        try {
            await api.apiFetch(api.endpoints.addRule, { method: 'POST', body: JSON.stringify({ domain, type: 'block' }) });
            helpers.showToast(`${domain} blocked`);
            closeModals();
            fetchService.fetchConfig();
        } catch (e) { helpers.showAlert('Block failed: ' + e.message); }
    });

    getEl('domain-allow-btn')?.addEventListener('click', async () => {
        const domain = getEl('domain-info-title').textContent;
        try {
            await api.apiFetch(api.endpoints.addRule, { method: 'POST', body: JSON.stringify({ domain, type: 'allow' }) });
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
    if (!list) return;
    getEl('modal-list-name').textContent = list.name || 'List Details';
    const urlEl = getEl('modal-list-url');
    urlEl.textContent = list.url;
    urlEl.href = list.url;
    getEl('modal-list-entries').textContent = list.entries?.toLocaleString() || '0';
    const ramMB = Math.round((list.entries || 0) * 1.1 / 1024);
    getEl('modal-list-ram').textContent = `~${ramMB} MB`;
    
    // Standard Update (ShieldDNS last sync)
    const localDate = (list.updated_at && list.updated_at !== '0001-01-01T00:00:00Z') ? 
        new Date(list.updated_at).toLocaleString() : 'Never';
    getEl('modal-list-updated').textContent = localDate;

    // Remote Update (Source file last modified)
    const remoteDate = (list.remote_updated_at && list.remote_updated_at !== '0001-01-01T00:00:00Z') ?
        new Date(list.remote_updated_at).toLocaleString() : 'n.a.';
    getEl('modal-list-remote-updated').textContent = remoteDate;

    getEl('list-details-modal').classList.remove('hidden');
};

window.openListDetailsModal = (idx, type) => {
    const list = type === 'block' ? state.currentConfig.lists[idx] : state.currentConfig.allowlists[idx];
    window.showListDetails(list);
};

window.showPresetDetails = (idx, type) => {
    const list = type === 'block' ? (state.blockPresets || [])[idx] : (state.allowPresets || [])[idx];
    window.showListDetails(list);
};
