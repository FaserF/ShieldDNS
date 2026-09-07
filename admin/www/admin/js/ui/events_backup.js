/**
 * Backup, Restore and System Maintenance Handlers
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';
import { showActivityOverlay, hideActivityOverlay } from './activity.js';

export function initBackupEvents(fetchConfig) {
    const backupModal = getEl('backup-modal');
    const restorePasswordModal = getEl('restore-password-modal');
    const restorePreviewModal = getEl('restore-preview-modal');

    const closeModal = (modal) => modal?.classList.add('hidden');
    const openModal = (modal) => modal?.classList.remove('hidden');

    getEl('backup-btn')?.addEventListener('click', () => {
        getEl('backup-password').value = '';
        getEl('backup-type').value = 'settings';
        openModal(backupModal);
    });

    getEl('backup-modal-cancel')?.addEventListener('click', () => closeModal(backupModal));
    getEl('backup-modal-confirm')?.addEventListener('click', () => {
        const type = getEl('backup-type').value;
        const password = getEl('backup-password').value;
        const token = localStorage.getItem('api_token');
        closeModal(backupModal);
        const backupUrl = new URL(api.endpoints.backup, window.location.origin);
        backupUrl.searchParams.set('token', token);
        backupUrl.searchParams.set('type', type);
        backupUrl.searchParams.set('password', password);
        window.location.href = backupUrl.toString();
    });

    let uploadedFile = null;
    let decryptionPassword = '';

    getEl('restore-file-input')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        uploadedFile = file;
        decryptionPassword = '';
        e.target.value = '';
        await handleRestorePreview();
    });

    getEl('restore-password-cancel')?.addEventListener('click', () => closeModal(restorePasswordModal));
    getEl('restore-preview-cancel')?.addEventListener('click', () => closeModal(restorePreviewModal));

    getEl('restore-password-confirm')?.addEventListener('click', async () => {
        decryptionPassword = getEl('restore-decrypt-password').value;
        closeModal(restorePasswordModal);
        await handleRestorePreview();
    });

    async function handleRestorePreview() {
        const formData = new FormData();
        formData.append('config', uploadedFile);
        formData.append('action', 'preview');
        if (decryptionPassword) {
            formData.append('password', decryptionPassword);
        }

        helpers.showToast('Analyzing backup...', 'info');
        try {
            const res = await api.apiFetch(api.endpoints.restore, {
                method: 'POST',
                body: formData
            });

            if (res.encrypted) {
                getEl('restore-decrypt-password').value = '';
                openModal(restorePasswordModal);
                helpers.showToast('Password required', 'warning');
                return;
            }

            const tbody = getEl('restore-preview-tbody');
            tbody.innerHTML = '';
            const preview = res.preview;
            const hasData = res.has_data;

            const dataWrapper = getEl('sel-cat-data-wrapper');
            const dataCheckbox = getEl('sel-cat-data');
            if (hasData) {
                dataWrapper.style.display = 'flex';
                dataCheckbox.checked = true;
            } else {
                dataWrapper.style.display = 'none';
                dataCheckbox.checked = false;
            }

            const keys = Object.keys(preview).sort((a, b) => {
                if (preview[a].category !== preview[b].category) {
                    return preview[a].category.localeCompare(preview[b].category);
                }
                return a.localeCompare(b);
            });

            for (const key of keys) {
                const item = preview[key];
                const tr = document.createElement('tr');
                if (item.changed) {
                    tr.style.background = 'rgba(239, 68, 68, 0.08)';
                }

                const formatVal = (v) => {
                    if (v === null || v === undefined) return '—';
                    if (typeof v === 'object') return JSON.stringify(v);
                    return String(v);
                };

                const currentText = formatVal(item.current);
                const backupText = formatVal(item.backup);

                tr.innerHTML = `
                    <td style="padding:10px; border-bottom:1px solid var(--border); font-weight:bold;">${key}</td>
                    <td style="padding:10px; border-bottom:1px solid var(--border);"><span class="badge" style="background:var(--bg-card); color:var(--text-secondary); border:1px solid var(--border); padding:2px 8px; border-radius:4px;">${item.category}</span></td>
                    <td style="padding:10px; border-bottom:1px solid var(--border); color:var(--text-secondary); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${currentText.replace(/"/g, '&quot;')}">${currentText}</td>
                    <td style="padding:10px; border-bottom:1px solid var(--border); max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${backupText.replace(/"/g, '&quot;')}">${backupText}</td>
                    <td style="padding:10px; border-bottom:1px solid var(--border); font-weight:bold; color:${item.changed ? '#ef4444' : '#22c55e'}">${item.changed ? 'Overwrites' : 'Identical'}</td>
                `;
                tbody.appendChild(tr);
            }

            openModal(restorePreviewModal);
        } catch (err) {
            helpers.showAlert('Preview failed: ' + err.message);
        }
    }

    getEl('restore-preview-confirm')?.addEventListener('click', async () => {
        closeModal(restorePreviewModal);

        const categories = [];
        if (getEl('sel-cat-dns').checked) categories.push('dns');
        if (getEl('sel-cat-filtering').checked) categories.push('filtering');
        if (getEl('sel-cat-lists').checked) categories.push('lists');
        if (getEl('sel-cat-clients').checked) categories.push('clients');
        if (getEl('sel-cat-abuse').checked) categories.push('abuse');
        if (getEl('sel-cat-system').checked) categories.push('system');
        if (getEl('sel-cat-auth').checked) categories.push('auth');
        if (getEl('sel-cat-data').checked) categories.push('data');

        if (categories.length === 0) {
            helpers.showAlert('Please select at least one category to import.');
            return;
        }

        const formData = new FormData();
        formData.append('config', uploadedFile);
        formData.append('action', 'apply');
        formData.append('selected_categories', JSON.stringify(categories));
        if (decryptionPassword) {
            formData.append('password', decryptionPassword);
        }

        helpers.showToast('Restoration in progress...', 'info');
        showActivityOverlay('System Restoration', 'Applying selected configurations...');
        try {
            await api.apiFetch(api.endpoints.restore, {
                method: 'POST',
                body: formData
            });
            helpers.showToast('Restoration completed successfully!');
            hideActivityOverlay(true);
            setTimeout(() => window.location.reload(), 2500);
        } catch (err) {
            hideActivityOverlay(false);
            helpers.showAlert('Restoration failed: ' + err.message);
        }
    });

    getEl('reset-system-btn')?.addEventListener('click', async () => {
        if (!await helpers.showConfirm('FACTORY RESET: This will wipe your configuration and password. The system will revert to setup mode. Are you absolutely sure?', 'Factory Reset', true)) return;
        
        showActivityOverlay('Factory Reset', 'Wiping all system data and configurations...');
        try {
            await api.apiFetch(api.endpoints.reset, { 
                method: 'POST', 
                body: JSON.stringify({ scope: 'all' }) 
            });
            helpers.showToast('Factory reset successful.');
            hideActivityOverlay(true);
            setTimeout(() => window.location.reload(), 2000);
        } catch (err) {
            hideActivityOverlay(false);
            helpers.showAlert('Factory reset failed: ' + err.message);
        }
    });
    
    getEl('clear-logs-btn')?.addEventListener('click', async () => {
        if (!await helpers.showConfirm('Are you sure you want to clear all query logs? This action is irreversible and will delete all historical query data.', 'Clear Logs', true)) return;
        
        const btn = getEl('clear-logs-btn');
        helpers.setBtnLoading(btn, true, 'Clearing...');
        try {
            await api.apiFetch(api.endpoints.clearLogs, { method: 'POST' });
            helpers.showToast('All query logs cleared', 'success');
            setTimeout(() => window.location.reload(), 1000);
        } catch (err) {
            helpers.showAlert('Failed to clear logs: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('btn-check-updates')?.addEventListener('click', async (e) => {
        const btn = e.target;
        helpers.setBtnLoading(btn, true, 'Checking...');
        try {
            const res = await api.apiFetch(api.endpoints.checkVersion, { method: 'POST' });
            if (res && res.ShieldDNS) {
                helpers.showToast('Version check complete');
                const latestVer = getEl('update-latest-ver');
                if (latestVer) {
                    latestVer.textContent = res.ShieldDNS;
                }
                const btnUpdate = getEl('btn-update-now');
                if (btnUpdate) {
                    const currentVer = getEl('about-shielddns-ver')?.textContent;
                    if (currentVer && res.ShieldDNS && currentVer !== res.ShieldDNS) {
                        btnUpdate.style.display = 'block';
                    } else {
                        btnUpdate.style.display = 'none';
                    }
                }
            } else {
                helpers.showToast('No version info returned', 'info');
            }
        } catch (err) {
            helpers.showAlert('Failed to check versions: ' + err.message);
        } finally {
            helpers.setBtnLoading(btn, false);
        }
    });

    getEl('btn-update-now')?.addEventListener('click', async (e) => {
        const btn = e.target;
        const confirmed = await helpers.showConfirm('Are you sure you want to update ShieldDNS? A full backup will be downloaded first, and then the server will perform the self-update via Docker.', 'Update ShieldDNS', true);
        if (!confirmed) return;

        helpers.setBtnLoading(btn, true, 'Initiating backup...');
        
        try {
            const token = localStorage.getItem('api_token') || '';
            const backupUrl = `${api.endpoints.backup}?type=full&token=${token}`;
            
            const link = document.createElement('a');
            link.href = backupUrl;
            link.setAttribute('download', 'shielddns-backup.zip');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);

            helpers.showToast('Backup download started. Starting update...', 'info');

            setTimeout(async () => {
                showActivityOverlay('System Update', 'Applying ShieldDNS update via Docker compose. This may take a minute...');
                try {
                    await api.apiFetch(api.endpoints.systemUpdate, { method: 'POST' });
                    helpers.showToast('Update initiated successfully!', 'success');
                    
                    setTimeout(() => {
                        window.location.reload();
                    }, 15000);
                } catch (err) {
                    hideActivityOverlay(false);
                    helpers.showAlert('Update failed to start: ' + err.message);
                    helpers.setBtnLoading(btn, false);
                }
            }, 1500);

        } catch (err) {
            helpers.showAlert('Update failed: ' + err.message);
            helpers.setBtnLoading(btn, false);
        }
    });
}
