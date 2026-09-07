/**
 * MFA & Passkey Event Handlers
 */
import * as api from '../services/api.js';
import * as helpers from './helpers.js';
import { state, getEl } from '../core/state.js';

export async function initMFA() {
    const toggleBtn = getEl('mfa-toggle-btn');
    if (!toggleBtn) return;

    toggleBtn.addEventListener('click', () => {
        const area = getEl('mfa-setup-area');
        area.classList.toggle('hidden');
        if (!area.classList.contains('hidden')) {
            getEl('mfa-manage-area').classList.remove('hidden');
            getEl('mfa-totp-setup').classList.add('hidden');
            
            import('./renderers.js').then(m => {
                m.updateMFAStatus();
                m.renderTOTPList();
                m.renderPasskeys();
            });
        }
    });

    getEl('mfa-cancel-setup')?.addEventListener('click', () => {
        getEl('mfa-setup-area').classList.add('hidden');
        getEl('mfa-totp-setup').classList.add('hidden');
        getEl('mfa-manage-area').classList.remove('hidden');
    });

    getEl('mfa-complete-setup')?.addEventListener('click', handleTOTPVerify);
    getEl('mfa-add-passkey-btn')?.addEventListener('click', handlePasskeyRegister);
    getEl('mfa-add-totp-btn')?.addEventListener('click', startTOTPSetup);
    getEl('mfa-disable-all-btn')?.addEventListener('click', handleMFADisable);
}

async function startTOTPSetup() {
    try {
        const res = await api.apiFetch('/api/mfa/totp/setup', { method: 'POST' });
        const qrImg = getEl('mfa-qr-code');
        const secretVal = getEl('mfa-secret-value');
        const secretContainer = getEl('mfa-secret-container');

        if (qrImg) {
            qrImg.src = res.qr;
            qrImg.dataset.secret = res.secret;
        }
        if (secretVal) secretVal.textContent = res.secret;
        if (secretContainer) secretContainer.classList.remove('hidden');

        getEl('mfa-totp-setup')?.classList.remove('hidden');
        getEl('mfa-manage-area')?.classList.add('hidden');
        getEl('mfa-setup-totp-name').value = '';
        getEl('mfa-setup-verify-code').value = '';
    } catch (e) {
        helpers.showAlert('Failed to start MFA setup: ' + e.message);
    }
}

async function handleTOTPVerify() {
    const code = getEl('mfa-setup-verify-code').value.trim();
    const name = getEl('mfa-setup-totp-name').value.trim();
    const secret = getEl('mfa-qr-code').dataset.secret;

    if (!/^\d{6}$/.test(code)) {
        return helpers.showToast('Please enter a valid 6-digit code', 'info');
    }

    const btn = getEl('mfa-complete-setup');
    helpers.setBtnLoading(btn, true, 'Verifying...');
    try {
        await api.apiFetch(api.endpoints.mfaTOTPVerify, {
            method: 'POST',
            body: JSON.stringify({ code, secret: state.pendingTOTPSecret, name })
        });
        helpers.showToast('Authenticator App added!');
        
        const cfg = await api.apiFetch(api.endpoints.config);
        state.currentConfig = cfg;
        
        import('./renderers.js').then(m => {
            m.updateMFAStatus(cfg);
        });
        
        getEl('mfa-totp-setup').classList.add('hidden');
        getEl('mfa-manage-area').classList.remove('hidden');
    } catch (e) {
        helpers.showAlert('Verification failed: ' + e.message);
    } finally {
        helpers.setBtnLoading(btn, false);
    }
}

async function handlePasskeyRegister() {
    const name = await helpers.showInput('Give this Passkey a name (e.g. Work Laptop, YubiKey):', 'Register Passkey', 'Passkey Name', `Passkey ${new Date().toLocaleDateString()}`);
    if (name === null) return;

    try {
        const options = await api.apiFetch(api.endpoints.mfaWebAuthnRegisterStart, { method: 'POST' });
        
        options.publicKey.challenge = helpers.bufferFromBase64(options.publicKey.challenge);
        options.publicKey.user.id = helpers.bufferFromBase64(options.publicKey.user.id);
        if (options.publicKey.excludeCredentials) {
            options.publicKey.excludeCredentials.forEach(c => {
                c.id = helpers.bufferFromBase64(c.id);
            });
        }

        const credential = await navigator.credentials.create(options);
        const attestation = {
            id: credential.id,
            rawId: helpers.base64FromBuffer(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: helpers.base64FromBuffer(credential.response.attestationObject),
                clientDataJSON: helpers.base64FromBuffer(credential.response.clientDataJSON)
            }
        };

        await api.apiFetch(api.endpoints.mfaWebAuthnRegisterFinish, {
            method: 'POST',
            headers: { 'X-Passkey-Name': name },
            body: JSON.stringify(attestation)
        });
        
        helpers.showToast('Passkey registered!');
        const cfg = await api.apiFetch(api.endpoints.config);
        state.currentConfig = cfg;
        import('./renderers.js').then(m => {
            m.updateMFAStatus(cfg);
        });
    } catch (e) {
        if (e.name !== 'NotAllowedError') {
            helpers.showAlert('Passkey registration failed: ' + e.message);
        }
    }
}

async function handleMFADisable() {
    if (!await helpers.showConfirm('Disable ALL Multi-Factor Authentication? This will remove all apps and keys.', 'Disable MFA', true)) return;

    try {
        await api.apiFetch(api.endpoints.mfaDisable, { method: 'POST' });
        helpers.showToast('MFA disabled.');
        const cfg = await api.apiFetch(api.endpoints.config);
        state.currentConfig = cfg;
        import('./renderers.js').then(m => {
            m.updateMFAStatus(cfg);
        });
        getEl('mfa-setup-area').classList.add('hidden');
    } catch (e) {
        helpers.showAlert('Failed to disable MFA: ' + e.message);
    }
}

window.deleteMFAMethod = async (type, id, event) => {
    if (!await helpers.showConfirm(`Remove this ${type === 'totp' ? 'Authenticator App' : 'Passkey'}?`)) return;

    const btn = event?.currentTarget;
    if (btn) helpers.setBtnLoading(btn, true, '');

    try {
        await api.apiFetch(api.endpoints.mfaDelete, {
            method: 'POST',
            body: JSON.stringify({ type, id })
        });
        helpers.showToast('Method removed');
        const cfg = await api.apiFetch(api.endpoints.config);
        state.currentConfig = cfg;
        import('./renderers.js').then(m => {
            m.updateMFAStatus(cfg);
        });
    } catch (e) {
        helpers.showAlert('Failed to remove method: ' + e.message);
    } finally {
        if (btn) helpers.setBtnLoading(btn, false);
    }
};
