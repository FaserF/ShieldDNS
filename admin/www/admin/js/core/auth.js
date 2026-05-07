/**
 * Auth & Setup Module
 */
import * as api from '../services/api.js';
import * as helpers from '../ui/helpers.js';
import { state, uiRefs, getEl } from './state.js';

export async function checkAuthStatus(onSuccess) {
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
            if (data.mfa_required) {
                showView('mfa');
            } else {
                showView('login');
            }
        } else {
            uiRefs.authOverlay?.classList.add('hidden');
            onSuccess();
        }
    } catch (e) {
        // Fallback
        const data = await api.apiFetch(api.endpoints.authStatus);
        if (data.need_setup) {
            uiRefs.authOverlay?.classList.remove('hidden');
            uiRefs.setupView?.classList.remove('hidden');
        } else if (!data.logged_in) {
            uiRefs.authOverlay?.classList.remove('hidden');
            if (data.mfa_required) {
                uiRefs.mfaView?.classList.remove('hidden');
            } else {
                uiRefs.loginView?.classList.remove('hidden');
            }
        } else {
            uiRefs.authOverlay?.classList.add('hidden');
            onSuccess();
        }
    }
}

export function showView(viewId) {
    if (!uiRefs.authOverlay) return;
    uiRefs.authOverlay.classList.remove('hidden');
    uiRefs.setupView?.classList.toggle('hidden', viewId !== 'setup');
    uiRefs.loginView?.classList.toggle('hidden', viewId !== 'login');
    uiRefs.mfaView?.classList.toggle('hidden', viewId !== 'mfa');

    if (viewId === 'setup') {
        const domainInput = getEl('setup-admin-domain');
        if (domainInput && !domainInput.value) {
            domainInput.value = window.location.hostname;
        }
    }
}

export async function handleLogin() {
    const pwd = getEl('login-password')?.value;
    if (!pwd) return;

    try {
        const res = await api.apiFetch(api.endpoints.login, {
            method: 'POST',
            body: JSON.stringify({ password: pwd })
        });
        
        if (res.mfa_required) {
            // Show method selector, hide TOTP input area
            getEl('mfa-method-selector')?.classList.remove('hidden');
            getEl('mfa-totp-input-area')?.classList.add('hidden');
            showView('mfa');
        } else {
            window.location.reload();
        }
    } catch (e) {
        helpers.showAlert('Login failed: ' + e.message);
    }
}

export async function handleMFAVerify() {
    const code = getEl('mfa-code')?.value;
    if (!code) return;

    const btn = getEl('mfa-confirm-btn');
    helpers.setBtnLoading(btn, true, 'Verifying...');
    try {
        await api.apiFetch('/api/mfa/challenge', {
            method: 'POST',
            body: JSON.stringify({ code })
        });
        window.location.reload();
    } catch (e) {
        helpers.showAlert('MFA verification failed: ' + e.message);
    } finally {
        helpers.setBtnLoading(btn, false);
    }
}

export async function handlePasskeyLogin() {
    const btn = getEl('mfa-use-passkey-btn');
    helpers.setBtnLoading(btn, true, 'Connecting...');
    try {
        const options = await api.apiFetch('/api/mfa/webauthn/login/start', { method: 'POST' });
        
        options.publicKey.challenge = helpers.bufferFromBase64(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials.forEach(c => {
                c.id = helpers.bufferFromBase64(c.id);
            });
        }

        const credential = await navigator.credentials.get(options);
        
        const credentialJSON = {
            id: credential.id,
            rawId: helpers.base64FromBuffer(credential.rawId),
            type: credential.type,
            response: {
                authenticatorData: helpers.base64FromBuffer(credential.response.authenticatorData),
                clientDataJSON: helpers.base64FromBuffer(credential.response.clientDataJSON),
                signature: helpers.base64FromBuffer(credential.response.signature),
                userHandle: credential.response.userHandle ? helpers.base64FromBuffer(credential.response.userHandle) : null
            }
        };

        await api.apiFetch('/api/mfa/webauthn/login/finish', {
            method: 'POST',
            body: JSON.stringify(credentialJSON)
        });
        
        window.location.reload();
    } catch (e) {
        if (e.name !== 'NotAllowedError') {
            helpers.showAlert('Passkey login failed: ' + e.message);
        }
    } finally {
        helpers.setBtnLoading(btn, false);
    }
}

/**
 * Setup Wizard
 */
export async function nextSetupStep(step) {
    document.querySelectorAll('.setup-pane').forEach(p => p.classList.add('hidden'));
    const targetPane = document.getElementById(`setup-pane-${step}`);
    if (targetPane) targetPane.classList.remove('hidden');
    
    document.querySelectorAll('.w-step').forEach(s => s.classList.remove('active'));
    document.getElementById(`w-step-${step}`)?.classList.add('active');

    if (step === 3) {
        await loadSetupPresets();
    }
}

async function loadSetupPresets() {
    const container = getEl('setup-presets');
    if (!container || container.children.length > 0) return;
    
    try {
        const presets = await api.apiFetch(api.endpoints.presets);
        container.innerHTML = '';
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

export async function finishSetup() {
    const pwd = getEl('setup-password')?.value;
    const confirm = getEl('setup-confirm')?.value;
    
    if (pwd.length < 12) {
        helpers.showAlert('Password must be at least 12 characters long');
        return;
    }
    if (pwd !== confirm) {
        helpers.showAlert('Passwords do not match');
        return;
    }
    
    const finishBtn = getEl('setup-finish-btn');
    const originalText = finishBtn.innerHTML;
    finishBtn.disabled = true;
    finishBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Finalizing...';
    
    try {
        await api.apiFetch(api.endpoints.setup, {
            method: 'POST',
            body: JSON.stringify({ password: pwd })
        });
        
        await api.apiFetch(api.endpoints.login, {
            method: 'POST',
            body: JSON.stringify({ password: pwd })
        });
        
        const upstreams = getEl('setup-upstreams').value.split(',').map(s => s.trim()).filter(s => s);
        const dotUpstreams = getEl('setup-dot-upstreams').value.split(',').map(s => s.trim()).filter(s => s);
        const adminDomain = getEl('setup-admin-domain').value.trim() || 'shielddns.local';
        const preferEncrypted = getEl('setup-prefer-encrypted')?.checked ?? true;
        
        const abuseDetection = getEl('setup-abuse-detection')?.checked ?? true;
        const maliciousBlocking = getEl('setup-malicious-blocking')?.checked ?? true;
        const serveStale = getEl('setup-serve-stale')?.checked ?? true;
        const verifyTls = getEl('setup-verify-tls')?.checked ?? true;
        const signProfiles = getEl('setup-sign-profiles')?.checked ?? true;
        
        const selectedLists = [];
        document.querySelectorAll('#setup-presets input:checked').forEach(input => {
            selectedLists.push({
                name: input.getAttribute('data-name'),
                url: input.getAttribute('data-url'),
                enabled: true
            });
        });

        await api.apiFetch(api.endpoints.config, {
            method: 'POST',
            body: JSON.stringify({
                upstreams,
                upstream_dot: dotUpstreams,
                admin_domain: adminDomain,
                prefer_encrypted: preferEncrypted,
                abuse_detection_enabled: abuseDetection,
                malicious_ip_blocking_enabled: maliciousBlocking,
                serve_stale: serveStale,
                verify_upstream_tls: verifyTls,
                sign_mobileconfig: signProfiles,
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
