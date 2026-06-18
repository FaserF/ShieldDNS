/**
 * API Module - Handles all communication with the ShieldDNS backend
 */
export async function apiFetch(endpoint, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    // Inject CSRF protection header for state-changing requests
    const method = options.method?.toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        options.headers = {
            'Content-Type': 'application/json',
            ...options.headers,
            'X-Shield-Request': 'true'
        };
        if (options.body instanceof FormData) {
            delete options.headers['Content-Type'];
        }
    }

    try {
        const response = await fetch(endpoint, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        
        if (response.status === 403) {
            const text = await response.text();
            if (text.includes('Setup required') || text.includes('SETUP_REQUIRED')) {
                throw new Error('SETUP_REQUIRED');
            }
        }
        
        if (response.status === 401) {
            localStorage.removeItem('api_token');
            window.location.reload();
            throw new Error('UNAUTHORIZED');
        }
        
        const text = await response.text();
        let data = {};
        if (text) {
            try {
                data = JSON.parse(text);
            } catch (e) {
                // If it's not JSON, use the raw text if it's an error status
                if (!response.ok) {
                    throw new Error(text.substring(0, 100) || response.statusText);
                }
            }
        }

        if (!response.ok) {
            throw new Error(data.error || data.message || `Server error: ${response.status}`);
        }
        
        return data;
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            throw new Error('Request timed out after 10 seconds');
        }
        throw err;
    }
}

// Determine API base path dynamically for Home Assistant Ingress
const getBasePath = () => {
    const path = window.location.pathname;
    if (path.includes('/admin/')) {
        return path.substring(0, path.indexOf('/admin/'));
    }
    if (path.endsWith('/admin')) {
        return path.substring(0, path.length - 6);
    }
    return '';
};

const basePath = getBasePath();

export const endpoints = {
    stats: basePath + '/api/stats',
    history: basePath + '/api/history',
    statsHistory: basePath + '/api/stats/history',
    config: basePath + '/api/config',
    queries: basePath + '/api/queries',
    search: basePath + '/api/search',
    events: basePath + '/api/events',
    tokens: basePath + '/api/tokens',
    createToken: basePath + '/api/tokens/create',
    updateToken: basePath + '/api/tokens/update',
    deleteToken: basePath + '/api/tokens/delete',
    presets: basePath + '/api/presets',
    allowlistPresets: basePath + '/api/presets/allow',
    countries: basePath + '/api/countries',
    authStatus: basePath + '/api/auth-status',
    topBlocked: basePath + '/api/top-blocked',
    topClients: basePath + '/api/top-clients',
    diagnostics: basePath + '/api/diagnostics',
    systemLogs: basePath + '/api/system-logs',
    refresh: basePath + '/api/refresh',
    toggleFiltering: basePath + '/api/filtering/toggle',
    addRule: basePath + '/api/rules/add',
    removeRule: basePath + '/api/rules/remove',
    fullReload: basePath + '/api/system/full-reload',
    reset: basePath + '/api/reset',
    resetLists: basePath + '/api/config/reset-lists',
    clientBlock: basePath + '/api/client/block',
    clientAlias: basePath + '/api/client/alias',
    clientStats: basePath + '/api/client/stats',
    clientTopDomains: basePath + '/api/client/top-domains',
    clientTopBlocked: basePath + '/api/client/top-blocked',
    domainStats: basePath + '/api/domain/stats',
    domainClients: basePath + '/api/domain/clients',
    changePassword: basePath + '/api/change-password',
    backup: basePath + '/api/backup',
    restore: basePath + '/api/restore',
    blockInfo: basePath + '/api/block-info',
    recheckDiagnostics: basePath + '/api/diagnostics/recheck',
    ipInfo: basePath + '/api/ip-info',
    clients: basePath + '/api/clients',
    blockedClients: basePath + '/api/config',
    metrics: basePath + '/api/metrics',
    exportLogs: basePath + '/api/export',
    clearLogs: basePath + '/api/logs/clear',
    filteringStatus: basePath + '/api/filtering/status',
    health: basePath + '/api/health',
    highRiskCountries: basePath + '/api/system/high-risk-countries',
    serverCountry: basePath + '/api/system/server-country',
    login: basePath + '/api/login',
    logout: basePath + '/api/logout',
    setup: basePath + '/api/setup',
    mfaChallenge: basePath + '/api/mfa/challenge',
    mfaTOTPSetup: basePath + '/api/mfa/totp/setup',
    mfaTOTPVerify: basePath + '/api/mfa/totp/verify',
    mfaDisable: basePath + '/api/mfa/disable',
    mfaDelete: basePath + '/api/mfa/delete',
    mfaWebAuthnRegisterStart: basePath + '/api/mfa/webauthn/register/start',
    mfaWebAuthnRegisterFinish: basePath + '/api/mfa/webauthn/register/finish',
    mfaWebAuthnLoginStart: basePath + '/api/mfa/webauthn/login/start',
    mfaWebAuthnLoginFinish: basePath + '/api/mfa/webauthn/login/finish',
    checkVersion: basePath + '/api/system/check-version',
    systemUpdate: basePath + '/api/system/update'
};
