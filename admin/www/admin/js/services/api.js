/**
 * API Module - Handles all communication with the ShieldDNS backend
 */
export async function apiFetch(endpoint, options = {}) {
    // Inject CSRF protection header for state-changing requests
    const method = options.method?.toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
        options.headers = {
            'Content-Type': 'application/json',
            ...options.headers,
            'X-Shield-Request': 'true'
        };
    }
    const response = await fetch(endpoint, options);
    
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
    
    if (response.status === 204) {
        return {};
    }
    
    const text = await response.text();
    if (!text) {
        return {};
    }
    
    try {
        return JSON.parse(text);
    } catch (e) {
        throw new Error(`Invalid JSON response: ${text.substring(0, 100)}`);
    }
}

export const endpoints = {
    stats: '/api/stats',
    history: '/api/history',
    statsHistory: '/api/stats/history',
    config: '/api/config',
    queries: '/api/queries',
    search: '/api/search',
    events: '/api/events',
    tokens: '/api/tokens',
    createToken: '/api/tokens/create',
    updateToken: '/api/tokens/update',
    deleteToken: '/api/tokens/delete',
    presets: '/api/presets',
    allowlistPresets: '/api/presets/allow',
    countries: '/api/countries',
    authStatus: '/api/auth-status',
    topBlocked: '/api/top-blocked',
    topClients: '/api/top-clients',
    diagnostics: '/api/diagnostics',
    systemLogs: '/api/system-logs',
    refresh: '/api/refresh',
    toggleFiltering: '/api/filtering/toggle',
    addRule: '/api/rules/add',
    removeRule: '/api/rules/remove',
    fullReload: '/api/system/full-reload',
    reset: '/api/reset',
    resetLists: '/api/config/reset-lists',
    clientBlock: '/api/client/block',
    clientAlias: '/api/client/alias',
    clientStats: '/api/client/stats',
    clientTopDomains: '/api/client/top-domains',
    clientTopBlocked: '/api/client/top-blocked',
    domainStats: '/api/domain/stats',
    domainClients: '/api/domain/clients',
    changePassword: '/api/change-password',
    backup: '/api/backup',
    restore: '/api/restore',
    blockInfo: '/api/block-info',
    recheckDiagnostics: '/api/diagnostics/recheck',
    ipInfo: '/api/ip-info',
    clients: '/api/clients',
    metrics: '/api/metrics',
    export: '/api/export',
    filteringStatus: '/api/filtering/status',
    health: '/api/health'
};
