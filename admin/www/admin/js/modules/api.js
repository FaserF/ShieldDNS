/**
 * API Module - Handles all communication with the ShieldDNS backend
 */
export async function apiFetch(endpoint, options = {}) {
    const response = await fetch(endpoint, options);
    
    if (response.status === 403) {
        const text = await response.text();
        if (text.includes('Setup required') || text.includes('SETUP_REQUIRED')) {
            throw new Error('SETUP_REQUIRED');
        }
    }
    
    if (response.status === 401) {
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
    events: '/api/events',
    tokens: '/api/tokens',
    presets: '/api/presets',
    allowlistPresets: '/api/presets/allow',
    countries: '/api/countries',
    authStatus: '/api/auth-status'
};
