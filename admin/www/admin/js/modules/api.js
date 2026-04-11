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
    
    if (!response.ok) {
        throw new Error(`API Error: ${response.statusText}`);
    }
    
    return response.json();
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
