/**
 * Application State Management
 */

export const state = {
    currentConfig: {},
    allTokens: [],
    cachedQueries: [],
    activeFetchId: 0,
    fullQueryScroller: null,
    queryEventSource: null,
    allCountries: {},
    diagnosticsInterval: null,
    systemLogStream: null,
    isDirty: false,
    liveUpdatesEnabled: true
};

export const getEl = (id) => document.getElementById(id);

export const uiRefs = {
    authOverlay: getEl('auth-overlay'),
    setupView: getEl('setup-view'),
    loginView: getEl('login-view'),
    queryLogItems: getEl('query-log-items'),
    fullQueryLogItems: getEl('full-query-log-items'),
    statsContainer: {
        total: getEl('stat-total'),
        blocked: getEl('stat-blocked'),
        ratio: getEl('stat-ratio'),
        cache: getEl('stat-cache'),
        latency: getEl('stat-latency'),
        clients: getEl('stat-clients'),
        qps: getEl('stat-qps'),
        blockedDomains: getEl('stat-blocked-domains')
    },
    guide: {
        mobileBtn: getEl('guide-mobileconfig-btn'),
        mobileQR: getEl('guide-mobileconfig-qr')
    }
};

/**
 * Update UI References (call after DOM changes if needed)
 */
export const updateUIRefs = () => {
    uiRefs.authOverlay = getEl('auth-overlay');
    uiRefs.setupView = getEl('setup-view');
    uiRefs.loginView = getEl('login-view');
    uiRefs.queryLogItems = getEl('query-log-items');
    uiRefs.fullQueryLogItems = getEl('full-query-log-items');
    
    uiRefs.statsContainer.total = getEl('stat-total');
    uiRefs.statsContainer.blocked = getEl('stat-blocked');
    uiRefs.statsContainer.ratio = getEl('stat-ratio');
    uiRefs.statsContainer.cache = getEl('stat-cache');
    uiRefs.statsContainer.latency = getEl('stat-latency');
    uiRefs.statsContainer.clients = getEl('stat-clients');
    uiRefs.statsContainer.qps = getEl('stat-qps');
    uiRefs.statsContainer.blockedDomains = getEl('stat-blocked-domains');
    
    uiRefs.guide.mobileBtn = getEl('guide-mobileconfig-btn');
    uiRefs.guide.mobileQR = getEl('guide-mobileconfig-qr');
};
