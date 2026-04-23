/**
 * Navigation, Routing, and Real-time Stream Module
 */
import * as api from '../services/api.js';
import { state, getEl } from './state.js';

export function initNavigation(viewHandlers) {
    const navItems = document.querySelectorAll('.nav-item');
    const viewTriggers = document.querySelectorAll('[data-view]');

    viewTriggers.forEach(item => {
        item.addEventListener('click', (e) => {
            const target = item.getAttribute('data-view');
            if (!target) return;

            // Prevent default for anchor tags (like the logo)
            if (item.tagName === 'A') e.preventDefault();
            
            // Update active state in sidebar
            navItems.forEach(i => i.classList.remove('active'));
            const matchedNav = document.querySelector(`.nav-item[data-view="${target}"]`);
            if (matchedNav) matchedNav.classList.add('active');
            else item.classList.add('active');
            
            document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
            getEl(target)?.classList.remove('hidden');
            
            // Call specific view handler if registered
            if (viewHandlers[target]) viewHandlers[target]();
            
            // Clean up other streams if needed
            if (target !== 'diagnostics') stopDiagTimer();
            if (target !== 'system-logs') stopSystemLogStream();

            if (window.innerWidth < 992) {
                document.querySelector('.sidebar')?.classList.remove('open');
                getEl('sidebar-overlay')?.classList.remove('open');
            }
        });
    });
}

/**
 * Programmatically navigate to a view and optionally set filters
 */
export function navigateTo(target, params = {}) {
    const item = document.querySelector(`.nav-item[data-view="${target}"]`);
    if (item) {
        // Trigger the click event on the nav item to use existing logic
        item.click();
        
        // Handle search parameters
        if (params.search) {
            // Check for common search input IDs based on target view
            const searchInput = getEl(`${target}-search`) || getEl('query-search') || getEl('global-search');
            if (searchInput) {
                searchInput.value = params.search;
                // Dispatch input event to trigger any live filtering logic
                searchInput.dispatchEvent(new Event('input'));
            }
        }
    }
}

// Global Timers and Streams

export function startDiagTimer(fetchDiagnostics) {
    stopDiagTimer();
    state.diagnosticsInterval = setInterval(fetchDiagnostics, 10000);
}

export function stopDiagTimer() {
    if (state.diagnosticsInterval) { 
        clearInterval(state.diagnosticsInterval); 
        state.diagnosticsInterval = null; 
    }
}

export function startSystemLogStream() {
    stopSystemLogStream();
    const term = getEl('system-log-terminal');
    if (term) term.innerHTML = '';
    state.systemLogStream = new EventSource(api.endpoints.systemLogs);

    let pendingLogs = [];
    let rafScheduled = false;

    const flushLogs = () => {
        rafScheduled = false;
        if (!term || pendingLogs.length === 0) return;
        term.innerHTML += pendingLogs.join('');
        pendingLogs = [];
        term.scrollTop = term.scrollHeight;
    };

    state.systemLogStream.onmessage = (e) => {
        if (!term) return;
        pendingLogs.push(e.data + '\n');
        if (!rafScheduled) {
            rafScheduled = true;
            requestAnimationFrame(flushLogs);
        }
    };
    state.systemLogStream.onerror = () => stopSystemLogStream();
}

export function stopSystemLogStream() {
    if (state.systemLogStream) { 
        state.systemLogStream.close(); 
        state.systemLogStream = null; 
    }
}

let _sseReconnectDelay = 1000;
let _sseReconnectTimer = null;
let _sseStopped = false;

function _connectSSE(createQueryRow, updateDashboardFeed) {
    if (_sseStopped) return;

    if (state.queryEventSource) {
        state.queryEventSource.close();
        state.queryEventSource = null;
    }

    const es = new EventSource(api.endpoints.events);
    state.queryEventSource = es;

    es.onopen = () => {
        _sseReconnectDelay = 1000; // Reset backoff on successful connection
    };

    es.onmessage = (event) => {
        try {
            if (!state.liveUpdatesEnabled) return;
            const query = JSON.parse(event.data);
            if (query.type === 'ping') return;

            updateDashboardFeed(query);

            if (state.fullQueryScroller) {
                state.fullQueryScroller.prepend(query);
            }
        } catch (err) {
            console.error('SSE JSON parse error:', err, event.data);
        }
    };

    es.onerror = () => {
        es.close();
        state.queryEventSource = null;

        if (_sseStopped) return;

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (cap)
        const delay = Math.min(_sseReconnectDelay, 30000);
        _sseReconnectDelay = Math.min(_sseReconnectDelay * 2, 30000);

        _sseReconnectTimer = setTimeout(() => {
            _connectSSE(createQueryRow, updateDashboardFeed);
        }, delay);
    };
}

export function startSSE(createQueryRow, updateDashboardFeed) {
    _sseStopped = false;
    _sseReconnectDelay = 1000;
    if (_sseReconnectTimer) {
        clearTimeout(_sseReconnectTimer);
        _sseReconnectTimer = null;
    }
    _connectSSE(createQueryRow, updateDashboardFeed);
}

export function stopSSE() {
    _sseStopped = true;
    if (_sseReconnectTimer) {
        clearTimeout(_sseReconnectTimer);
        _sseReconnectTimer = null;
    }
    if (state.queryEventSource) {
        state.queryEventSource.close();
        state.queryEventSource = null;
    }
}
