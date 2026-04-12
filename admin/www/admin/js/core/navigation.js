/**
 * Navigation, Routing, and Real-time Stream Module
 */
import * as api from '../services/api.js';
import { state, getEl } from './state.js';

export function initNavigation(viewHandlers) {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const target = item.getAttribute('data-view');
            if (!target) return;
            
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            
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
    state.systemLogStream.onmessage = (e) => {
        if (!term) return;
        term.innerHTML += e.data + '\n';
        term.scrollTop = term.scrollHeight;
    };
    state.systemLogStream.onerror = () => stopSystemLogStream();
}

export function stopSystemLogStream() {
    if (state.systemLogStream) { 
        state.systemLogStream.close(); 
        state.systemLogStream = null; 
    }
}

export function startSSE(createQueryRow, updateDashboardFeed, scroller) {
    if (state.queryEventSource) state.queryEventSource.close();
    
    state.queryEventSource = new EventSource(api.endpoints.events);
    
    state.queryEventSource.onmessage = (event) => {
        try {
            const query = JSON.parse(event.data);
            if (query.type === 'ping') return;
            
            updateDashboardFeed(query);
            
            if (scroller) {
                scroller.prepend(query);
            }
        } catch (err) {
            console.error('SSE JSON parse error:', err, event.data);
        }
    };

    state.queryEventSource.onerror = (err) => {
        console.warn('SSE Connection lost. Reconnecting...', err);
        // EventSource automatically reconnects, but we might want to log it
    };
}

export function stopSSE() {
	if (state.queryEventSource) {
		state.queryEventSource.close();
		state.queryEventSource = null;
	}
}
