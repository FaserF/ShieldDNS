/* jshint worker: true */
const CACHE_NAME = 'shielddns-admin-{{.CacheVersion}}';
const ASSETS = [
    './',
    'index.html',
    'style.css',
    'js/app.js',
    'utils.js',
    'manifest.json',
    'js/services/api.js',
    'js/services/fetch.js',
    'js/ui/helpers.js',
    'js/ui/charts.js',
    'js/ui/scroller.js',
    'js/ui/ui.js',
    'js/ui/renderers.js',
    'js/ui/events.js',
    'js/core/state.js',
    'js/core/auth.js',
    'js/core/navigation.js'
];

/**
 * ShieldDNS Service Worker
 */

// Install event - Cache static assets
self.addEventListener('install', (event) => {
    self.skipWaiting(); // Force new service worker to become active
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS);
        })
    );
});

// Activate event - Cleanup old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        Promise.all([
            self.clients.claim(), // Take control of all open clients immediately
            caches.keys().then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cache) => {
                        if (cache !== CACHE_NAME) {
                            return caches.delete(cache);
                        }
                    })
                );
            })
        ])
    );
});

// Fetch event - Stale-while-revalidate for assets
self.addEventListener('fetch', (event) => {
    // Only handle GET requests and http/https schemes
    if (event.request.method !== 'GET') return;
    if (!event.request.url.startsWith('http')) return;

    // Skip API requests to ensure real-time data
    if (event.request.url.includes('/api/')) return;

    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            const fetchPromise = fetch(event.request).then((networkResponse) => {
                // If it's a valid response, update the cache
                if (networkResponse && networkResponse.status === 200) {
                    const responseToCache = networkResponse.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseToCache);
                    });
                }
                return networkResponse;
            }).catch((err) => {
                // Return cached response if offline/fetch fails, don't crash the worker
                console.warn(`[SW] Fetch failed for ${event.request.url}:`, err);
                return cachedResponse || new Response('Network error occurred', { status: 503, statusText: 'Service Unavailable' });
            });

            // Return cached response if available, otherwise wait for network
            return cachedResponse || fetchPromise;
        })
    );
});
