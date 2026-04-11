/* jshint worker: true */
const CACHE_NAME = 'shielddns-admin-v8';
const ASSETS = [
    '/admin/',
    '/admin/index.html',
    '/admin/style.css',
    '/admin/js/app.js',
    '/admin/utils.js',
    '/admin/manifest.json',
    '/admin/js/services/api.js',
    '/admin/js/services/fetch.js',
    '/admin/js/ui/helpers.js',
    '/admin/js/ui/charts.js',
    '/admin/js/ui/scroller.js',
    '/admin/js/ui/ui.js',
    '/admin/js/ui/renderers.js',
    '/admin/js/ui/events.js',
    '/admin/js/core/state.js',
    '/admin/js/core/auth.js',
    '/admin/js/core/navigation.js'
];

/**
 * ShieldDNS Service Worker
 */

// Install event - Cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            return cache.addAll(ASSETS);
        })
    );
});

// Activate event - Cleanup old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cache) => {
                    if (cache !== CACHE_NAME) {
                        return caches.delete(cache);
                    }
                })
            );
        })
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
            });

            // Return cached response if available, otherwise wait for network
            return cachedResponse || fetchPromise;
        })
    );
});
