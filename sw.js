const CACHE_NAME = 'secure-box-v1';
const OFFLINE_PAGE = '/offline.html';

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.add(OFFLINE_PAGE))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request)
                .then((response) => {
                    console.log('Fetch succeeded:', response.url);
                    // Check for Cloudflare Errors (530, 520, etc) or Server Errors
                    if (!response.ok || response.status === 530 || response.status >= 500) {
                        return caches.match(OFFLINE_PAGE).then(cachedResponse => {
                            // If cache exists, return it. If not, return the error (better than nothing)
                            return cachedResponse || response;
                        });
                    }
                    return response;
                })
                .catch(() => {
                    console.log('Fetch failed; returning offline page instead.');
                    // Network completely dead
                    return caches.match(OFFLINE_PAGE);
                })
        );
    }
});

// Handle push notifications (for future server-side push support)
self.addEventListener('push', (event) => {
    if (!event.data) return;

    try {
        const data = event.data.json();
        const options = {
            body: data.body || 'New notification',
            vibrate: [200, 100, 200],
            data: data.data || {},
            tag: data.tag || 'default',
            requireInteraction: false
        };

        event.waitUntil(
            self.registration.showNotification(data.title || 'PiChat', options)
        );
    } catch (e) {
        console.error('Error handling push notification:', e);
    }
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
    event.notification.close();

    // Focus or open the app window
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
            // Check if there's already a window open
            for (const client of clientList) {
                if (client.url.includes('/chat') && 'focus' in client) {
                    return client.focus();
                }
            }
            // If no window is open, open one
            if (clients.openWindow) {
                return clients.openWindow('chat');
            }
        })
    );
});

// Handle notification close
self.addEventListener('notificationclose', (event) => {
    console.log('Notification closed:', event.notification.tag);
});