// Service Worker for Vulnerability Intelligence Dashboard
// Provides offline functionality, caching, and performance optimizations

const CACHE_NAME = 'vuln-bot-v1';
const OFFLINE_URL = '/offline.html';
const STATIC_CACHE_URLS = [
  '/',
  '/cves/',
  '/about/',
  '/offline.html',
  '/assets/css/main.css',
  'https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js',
  'https://cdn.jsdelivr.net/npm/fuse.js@7.0.0'
];

// Data cache configuration
const DATA_CACHE_NAME = 'vuln-data-v1';
const DATA_CACHE_URLS = [
  '/api/vulns/index.json',
  '/api/vulns/chunk-index.json'
];

// Cache duration settings (in milliseconds)
const CACHE_DURATIONS = {
  static: 7 * 24 * 60 * 60 * 1000,  // 7 days for static assets
  data: 4 * 60 * 60 * 1000,          // 4 hours for vulnerability data
  pages: 2 * 60 * 60 * 1000          // 2 hours for HTML pages
};

// Install event - cache static resources
self.addEventListener('install', event => {
  console.log('Service Worker installing...');
  
  event.waitUntil(
    Promise.all([
      // Cache static resources
      caches.open(CACHE_NAME).then(cache => {
        console.log('Caching static resources...');
        return cache.addAll(STATIC_CACHE_URLS);
      }),
      
      // Cache data resources
      caches.open(DATA_CACHE_NAME).then(cache => {
        console.log('Caching data resources...');
        return cache.addAll(DATA_CACHE_URLS.map(url => new Request(url, {
          cache: 'no-cache'
        })));
      })
    ]).then(() => {
      // Skip waiting to activate immediately
      return self.skipWaiting();
    })
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  console.log('Service Worker activating...');
  
  event.waitUntil(
    Promise.all([
      // Clean up old caches
      caches.keys().then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (cacheName !== CACHE_NAME && cacheName !== DATA_CACHE_NAME) {
              console.log('Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      }),
      
      // Take control of all pages
      self.clients.claim()
    ])
  );
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', event => {
  // Only handle GET requests
  if (event.request.method !== 'GET') {
    return;
  }
  
  const url = new URL(event.request.url);
  
  // Handle different types of requests with appropriate strategies
  if (isStaticAsset(url)) {
    event.respondWith(cacheFirst(event.request, CACHE_NAME));
  } else if (isDataRequest(url)) {
    event.respondWith(staleWhileRevalidate(event.request, DATA_CACHE_NAME));
  } else if (isPageRequest(url)) {
    event.respondWith(networkFirst(event.request, CACHE_NAME));
  } else if (isExternalResource(url)) {
    event.respondWith(cacheFirst(event.request, CACHE_NAME));
  }
});

// Background sync for offline data updates
self.addEventListener('sync', event => {
  if (event.tag === 'vulnerability-data-sync') {
    console.log('Background sync: updating vulnerability data');
    event.waitUntil(updateVulnerabilityData());
  }
});

// Push notifications for critical vulnerabilities
self.addEventListener('push', event => {
  if (event.data) {
    const data = event.data.json();
    
    if (data.type === 'critical-vulnerability') {
      const options = {
        body: `Critical vulnerability detected: ${data.cveId}`,
        icon: '/assets/icons/icon-192.png',
        badge: '/assets/icons/badge-72.png',
        tag: 'critical-vuln',
        requireInteraction: true,
        actions: [
          {
            action: 'view',
            title: 'View Details',
            icon: '/assets/icons/view.png'
          },
          {
            action: 'dismiss',
            title: 'Dismiss',
            icon: '/assets/icons/dismiss.png'
          }
        ],
        data: {
          cveId: data.cveId,
          url: `/cves/${data.cveId}.html`
        }
      };
      
      event.waitUntil(
        self.registration.showNotification('Critical Vulnerability Alert', options)
      );
    }
  }
});

// Handle notification clicks
self.addEventListener('notificationclick', event => {
  event.notification.close();
  
  if (event.action === 'view' && event.notification.data.url) {
    event.waitUntil(
      clients.openWindow(event.notification.data.url)
    );
  }
});

// Cache strategies
async function cacheFirst(request, cacheName) {
  try {
    const cachedResponse = await caches.match(request);
    if (cachedResponse && !isExpired(cachedResponse, CACHE_DURATIONS.static)) {
      return cachedResponse;
    }
    
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  } catch (error) {
    console.error('Cache first strategy failed:', error);
    const cachedResponse = await caches.match(request);
    return cachedResponse || createErrorResponse('Resource unavailable offline');
  }
}

async function networkFirst(request, cacheName) {
  try {
    const networkResponse = await fetch(request);
    if (networkResponse.ok) {
      const cache = await caches.open(cacheName);
      cache.put(request, networkResponse.clone());
      return networkResponse;
    }
    throw new Error('Network response not ok');
  } catch (error) {
    console.error('Network first strategy failed:', error);
    const cachedResponse = await caches.match(request);
    
    if (cachedResponse) {
      return cachedResponse;
    }
    
    // Return offline page for page requests
    if (isPageRequest(new URL(request.url))) {
      return caches.match(OFFLINE_URL);
    }
    
    return createErrorResponse('Content unavailable offline');
  }
}

async function staleWhileRevalidate(request, cacheName) {
  const cache = await caches.open(cacheName);
  const cachedResponse = await cache.match(request);
  
  const fetchPromise = fetch(request).then(networkResponse => {
    if (networkResponse.ok) {
      cache.put(request, networkResponse.clone());
    }
    return networkResponse;
  }).catch(error => {
    console.error('Background fetch failed:', error);
    return cachedResponse;
  });
  
  // Return cached response immediately if available, otherwise wait for network
  return cachedResponse || fetchPromise;
}

// Utility functions
function isStaticAsset(url) {
  return /\.(css|js|png|jpg|jpeg|svg|ico|woff|woff2|ttf)$/i.test(url.pathname);
}

function isDataRequest(url) {
  return url.pathname.startsWith('/api/') || url.pathname.endsWith('.json');
}

function isPageRequest(url) {
  return url.pathname === '/' || 
         url.pathname.startsWith('/cves/') || 
         url.pathname.startsWith('/about/') ||
         url.pathname.endsWith('.html');
}

function isExternalResource(url) {
  return url.origin !== self.location.origin;
}

function isExpired(response, maxAge) {
  const dateHeader = response.headers.get('date');
  if (!dateHeader) return false;
  
  const date = new Date(dateHeader);
  return (Date.now() - date.getTime()) > maxAge;
}

function createErrorResponse(message) {
  return new Response(
    JSON.stringify({ error: message }),
    {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    }
  );
}

async function updateVulnerabilityData() {
  try {
    const cache = await caches.open(DATA_CACHE_NAME);
    
    // Update main data files
    const dataUrls = [
      '/api/vulns/index.json',
      '/api/vulns/chunk-index.json'
    ];
    
    for (const url of dataUrls) {
      try {
        const response = await fetch(url, { cache: 'no-cache' });
        if (response.ok) {
          await cache.put(url, response);
          console.log(`Updated cache for: ${url}`);
        }
      } catch (error) {
        console.error(`Failed to update ${url}:`, error);
      }
    }
    
    console.log('Vulnerability data sync completed');
  } catch (error) {
    console.error('Background sync failed:', error);
  }
}

// Analytics for offline usage
function trackOfflineUsage(request) {
  // Send analytics event when serving from cache
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    navigator.serviceWorker.controller.postMessage({
      type: 'OFFLINE_USAGE',
      url: request.url,
      timestamp: Date.now()
    });
  }
}

// Message handling for communication with main thread
self.addEventListener('message', event => {
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  } else if (event.data.type === 'CHECK_UPDATE') {
    // Check for updates and notify client
    checkForUpdates().then(hasUpdate => {
      event.ports[0].postMessage({ hasUpdate });
    });
  }
});

async function checkForUpdates() {
  try {
    const response = await fetch('/api/vulns/index.json', { 
      cache: 'no-cache' 
    });
    
    if (response.ok) {
      const data = await response.json();
      const cached = await caches.match('/api/vulns/index.json');
      
      if (cached) {
        const cachedData = await cached.json();
        return data.metadata.generated_at !== cachedData.metadata.generated_at;
      }
    }
    
    return false;
  } catch (error) {
    console.error('Failed to check for updates:', error);
    return false;
  }
}