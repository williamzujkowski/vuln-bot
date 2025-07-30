/**
 * Service Worker for HTMX Static Dashboard
 * Provides client-side search and filtering capabilities
 */

const CACHE_NAME = 'vuln-dashboard-v1';
const API_CACHE = 'vuln-api-cache-v1';

// Files to cache on install
const STATIC_CACHE = [
    '/',
    '/index.html',
    '/fragments/stats.html',
    '/fragments/vulnerabilities.html',
    '/fragments/charts.html',
    '/data/vulnerabilities.json',
    'https://unpkg.com/htmx.org@1.9.10',
    'https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js',
    'https://cdn.jsdelivr.net/npm/chart.js'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            console.log('Caching static assets');
            return cache.addAll(STATIC_CACHE.map(url => 
                url.startsWith('http') ? url : self.location.origin + url
            ));
        })
    );
    self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME && cacheName !== API_CACHE) {
                        console.log('Deleting old cache:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
    self.clients.claim();
});

// Fetch event - serve from cache, with dynamic handling
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Handle API-like requests for dynamic filtering
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(handleApiRequest(event.request));
        return;
    }
    
    // Network-first strategy for fragments
    if (url.pathname.includes('/fragments/')) {
        event.respondWith(
            fetch(event.request)
                .then(response => {
                    // Cache successful responses
                    if (response.status === 200) {
                        const responseToCache = response.clone();
                        caches.open(API_CACHE).then(cache => {
                            cache.put(event.request, responseToCache);
                        });
                    }
                    return response;
                })
                .catch(() => {
                    // Fallback to cache
                    return caches.match(event.request);
                })
        );
        return;
    }
    
    // Cache-first strategy for static assets
    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});

// Handle API-like requests with client-side processing
async function handleApiRequest(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    try {
        // Load vulnerability data
        const dataResponse = await caches.match('/data/vulnerabilities.json');
        if (!dataResponse) {
            return new Response('Data not found', { status: 404 });
        }
        
        const vulnerabilities = await dataResponse.json();
        
        // Handle search
        if (path === '/api/search') {
            const formData = await request.formData();
            const query = formData.get('search')?.toLowerCase() || '';
            
            const filtered = vulnerabilities.filter(vuln => 
                vuln.cve_id.toLowerCase().includes(query) ||
                vuln.title.toLowerCase().includes(query) ||
                vuln.vendors.some(v => v.toLowerCase().includes(query))
            );
            
            return generateTableResponse(filtered);
        }
        
        // Handle advanced filtering
        if (path === '/api/filter') {
            const formData = await request.formData();
            let filtered = [...vulnerabilities];
            
            // Apply filters
            const severity = formData.get('severity');
            if (severity) {
                filtered = filtered.filter(v => v.severity === severity);
            }
            
            const cvssMin = parseFloat(formData.get('cvss_min') || '0');
            const cvssMax = parseFloat(formData.get('cvss_max') || '10');
            filtered = filtered.filter(v => 
                (v.cvss_score || 0) >= cvssMin && (v.cvss_score || 0) <= cvssMax
            );
            
            const epssMin = parseInt(formData.get('epss_min') || '0');
            const epssMax = parseInt(formData.get('epss_max') || '100');
            filtered = filtered.filter(v => 
                v.epss_percentile >= epssMin && v.epss_percentile <= epssMax
            );
            
            const vendor = formData.get('vendor')?.toLowerCase();
            if (vendor) {
                filtered = filtered.filter(v => 
                    v.vendors.some(ven => ven.toLowerCase().includes(vendor))
                );
            }
            
            return generateTableResponse(filtered);
        }
        
        // Handle real-time stats update
        if (path === '/api/stats/live') {
            return generateLiveStats(vulnerabilities);
        }
        
    } catch (error) {
        console.error('Service worker error:', error);
        return new Response('Internal error', { status: 500 });
    }
    
    return new Response('Not found', { status: 404 });
}

// Generate table HTML response
function generateTableResponse(vulnerabilities, page = 1, perPage = 50) {
    const total = vulnerabilities.length;
    const totalPages = Math.ceil(total / perPage);
    const start = (page - 1) * perPage;
    const pageVulns = vulnerabilities.slice(start, start + perPage);
    
    const rows = pageVulns.map(vuln => {
        const severityClass = `severity-${vuln.severity.toLowerCase()}`;
        const riskClass = vuln.risk_score >= 80 ? 'critical' : 'high';
        
        // Format date
        const pubDate = new Date(vuln.published_date);
        const daysOld = Math.floor((Date.now() - pubDate) / (1000 * 60 * 60 * 24));
        let dateStr = pubDate.toLocaleDateString();
        if (daysOld === 0) dateStr = 'Today';
        else if (daysOld === 1) dateStr = 'Yesterday';
        else if (daysOld < 7) dateStr = `${daysOld} days ago`;
        
        return `
        <tr class="vulnerability-row" data-cve="${vuln.cve_id}">
            <td>
                <a href="#" class="cve-link" data-cve="${vuln.cve_id}"
                   onclick="openCveModal('${vuln.cve_id}'); return false;">
                    ${vuln.cve_id}
                </a>
            </td>
            <td><span class="severity-badge ${severityClass}">${vuln.severity}</span></td>
            <td>${vuln.cvss_score || 'N/A'}</td>
            <td>${vuln.epss_percentile}%</td>
            <td>
                <div class="risk-score ${riskClass}">
                    <span>${vuln.risk_score}</span>
                </div>
            </td>
            <td class="title-cell">${vuln.title.substring(0, 80)}${vuln.title.length > 80 ? '...' : ''}</td>
            <td>${vuln.vendors.slice(0, 2).join(', ')}${vuln.vendors.length > 2 ? '...' : ''}</td>
            <td>${dateStr}</td>
        </tr>
        `;
    }).join('');
    
    const html = `
    <div class="table-container" id="vulnerabilities-table">
        <table class="data-table">
            <thead>
                <tr>
                    <th class="sortable" onclick="clientSort('cve_id')">CVE ID</th>
                    <th class="sortable" onclick="clientSort('severity')">Severity</th>
                    <th class="sortable" onclick="clientSort('cvss_score')">CVSS</th>
                    <th class="sortable" onclick="clientSort('epss_percentile')">EPSS %</th>
                    <th class="sortable" onclick="clientSort('risk_score')">Risk Score</th>
                    <th>Title</th>
                    <th>Vendors</th>
                    <th class="sortable" onclick="clientSort('published_date')">Published</th>
                </tr>
            </thead>
            <tbody>
                ${rows}
            </tbody>
        </table>
        
        <div class="pagination">
            <button class="page-btn" ${page <= 1 ? 'disabled' : ''} 
                    onclick="clientPaginate(${page - 1})">
                Previous
            </button>
            <span class="page-info">
                Page ${page} of ${totalPages} • ${total} vulnerabilities
            </span>
            <button class="page-btn" ${page >= totalPages ? 'disabled' : ''}
                    onclick="clientPaginate(${page + 1})">
                Next
            </button>
        </div>
    </div>
    
    <script>
        document.getElementById('result-count').textContent = 'Showing ${pageVulns.length} of ${total} results';
    </script>
    `;
    
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

// Generate live statistics
function generateLiveStats(vulnerabilities) {
    const now = new Date();
    const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
    const today = now.toISOString().split('T')[0];
    
    const stats = {
        total: vulnerabilities.length,
        critical: vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        highEpss: vulnerabilities.filter(v => v.epss_percentile >= 90).length,
        avgRisk: Math.round(
            vulnerabilities.reduce((sum, v) => sum + v.risk_score, 0) / vulnerabilities.length
        ),
        weekChange: vulnerabilities.filter(v => 
            new Date(v.published_date) >= weekAgo
        ).length,
        todayNew: vulnerabilities.filter(v => 
            v.published_date.startsWith(today)
        ).length
    };
    
    const html = `
    <div class="stats-grid" id="stats-container">
        <div class="stat-card">
            <div class="stat-icon">🛡️</div>
            <div class="stat-value">${stats.total}</div>
            <div class="stat-label">Total Vulnerabilities</div>
            <div class="stat-change ${stats.weekChange > 0 ? 'negative' : ''}">
                <span>${stats.weekChange > 0 ? '+' : ''}${stats.weekChange}</span>
                <span>from last week</span>
            </div>
        </div>
        
        <div class="stat-card">
            <div class="stat-icon">🚨</div>
            <div class="stat-value">${stats.critical}</div>
            <div class="stat-label">Critical Severity</div>
            <div class="stat-change negative">
                <span>+${stats.todayNew}</span>
                <span>new today</span>
            </div>
        </div>
        
        <div class="stat-card">
            <div class="stat-icon">📈</div>
            <div class="stat-value">${stats.highEpss}</div>
            <div class="stat-label">High EPSS (≥90%)</div>
            <div class="stat-change">
                <span>Exploitation likely</span>
            </div>
        </div>
        
        <div class="stat-card">
            <div class="stat-icon">⚡</div>
            <div class="stat-value">${stats.avgRisk}</div>
            <div class="stat-label">Average Risk Score</div>
            <div class="stat-change">
                <span>Out of 100</span>
            </div>
        </div>
    </div>
    
    <div class="live-indicator">
        <span class="pulse"></span>
        <span>Live Data</span>
    </div>
    `;
    
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

// Message handler for client-worker communication
self.addEventListener('message', (event) => {
    if (event.data.type === 'CACHE_UPDATE') {
        // Force cache update
        caches.delete(API_CACHE).then(() => {
            console.log('API cache cleared for update');
        });
    }
});