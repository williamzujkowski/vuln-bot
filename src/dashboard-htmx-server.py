#!/usr/bin/env python3
"""
HTMX Dashboard Server - Proof of Concept
Demonstrates server-side rendering with HTMX for the vulnerability dashboard
"""

import json
import os
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import random

class DashboardHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests"""
        path = urlparse(self.path).path
        
        if path == '/':
            # Serve the main dashboard HTML
            self.send_file('dashboard-htmx.html', 'text/html')
        elif path == '/api/stats':
            self.send_stats()
        elif path == '/api/vulnerabilities':
            self.send_vulnerabilities()
        elif path == '/api/charts':
            self.send_charts()
        elif path == '/api/export/csv':
            self.send_csv()
        else:
            self.send_error(404)
    
    def do_POST(self):
        """Handle POST requests"""
        path = urlparse(self.path).path
        
        if path == '/api/filter':
            self.send_filtered_vulnerabilities()
        elif path == '/api/search':
            self.send_search_results()
        elif path == '/api/filter/quick':
            self.send_quick_filter_results()
        else:
            self.send_error(404)
    
    def send_file(self, filename, content_type):
        """Send a file response"""
        try:
            with open(filename, 'rb') as f:
                content = f.read()
            
            self.send_response(200)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        except FileNotFoundError:
            self.send_error(404)
    
    def send_stats(self):
        """Send dashboard statistics as HTML fragment"""
        # Generate mock stats
        total = random.randint(100, 200)
        critical = random.randint(20, 50)
        high_epss = random.randint(30, 60)
        avg_risk = random.randint(65, 85)
        
        html = f'''
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🛡️</div>
                <div class="stat-value">{total}</div>
                <div class="stat-label">Total Vulnerabilities</div>
                <div style="color: var(--accent-danger); font-size: 0.875rem;">
                    +{random.randint(5, 15)} from last week
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">🚨</div>
                <div class="stat-value">{critical}</div>
                <div class="stat-label">Critical Severity</div>
                <div style="color: var(--accent-danger); font-size: 0.875rem;">
                    +{random.randint(1, 5)} new today
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">📈</div>
                <div class="stat-value">{high_epss}</div>
                <div class="stat-label">High EPSS (≥90%)</div>
                <div style="color: var(--text-muted); font-size: 0.875rem;">
                    Exploitation likely
                </div>
            </div>
            
            <div class="stat-card">
                <div class="stat-icon">⚡</div>
                <div class="stat-value">{avg_risk}</div>
                <div class="stat-label">Average Risk Score</div>
                <div style="color: var(--text-muted); font-size: 0.875rem;">
                    Out of 100
                </div>
            </div>
        </div>
        '''
        
        self.send_html_response(html)
    
    def send_vulnerabilities(self, filters=None):
        """Send vulnerability table as HTML fragment"""
        # Generate mock vulnerability data
        vulns = []
        vendors = ['Microsoft', 'Apache', 'Oracle', 'Cisco', 'VMware', 'Adobe']
        
        for i in range(50):
            severity = random.choice(['CRITICAL', 'HIGH', 'MEDIUM'])
            cvss = round(random.uniform(7.0, 10.0) if severity == 'CRITICAL' else random.uniform(5.0, 8.0), 1)
            epss = random.randint(70, 99)
            
            vulns.append({
                'cve_id': f'CVE-2025-{40000 + i:05d}',
                'severity': severity,
                'cvss': cvss,
                'epss': epss,
                'title': f'{severity} vulnerability in {random.choice(vendors)} component',
                'published': (datetime.now() - timedelta(days=random.randint(0, 30))).strftime('%Y-%m-%d')
            })
        
        # Build table HTML
        rows = []
        for vuln in vulns[:20]:  # Show first 20
            severity_class = f'severity-{vuln["severity"].lower()}'
            rows.append(f'''
            <tr>
                <td>
                    <a href="#" style="color: var(--accent-primary); text-decoration: none;"
                       hx-get="/api/vulnerability/{vuln['cve_id']}"
                       hx-target="#modal-container"
                       hx-swap="innerHTML">
                        {vuln['cve_id']}
                    </a>
                </td>
                <td><span class="severity-badge {severity_class}">{vuln['severity']}</span></td>
                <td>{vuln['cvss']}</td>
                <td>{vuln['epss']}%</td>
                <td>{vuln['title']}</td>
                <td>{vuln['published']}</td>
            </tr>
            ''')
        
        html = f'''
        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th hx-get="/api/sort?field=cve_id" hx-target="#vulnerabilities-table">CVE ID</th>
                        <th hx-get="/api/sort?field=severity" hx-target="#vulnerabilities-table">Severity</th>
                        <th hx-get="/api/sort?field=cvss" hx-target="#vulnerabilities-table">CVSS</th>
                        <th hx-get="/api/sort?field=epss" hx-target="#vulnerabilities-table">EPSS %</th>
                        <th>Title</th>
                        <th hx-get="/api/sort?field=published" hx-target="#vulnerabilities-table">Published</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
        </div>
        
        <div class="pagination">
            <button class="page-btn" disabled>Previous</button>
            <span style="color: var(--text-secondary);">Page 1 of 3</span>
            <button class="page-btn" 
                    hx-get="/api/vulnerabilities?page=2" 
                    hx-target="#vulnerabilities-table">
                Next
            </button>
        </div>
        
        <script>
            // Update result count
            document.getElementById('result-count').textContent = 'Showing 20 of 50 results';
        </script>
        '''
        
        self.send_html_response(html)
    
    def send_charts(self):
        """Send charts section as HTML fragment"""
        html = '''
        <div class="chart-card">
            <h3 class="chart-title">Severity Distribution</h3>
            <div class="chart-container">
                <canvas id="severity-chart"></canvas>
            </div>
        </div>
        
        <div class="chart-card">
            <h3 class="chart-title">30-Day Trend</h3>
            <div class="chart-container">
                <canvas id="trend-chart"></canvas>
            </div>
        </div>
        
        <script>
            // Store chart data globally for initialization
            window.chartData = {
                severity: {
                    labels: ['Critical', 'High', 'Medium'],
                    datasets: [{
                        data: [25, 45, 30],
                        backgroundColor: ['#dc2626', '#ef4444', '#f59e0b']
                    }]
                }
            };
            
            // Trigger chart initialization
            document.body.dispatchEvent(new Event('htmx:afterSwap'));
        </script>
        '''
        
        self.send_html_response(html)
    
    def send_filtered_vulnerabilities(self):
        """Handle filter form submission"""
        # In a real implementation, we'd parse the POST data and apply filters
        # For this demo, we'll just return filtered results
        self.send_vulnerabilities()
    
    def send_search_results(self):
        """Handle search requests"""
        # In a real implementation, we'd parse the search query
        # For this demo, we'll return search results
        self.send_vulnerabilities()
    
    def send_quick_filter_results(self):
        """Handle quick filter buttons"""
        # Parse the filter type from POST data
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # For demo, just return filtered results
        self.send_vulnerabilities()
    
    def send_csv(self):
        """Send CSV export"""
        csv_content = '''CVE ID,Severity,CVSS,EPSS %,Title,Published
CVE-2025-40001,CRITICAL,9.8,95,Critical vulnerability in Microsoft Exchange,2025-01-15
CVE-2025-40002,HIGH,8.1,88,High vulnerability in Apache Log4j,2025-01-14
'''
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv')
        self.send_header('Content-Disposition', 'attachment; filename="vulnerabilities.csv"')
        self.send_header('Content-Length', len(csv_content))
        self.end_headers()
        self.wfile.write(csv_content.encode())
    
    def send_html_response(self, html):
        """Send HTML response"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(html))
        self.end_headers()
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        print(f"{self.address_string()} - {format % args}")

def main():
    """Run the HTMX dashboard server"""
    port = 8080
    server = HTTPServer(('localhost', port), DashboardHTTPHandler)
    
    print(f"🚀 HTMX Dashboard Server running at http://localhost:{port}")
    print("📝 This is a proof-of-concept demonstrating server-side rendering with HTMX")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✅ Server stopped")
        server.shutdown()

if __name__ == '__main__':
    main()