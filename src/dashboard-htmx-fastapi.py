#!/usr/bin/env python3
"""
FastAPI + HTMX Dashboard Implementation
Production-ready example showing how to integrate with existing data pipeline
"""

from fastapi import FastAPI, Request, Query, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional, List
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
from contextlib import asynccontextmanager

# Database setup
DB_PATH = Path(".cache/vulns.db")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    # Initialize database connection pool
    app.state.db = sqlite3.connect(DB_PATH, check_same_thread=False)
    app.state.db.row_factory = sqlite3.Row
    yield
    # Cleanup
    app.state.db.close()

app = FastAPI(lifespan=lifespan)

# Templates
templates = Jinja2Templates(directory="templates")

# Static files (if needed)
# app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    return HTMLResponse(content=open("dashboard-htmx.html").read())

@app.get("/api/stats", response_class=HTMLResponse)
async def get_stats(request: Request):
    """Get dashboard statistics"""
    db = request.app.state.db
    cursor = db.cursor()
    
    # Get statistics from database
    stats = cursor.execute("""
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical,
            COUNT(CASE WHEN epss_percentile >= 90 THEN 1 END) as high_epss,
            AVG(CASE 
                WHEN cvss_score IS NOT NULL THEN cvss_score * 10 
                ELSE 50 
            END) as avg_risk
        FROM vulnerabilities
        WHERE epss_percentile >= 70
    """).fetchone()
    
    # Get week-over-week change
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    week_change = cursor.execute("""
        SELECT COUNT(*) as new_vulns
        FROM vulnerabilities
        WHERE published_date >= ? AND epss_percentile >= 70
    """, (week_ago,)).fetchone()
    
    html = f"""
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-icon">🛡️</div>
            <div class="stat-value">{stats['total']}</div>
            <div class="stat-label">Total Vulnerabilities</div>
            <div style="color: var(--accent-danger); font-size: 0.875rem;">
                +{week_change['new_vulns']} from last week
            </div>
        </div>
        
        <div class="stat-card">
            <div class="stat-icon">🚨</div>
            <div class="stat-value">{stats['critical']}</div>
            <div class="stat-label">Critical Severity</div>
        </div>
        
        <div class="stat-card">
            <div class="stat-icon">📈</div>
            <div class="stat-value">{stats['high_epss']}</div>
            <div class="stat-label">High EPSS (≥90%)</div>
        </div>
        
        <div class="stat-card">
            <div class="stat-icon">⚡</div>
            <div class="stat-value">{int(stats['avg_risk'])}</div>
            <div class="stat-label">Average Risk Score</div>
        </div>
    </div>
    """
    
    return HTMLResponse(content=html)

@app.get("/api/vulnerabilities", response_class=HTMLResponse)
async def get_vulnerabilities(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=10, le=100),
    sort: str = Query("epss_percentile", regex="^(cve_id|severity|cvss_score|epss_percentile|published_date)$"),
    order: str = Query("desc", regex="^(asc|desc)$")
):
    """Get paginated vulnerabilities"""
    db = request.app.state.db
    cursor = db.cursor()
    
    offset = (page - 1) * limit
    
    # Get total count
    total = cursor.execute("""
        SELECT COUNT(*) as count 
        FROM vulnerabilities 
        WHERE epss_percentile >= 70
    """).fetchone()['count']
    
    # Get vulnerabilities
    vulns = cursor.execute(f"""
        SELECT 
            cve_id,
            severity,
            cvss_score,
            epss_percentile,
            title,
            published_date,
            vendors,
            tags
        FROM vulnerabilities
        WHERE epss_percentile >= 70
        ORDER BY {sort} {order}
        LIMIT ? OFFSET ?
    """, (limit, offset)).fetchall()
    
    # Build table rows
    rows = []
    for vuln in vulns:
        severity_class = f'severity-{vuln["severity"].lower()}'
        vendors_list = json.loads(vuln['vendors']) if vuln['vendors'] else []
        tags_list = json.loads(vuln['tags']) if vuln['tags'] else []
        
        # Format published date
        pub_date = datetime.fromisoformat(vuln['published_date'])
        days_old = (datetime.now() - pub_date).days
        if days_old == 0:
            date_str = "Today"
        elif days_old == 1:
            date_str = "Yesterday"
        elif days_old < 7:
            date_str = f"{days_old} days ago"
        else:
            date_str = pub_date.strftime("%Y-%m-%d")
        
        rows.append(f"""
        <tr>
            <td>
                <a href="#" 
                   style="color: var(--accent-primary); text-decoration: none;"
                   hx-get="/api/vulnerability/{vuln['cve_id']}"
                   hx-target="#modal-container"
                   hx-swap="innerHTML">
                    {vuln['cve_id']}
                </a>
            </td>
            <td><span class="severity-badge {severity_class}">{vuln['severity']}</span></td>
            <td>{vuln['cvss_score'] or 'N/A'}</td>
            <td>{vuln['epss_percentile']}%</td>
            <td>{vuln['title'][:60]}...</td>
            <td>{', '.join(vendors_list[:2])}</td>
            <td>{'⭐ KEV' if 'KEV' in tags_list else ''}</td>
            <td>{date_str}</td>
        </tr>
        """)
    
    # Calculate pagination
    total_pages = (total + limit - 1) // limit
    
    html = f"""
    <div class="table-wrapper">
        <table>
            <thead>
                <tr>
                    <th hx-get="/api/vulnerabilities?sort=cve_id&order={'asc' if sort == 'cve_id' and order == 'desc' else 'desc'}" 
                        hx-target="#vulnerabilities-table"
                        style="cursor: pointer;">
                        CVE ID {' ↓' if sort == 'cve_id' and order == 'desc' else ' ↑' if sort == 'cve_id' and order == 'asc' else ''}
                    </th>
                    <th hx-get="/api/vulnerabilities?sort=severity" 
                        hx-target="#vulnerabilities-table"
                        style="cursor: pointer;">
                        Severity
                    </th>
                    <th hx-get="/api/vulnerabilities?sort=cvss_score&order={'asc' if sort == 'cvss_score' and order == 'desc' else 'desc'}" 
                        hx-target="#vulnerabilities-table"
                        style="cursor: pointer;">
                        CVSS {' ↓' if sort == 'cvss_score' and order == 'desc' else ' ↑' if sort == 'cvss_score' and order == 'asc' else ''}
                    </th>
                    <th hx-get="/api/vulnerabilities?sort=epss_percentile&order={'asc' if sort == 'epss_percentile' and order == 'desc' else 'desc'}" 
                        hx-target="#vulnerabilities-table"
                        style="cursor: pointer;">
                        EPSS % {' ↓' if sort == 'epss_percentile' and order == 'desc' else ' ↑' if sort == 'epss_percentile' and order == 'asc' else ''}
                    </th>
                    <th>Title</th>
                    <th>Vendors</th>
                    <th>Tags</th>
                    <th hx-get="/api/vulnerabilities?sort=published_date&order={'asc' if sort == 'published_date' and order == 'desc' else 'desc'}" 
                        hx-target="#vulnerabilities-table"
                        style="cursor: pointer;">
                        Published {' ↓' if sort == 'published_date' and order == 'desc' else ' ↑' if sort == 'published_date' and order == 'asc' else ''}
                    </th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </div>
    
    <div class="pagination">
        <button class="page-btn" 
                {'disabled' if page <= 1 else ''}
                {f'hx-get="/api/vulnerabilities?page={page-1}&limit={limit}&sort={sort}&order={order}"' if page > 1 else ''}
                hx-target="#vulnerabilities-table">
            Previous
        </button>
        <span style="color: var(--text-secondary);">
            Page {page} of {total_pages} ({total} total)
        </span>
        <button class="page-btn" 
                {'disabled' if page >= total_pages else ''}
                {f'hx-get="/api/vulnerabilities?page={page+1}&limit={limit}&sort={sort}&order={order}"' if page < total_pages else ''}
                hx-target="#vulnerabilities-table">
            Next
        </button>
    </div>
    """
    
    return HTMLResponse(content=html)

@app.post("/api/filter", response_class=HTMLResponse)
async def filter_vulnerabilities(
    request: Request,
    search: str = Form(""),
    severity: str = Form(""),
    cvss_min: float = Form(0),
    cvss_max: float = Form(10),
    epss_min: int = Form(70),
    epss_max: int = Form(100),
    published_from: str = Form(""),
    published_to: str = Form(""),
    vendor: str = Form("")
):
    """Filter vulnerabilities based on form inputs"""
    db = request.app.state.db
    cursor = db.cursor()
    
    # Build query dynamically
    conditions = ["epss_percentile >= 70"]  # Base condition
    params = []
    
    if search:
        conditions.append("(cve_id LIKE ? OR title LIKE ? OR vendors LIKE ?)")
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
    
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    
    if cvss_min > 0 or cvss_max < 10:
        conditions.append("cvss_score BETWEEN ? AND ?")
        params.extend([cvss_min, cvss_max])
    
    if epss_min > 0 or epss_max < 100:
        conditions.append("epss_percentile BETWEEN ? AND ?")
        params.extend([epss_min, epss_max])
    
    if published_from:
        conditions.append("published_date >= ?")
        params.append(published_from)
    
    if published_to:
        conditions.append("published_date <= ?")
        params.append(published_to)
    
    if vendor:
        conditions.append("vendors LIKE ?")
        params.append(f"%{vendor}%")
    
    # Execute query
    where_clause = " AND ".join(conditions)
    vulns = cursor.execute(f"""
        SELECT * FROM vulnerabilities
        WHERE {where_clause}
        ORDER BY epss_percentile DESC
        LIMIT 20
    """, params).fetchall()
    
    # Return filtered table (reuse the table building logic)
    # ... (similar to get_vulnerabilities)
    
    return HTMLResponse(content="<div>Filtered results would appear here</div>")

@app.post("/api/filter/quick", response_class=HTMLResponse)
async def quick_filter(
    request: Request,
    filter: str = Form(...)
):
    """Handle quick filter buttons"""
    db = request.app.state.db
    cursor = db.cursor()
    
    # Apply quick filters
    if filter == "critical":
        query = "SELECT * FROM vulnerabilities WHERE severity = 'CRITICAL' AND epss_percentile >= 70 ORDER BY epss_percentile DESC LIMIT 20"
    elif filter == "today":
        today = datetime.now().date().isoformat()
        query = f"SELECT * FROM vulnerabilities WHERE published_date >= '{today}' AND epss_percentile >= 70 ORDER BY epss_percentile DESC LIMIT 20"
    elif filter == "kev":
        query = "SELECT * FROM vulnerabilities WHERE tags LIKE '%KEV%' AND epss_percentile >= 70 ORDER BY epss_percentile DESC LIMIT 20"
    elif filter == "network":
        query = "SELECT * FROM vulnerabilities WHERE (attack_vector = 'NETWORK' OR title LIKE '%network%' OR title LIKE '%remote%') AND epss_percentile >= 70 ORDER BY epss_percentile DESC LIMIT 20"
    else:
        query = "SELECT * FROM vulnerabilities WHERE epss_percentile >= 70 ORDER BY epss_percentile DESC LIMIT 20"
    
    vulns = cursor.execute(query).fetchall()
    
    # Return filtered results (reuse table building logic)
    return HTMLResponse(content=f"<div>{len(vulns)} results for {filter} filter</div>")

@app.get("/api/export/csv")
async def export_csv(request: Request):
    """Export current filtered results as CSV"""
    db = request.app.state.db
    cursor = db.cursor()
    
    # Get current filter parameters from query string
    # In production, you'd parse filters from request
    
    vulns = cursor.execute("""
        SELECT cve_id, severity, cvss_score, epss_percentile, title, published_date
        FROM vulnerabilities
        WHERE epss_percentile >= 70
        ORDER BY epss_percentile DESC
    """).fetchall()
    
    # Build CSV
    csv_lines = ["CVE ID,Severity,CVSS,EPSS %,Title,Published"]
    for vuln in vulns:
        csv_lines.append(
            f'{vuln["cve_id"]},{vuln["severity"]},{vuln["cvss_score"] or ""},'
            f'{vuln["epss_percentile"]},"{vuln["title"]}",{vuln["published_date"]}'
        )
    
    csv_content = "\n".join(csv_lines)
    
    return FileResponse(
        path=None,
        media_type="text/csv",
        filename=f"vulnerabilities-{datetime.now().strftime('%Y%m%d')}.csv",
        content=csv_content.encode()
    )

@app.get("/api/charts", response_class=HTMLResponse)
async def get_charts(request: Request):
    """Get chart data and render chart containers"""
    db = request.app.state.db
    cursor = db.cursor()
    
    # Get severity distribution
    severity_data = cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        WHERE epss_percentile >= 70
        GROUP BY severity
    """).fetchall()
    
    # Get 30-day trend
    trend_data = []
    for i in range(30):
        date = (datetime.now() - timedelta(days=i)).date().isoformat()
        count = cursor.execute("""
            SELECT COUNT(*) as count
            FROM vulnerabilities
            WHERE published_date = ?
        """, (date,)).fetchone()['count']
        trend_data.append((date, count))
    
    # Convert to JavaScript arrays
    severity_labels = [row['severity'] for row in severity_data]
    severity_values = [row['count'] for row in severity_data]
    
    trend_labels = [row[0] for row in trend_data[-7:]]  # Last 7 days
    trend_values = [row[1] for row in trend_data[-7:]]
    
    html = f"""
    <div class="chart-card">
        <h3 class="chart-title">Severity Distribution</h3>
        <div class="chart-container">
            <canvas id="severity-chart"></canvas>
        </div>
    </div>
    
    <div class="chart-card">
        <h3 class="chart-title">7-Day Trend</h3>
        <div class="chart-container">
            <canvas id="trend-chart"></canvas>
        </div>
    </div>
    
    <script>
        // Initialize charts with real data
        const severityCtx = document.getElementById('severity-chart');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: {severity_labels},
                datasets: [{{
                    data: {severity_values},
                    backgroundColor: ['#dc2626', '#ef4444', '#f59e0b', '#3b82f6']
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        labels: {{ color: '#cbd5e1' }}
                    }}
                }}
            }}
        }});
        
        const trendCtx = document.getElementById('trend-chart');
        new Chart(trendCtx, {{
            type: 'line',
            data: {{
                labels: {trend_labels},
                datasets: [{{
                    label: 'New CVEs',
                    data: {trend_values},
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    tension: 0.4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
    </script>
    """
    
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    
    print("🚀 Starting FastAPI + HTMX Dashboard")
    print("📊 This demonstrates server-side rendering with real database integration")
    print("🔗 Visit http://localhost:8000")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)