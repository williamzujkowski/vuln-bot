"""Dashboard Agent - Generates the Alpine.js dashboard and API data."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

from scripts.agents.base_agent import BaseAgent
from scripts.processing.cache_manager import CacheManager


class DashboardAgent(BaseAgent):
    """Agent responsible for generating the vulnerability dashboard."""
    
    def __init__(self, cache_dir: Path = None):
        super().__init__("dashboard", cache_dir)
        self.cache_manager = None
        
        # Configuration
        self.config = {
            'output_dir': 'public',
            'api_dir': 'api/vulns',
            'max_vulnerabilities': 1000,
            'chunk_by_severity': True,
            'generate_search_index': True,
            'dashboard_template': 'src/index.njk'
        }
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute dashboard generation.
        
        Returns:
            Results from dashboard generation
        """
        # Initialize cache manager
        if not self.cache_manager:
            cache_db_path = self.cache_dir / "vulns.db"
            self.cache_manager = CacheManager(db_path=str(cache_db_path))
        
        config = {**self.config, **kwargs}
        
        results = {
            'started_at': datetime.now(timezone.utc).isoformat(),
            'config': config,
            'files_generated': [],
            'api_files': [],
            'success': True,
            'errors': [],
            'metrics': {}
        }
        
        try:
            # Get vulnerabilities from cache
            vulnerabilities = await asyncio.to_thread(
                self.cache_manager.get_recent_vulnerabilities,
                limit=config['max_vulnerabilities'],
                min_risk_score=70
            )
            
            self.logger.info(
                "Generating dashboard",
                vulnerability_count=len(vulnerabilities),
                max_vulnerabilities=config['max_vulnerabilities']
            )
            
            # Generate API data files
            api_files = await self._generate_api_files(vulnerabilities, config)
            results['api_files'] = api_files
            
            # Generate dashboard HTML
            dashboard_file = await self._generate_dashboard_html(vulnerabilities, config)
            results['files_generated'].append(dashboard_file)
            
            # Generate search index
            if config.get('generate_search_index'):
                search_index = await self._generate_search_index(vulnerabilities, config)
                results['files_generated'].append(search_index)
            
            # Calculate metrics
            from collections import Counter
            severity_dist = Counter(v.severity.value for v in vulnerabilities)
            
            results['metrics'] = {
                'vulnerabilities_processed': len(vulnerabilities),
                'severity_distribution': dict(severity_dist),
                'api_files_generated': len(api_files),
                'avg_risk_score': sum(v.risk_score for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0,
                'top_vendors': [vendor for vendor, _ in Counter(
                    vendor for v in vulnerabilities for vendor in v.affected_vendors[:3]
                ).most_common(10)]
            }
            
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            self.logger.info(
                "Dashboard generation completed",
                vulnerabilities_processed=len(vulnerabilities),
                files_generated=len(results['files_generated']) + len(results['api_files'])
            )
            
            return results
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            self.logger.error("Dashboard generation failed", error=str(e))
            raise
    
    async def _generate_api_files(self, vulnerabilities: List, config: Dict[str, Any]) -> List[str]:
        """Generate API data files for the dashboard.
        
        Args:
            vulnerabilities: List of vulnerability objects
            config: Generation configuration
            
        Returns:
            List of generated file paths
        """
        api_dir = Path(config['api_dir'])
        api_dir.mkdir(parents=True, exist_ok=True)
        
        generated_files = []
        
        if config.get('chunk_by_severity'):
            # Group by severity and year
            from collections import defaultdict
            chunks = defaultdict(list)
            
            for vuln in vulnerabilities:
                year = vuln.published_date.year
                severity = vuln.severity.value
                chunk_key = f"{year}-{severity}"
                chunks[chunk_key].append(vuln.to_summary_dict())
            
            # Generate chunk files
            chunk_index = {}
            for chunk_key, vulns in chunks.items():
                chunk_file = api_dir / f"vulns-{chunk_key}.json"
                
                chunk_data = {
                    'chunk_id': chunk_key,
                    'count': len(vulns),
                    'vulnerabilities': vulns,
                    'generated_at': datetime.now(timezone.utc).isoformat()
                }
                
                chunk_file.write_text(json.dumps(chunk_data, indent=2))
                generated_files.append(str(chunk_file))
                
                chunk_index[chunk_key] = {
                    'file': f"vulns-{chunk_key}.json",
                    'count': len(vulns),
                    'year': chunk_key.split('-')[0],
                    'severity': chunk_key.split('-')[1]
                }
            
            # Generate chunk index
            chunk_index_file = api_dir / "chunk-index.json"
            chunk_index_data = {
                'chunks': chunk_index,
                'total_chunks': len(chunk_index),
                'total_vulnerabilities': len(vulnerabilities),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
            
            chunk_index_file.write_text(json.dumps(chunk_index_data, indent=2))
            generated_files.append(str(chunk_index_file))
        
        else:
            # Single file approach
            api_file = api_dir / "vulnerabilities.json"
            
            api_data = {
                'vulnerabilities': [v.to_summary_dict() for v in vulnerabilities],
                'count': len(vulnerabilities),
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
            
            api_file.write_text(json.dumps(api_data, indent=2))
            generated_files.append(str(api_file))
        
        return generated_files
    
    async def _generate_dashboard_html(self, vulnerabilities: List, config: Dict[str, Any]) -> str:
        """Generate the main dashboard HTML file.
        
        Args:
            vulnerabilities: List of vulnerability objects
            config: Generation configuration
            
        Returns:
            Path to generated dashboard file
        """
        output_dir = Path(config['output_dir'])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        dashboard_file = output_dir / "index.html"
        
        # Prepare dashboard data
        dashboard_data = {
            'vulnerabilities': [v.to_summary_dict() for v in vulnerabilities],
            'metadata': {
                'total_count': len(vulnerabilities),
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'last_updated': max(v.last_modified_date for v in vulnerabilities).isoformat() if vulnerabilities else None,
                'data_source': 'cache'
            }
        }
        
        # Calculate statistics for dashboard
        from collections import Counter, defaultdict
        
        stats = {
            'severity_distribution': dict(Counter(v.severity.value for v in vulnerabilities)),
            'vendor_distribution': dict(Counter(
                vendor for v in vulnerabilities for vendor in v.affected_vendors[:3]
            ).most_common(20)),
            'exploitation_status': dict(Counter(v.exploitation_status.value for v in vulnerabilities)),
            'risk_score_ranges': {
                'critical': len([v for v in vulnerabilities if v.risk_score >= 90]),
                'high': len([v for v in vulnerabilities if 70 <= v.risk_score < 90]),
                'medium': len([v for v in vulnerabilities if 50 <= v.risk_score < 70]),
                'low': len([v for v in vulnerabilities if v.risk_score < 50])
            }
        }
        
        # Generate HTML with embedded data
        html_content = self._build_dashboard_html(dashboard_data, stats)
        
        dashboard_file.write_text(html_content)
        
        return str(dashboard_file)
    
    def _build_dashboard_html(self, dashboard_data: Dict[str, Any], stats: Dict[str, Any]) -> str:
        """Build the complete dashboard HTML.
        
        Args:
            dashboard_data: Dashboard data including vulnerabilities
            stats: Calculated statistics
            
        Returns:
            Complete HTML content
        """
        return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Intelligence Dashboard</title>
    <meta name="description" content="High-risk CVE intelligence platform tracking {dashboard_data['metadata']['total_count']} vulnerabilities">
    
    <!-- Alpine.js -->
    <script defer src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js"></script>
    
    <!-- Fuse.js for search -->
    <script src="https://cdn.jsdelivr.net/npm/fuse.js@7.0.0"></script>
    
    <style>
        /* Modern CSS Variables */
        :root {{
            --primary: #0369a1;
            --secondary: #64748b;
            --success: #059669;
            --warning: #d97706;
            --danger: #dc2626;
            --dark: #1e293b;
            --light: #f8fafc;
            --border: #e2e8f0;
        }}
        
        * {{ box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: var(--light);
            color: var(--dark);
            line-height: 1.6;
        }}
        
        .header {{
            background: white;
            border-bottom: 1px solid var(--border);
            padding: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            margin: 0;
            color: var(--primary);
            font-size: 1.8rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 1rem;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary);
        }}
        
        .controls {{
            background: white;
            padding: 1rem;
            margin: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        
        .search-box {{
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: 6px;
            font-size: 1rem;
        }}
        
        .filters {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .filter-group select {{
            width: 100%;
            padding: 0.5rem;
            border: 1px solid var(--border);
            border-radius: 4px;
        }}
        
        .vulnerability-table {{
            background: white;
            margin: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            overflow: hidden;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        th, td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        th {{
            background: var(--light);
            font-weight: 600;
            cursor: pointer;
        }}
        
        th:hover {{
            background: #e2e8f0;
        }}
        
        .severity-critical {{ color: var(--danger); font-weight: bold; }}
        .severity-high {{ color: #ea580c; font-weight: bold; }}
        .severity-medium {{ color: var(--warning); }}
        .severity-low {{ color: var(--secondary); }}
        
        .risk-score {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-weight: bold;
            color: white;
        }}
        
        .risk-critical {{ background: var(--danger); }}
        .risk-high {{ background: #ea580c; }}
        .risk-medium {{ background: var(--warning); }}
        .risk-low {{ background: var(--secondary); }}
        
        .pagination {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 1rem;
            margin: 1rem;
        }}
        
        .pagination button {{
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            background: white;
            cursor: pointer;
            border-radius: 4px;
        }}
        
        .pagination button:hover {{ background: var(--light); }}
        .pagination button:disabled {{ opacity: 0.5; cursor: not-allowed; }}
        
        @media (max-width: 768px) {{
            .stats {{ grid-template-columns: 1fr 1fr; }}
            .filters {{ grid-template-columns: 1fr; }}
            table {{ font-size: 0.9rem; }}
            th, td {{ padding: 0.5rem; }}
        }}
    </style>
</head>
<body>
    <div x-data="vulnerabilityDashboard()" x-init="init()">
        <!-- Header -->
        <header class="header">
            <h1>🛡️ Vulnerability Intelligence Dashboard</h1>
            <p>Tracking <span x-text="totalVulnerabilities"></span> high-risk vulnerabilities 
               | Last updated: <span x-text="formatDate(metadata.generated_at)"></span></p>
        </header>
        
        <!-- Statistics -->
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" x-text="stats.severity_distribution.CRITICAL || 0"></div>
                <div>Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" x-text="stats.severity_distribution.HIGH || 0"></div>
                <div>High</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" x-text="stats.risk_score_ranges.critical || 0"></div>
                <div>Risk Score ≥90</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" x-text="Object.keys(stats.vendor_distribution).length"></div>
                <div>Affected Vendors</div>
            </div>
        </div>
        
        <!-- Search and Filters -->
        <div class="controls">
            <input type="text" 
                   class="search-box" 
                   placeholder="Search CVEs, vendors, products..." 
                   x-model="searchQuery"
                   @input.debounce.300ms="performSearch()">
            
            <div class="filters">
                <div class="filter-group">
                    <label>Severity</label>
                    <select x-model="filters.severity" @change="applyFilters()">
                        <option value="">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label>Risk Score</label>
                    <select x-model="filters.riskScore" @change="applyFilters()">
                        <option value="">All Risk Scores</option>
                        <option value="90">≥ 90 (Critical)</option>
                        <option value="70">≥ 70 (High)</option>
                        <option value="50">≥ 50 (Medium)</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label>Sort By</label>
                    <select x-model="sortBy" @change="applySorting()">
                        <option value="riskScore">Risk Score</option>
                        <option value="cvssScore">CVSS Score</option>
                        <option value="publishedDate">Published Date</option>
                        <option value="cveId">CVE ID</option>
                    </select>
                </div>
                
                <div class="filter-group">
                    <label>Per Page</label>
                    <select x-model="perPage" @change="changePerPage()">
                        <option value="25">25</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                </div>
            </div>
        </div>
        
        <!-- Vulnerabilities Table -->
        <div class="vulnerability-table">
            <table>
                <thead>
                    <tr>
                        <th @click="sortBy('cveId')">CVE ID</th>
                        <th @click="sortBy('title')">Title</th>
                        <th @click="sortBy('severity')">Severity</th>
                        <th @click="sortBy('cvssScore')">CVSS</th>
                        <th @click="sortBy('epssScore')">EPSS %</th>
                        <th @click="sortBy('riskScore')">Risk Score</th>
                        <th @click="sortBy('publishedDate')">Published</th>
                    </tr>
                </thead>
                <tbody>
                    <template x-for="vuln in paginatedResults" :key="vuln.cveId">
                        <tr>
                            <td>
                                <a :href="'/cves/' + vuln.cveId + '.html'" 
                                   x-text="vuln.cveId" 
                                   class="cve-link"></a>
                            </td>
                            <td x-text="vuln.title.length > 60 ? vuln.title.substring(0, 60) + '...' : vuln.title"></td>
                            <td>
                                <span :class="'severity-' + vuln.severity.toLowerCase()" 
                                      x-text="vuln.severity"></span>
                            </td>
                            <td x-text="vuln.cvssScore || 'N/A'"></td>
                            <td x-text="vuln.epssScore || 'N/A'"></td>
                            <td>
                                <span :class="getRiskScoreClass(vuln.riskScore)" 
                                      class="risk-score" 
                                      x-text="vuln.riskScore"></span>
                            </td>
                            <td x-text="formatDate(vuln.publishedDate)"></td>
                        </tr>
                    </template>
                </tbody>
            </table>
        </div>
        
        <!-- Pagination -->
        <div class="pagination">
            <button @click="previousPage()" :disabled="currentPage === 1">Previous</button>
            <span>Page <span x-text="currentPage"></span> of <span x-text="totalPages"></span></span>
            <button @click="nextPage()" :disabled="currentPage === totalPages">Next</button>
        </div>
    </div>
    
    <script>
        function vulnerabilityDashboard() {{
            return {{
                // Data
                allVulnerabilities: {json.dumps(dashboard_data['vulnerabilities'])},
                filteredResults: [],
                paginatedResults: [],
                metadata: {json.dumps(dashboard_data['metadata'])},
                stats: {json.dumps(stats)},
                
                // State
                searchQuery: '',
                filters: {{
                    severity: '',
                    riskScore: ''
                }},
                sortBy: 'riskScore',
                sortDirection: 'desc',
                currentPage: 1,
                perPage: 50,
                totalVulnerabilities: {dashboard_data['metadata']['total_count']},
                
                // Search
                fuse: null,
                
                init() {{
                    this.filteredResults = [...this.allVulnerabilities];
                    this.applySorting();
                    this.updatePagination();
                    
                    // Initialize Fuse.js for search
                    this.fuse = new Fuse(this.allVulnerabilities, {{
                        keys: ['cveId', 'title', 'vendors', 'products'],
                        threshold: 0.3
                    }});
                }},
                
                performSearch() {{
                    if (!this.searchQuery.trim()) {{
                        this.filteredResults = [...this.allVulnerabilities];
                    }} else {{
                        const results = this.fuse.search(this.searchQuery);
                        this.filteredResults = results.map(result => result.item);
                    }}
                    this.applyFilters();
                }},
                
                applyFilters() {{
                    let results = this.searchQuery.trim() ? this.filteredResults : [...this.allVulnerabilities];
                    
                    if (this.filters.severity) {{
                        results = results.filter(v => v.severity === this.filters.severity);
                    }}
                    
                    if (this.filters.riskScore) {{
                        const minScore = parseInt(this.filters.riskScore);
                        results = results.filter(v => v.riskScore >= minScore);
                    }}
                    
                    this.filteredResults = results;
                    this.currentPage = 1;
                    this.applySorting();
                }},
                
                applySorting() {{
                    this.filteredResults.sort((a, b) => {{
                        let aVal = a[this.sortBy];
                        let bVal = b[this.sortBy];
                        
                        // Handle dates
                        if (this.sortBy === 'publishedDate') {{
                            aVal = new Date(aVal);
                            bVal = new Date(bVal);
                        }}
                        
                        // Handle null values
                        if (aVal === null || aVal === undefined) aVal = 0;
                        if (bVal === null || bVal === undefined) bVal = 0;
                        
                        if (this.sortDirection === 'asc') {{
                            return aVal > bVal ? 1 : -1;
                        }} else {{
                            return aVal < bVal ? 1 : -1;
                        }}
                    }});
                    
                    this.updatePagination();
                }},
                
                updatePagination() {{
                    const start = (this.currentPage - 1) * this.perPage;
                    const end = start + this.perPage;
                    this.paginatedResults = this.filteredResults.slice(start, end);
                }},
                
                get totalPages() {{
                    return Math.ceil(this.filteredResults.length / this.perPage);
                }},
                
                nextPage() {{
                    if (this.currentPage < this.totalPages) {{
                        this.currentPage++;
                        this.updatePagination();
                    }}
                }},
                
                previousPage() {{
                    if (this.currentPage > 1) {{
                        this.currentPage--;
                        this.updatePagination();
                    }}
                }},
                
                changePerPage() {{
                    this.currentPage = 1;
                    this.updatePagination();
                }},
                
                formatDate(dateStr) {{
                    return new Date(dateStr).toLocaleDateString();
                }},
                
                getRiskScoreClass(score) {{
                    if (score >= 90) return 'risk-critical';
                    if (score >= 70) return 'risk-high';
                    if (score >= 50) return 'risk-medium';
                    return 'risk-low';
                }}
            }}
        }}
    </script>
</body>
</html>'''
    
    async def _generate_search_index(self, vulnerabilities: List, config: Dict[str, Any]) -> str:
        """Generate search index for client-side search.
        
        Args:
            vulnerabilities: List of vulnerability objects
            config: Generation configuration
            
        Returns:
            Path to generated search index file
        """
        api_dir = Path(config['api_dir'])
        search_index_file = api_dir / "search-index.json"
        
        # Build lightweight search index
        search_data = []
        for vuln in vulnerabilities:
            search_data.append({
                'id': vuln.cve_id,
                'title': vuln._create_enhanced_title(),
                'description': vuln.description[:200],
                'severity': vuln.severity.value,
                'vendors': vuln.affected_vendors[:5],
                'products': vuln.affected_products[:5],
                'tags': vuln.tags[:10],
                'risk_score': vuln.risk_score,
                'cvss_score': vuln.cvss_base_score,
                'epss_score': vuln.epss_probability,
                'published': vuln.published_date.isoformat()
            })
        
        search_index = {
            'data': search_data,
            'count': len(search_data),
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        search_index_file.write_text(json.dumps(search_index, indent=2))
        
        return str(search_index_file)
    
    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        return {
            '.cache/vulns.db',
            'src/index.njk',
            'src/_includes/',
            'src/assets/',
            'scripts/processing/cache_manager.py'
        }