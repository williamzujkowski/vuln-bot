#!/usr/bin/env python3
"""
Complete Tailwind CSS-based dashboard generator with system dark/light mode
Replaces generate_alpine_dashboard.py with modern utility-first CSS approach
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Configuration
OUTPUT_DIR = Path("public")
API_DIR = Path("api/vulns")
OUTPUT_DIR.mkdir(exist_ok=True)

def load_vulnerabilities():
    """Load vulnerabilities from JSON API"""
    index_file = API_DIR / "index.json"

    if not index_file.exists():
        print(f"Error: {index_file} not found")
        sys.exit(1)

    with open(index_file) as f:
        data = json.load(f)

    return data.get("vulnerabilities", []), data.get("generated", "")

def generate_dashboard():
    """Generate complete Tailwind CSS dashboard"""

    print("Loading vulnerabilities...")
    vulnerabilities, data_generated = load_vulnerabilities()
    
    # Prepare vulnerability data for JavaScript embedding
    vuln_data = []
    for v in vulnerabilities:
        # Get full description (not truncated for modal)
        full_desc = v.get("title", v.get("originalTitle", "No description available"))

        vuln_data.append({
            # Basic identification
            "cve_id": v.get("cveId", ""),
            "title": v.get("title", ""),
            "description": full_desc,

            # Severity and scores
            "severity": v.get("severity", ""),
            "cvss_score": v.get("cvssScore", 0),
            "epss_score": v.get("epssScore", 0),
            "epss_percentile": v.get("epssPercentile", 0),
            "risk_score": v.get("riskScore", 0),

            # Products and vendors
            "products": v.get("products", []),
            "products_display": ", ".join(v.get("products", []))[:100],  # Truncated for table
            "vendors": v.get("vendors", []),
            "vendors_display": ", ".join(v.get("vendors", []))[:100],  # Truncated for table

            # Dates
            "published": str(v.get("publishedDate", ""))[:10],
            "last_modified": str(v.get("lastModifiedDate", ""))[:10],

            # Exploitation status
            "kev": v.get("exploitationStatus") == "KNOWN_EXPLOITED",
            "exploitation_status": v.get("exploitationStatus", "UNKNOWN"),

            # CVSS metrics
            "attack_vector": v.get("attackVector", ""),
            "attack_complexity": v.get("attackComplexity", ""),
            "privileges_required": v.get("privilegesRequired", ""),
            "user_interaction": v.get("userInteraction", ""),

            # SSVC data
            "ssvc": v.get("ssvc", {}),

            # Enrichments
            "enrichments": v.get("enrichments", {}),

            # References
            "references": v.get("references", []),

            # Tags
            "tags": v.get("tags", []),
        })
    
    # Calculate statistics
    total_vulns = len(vuln_data)
    critical_count = sum(1 for v in vuln_data if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in vuln_data if v["severity"] == "HIGH")
    kev_count = sum(1 for v in vuln_data if v["kev"])

    # SERVER-SIDE CHART CALCULATIONS (to avoid client-side caching issues)

    # 1. Calculate Top 10 Vendors
    vendor_counts = {}
    for v in vuln_data:
        for vendor in v.get("vendors", []):
            if vendor:
                vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

    # Get top 10 vendors sorted by count
    top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    vendor_labels = [vendor for vendor, count in top_vendors]
    vendor_data = [count for vendor, count in top_vendors]

    # 2. Calculate EPSS Distribution
    epss_buckets = {
        '60-70%': 0,
        '70-80%': 0,
        '80-90%': 0,
        '90-95%': 0,
        '95-100%': 0
    }

    for v in vuln_data:
        epss = v.get("epss_score", 0)
        if epss >= 95:
            epss_buckets['95-100%'] += 1
        elif epss >= 90:
            epss_buckets['90-95%'] += 1
        elif epss >= 80:
            epss_buckets['80-90%'] += 1
        elif epss >= 70:
            epss_buckets['70-80%'] += 1
        elif epss >= 60:
            epss_buckets['60-70%'] += 1

    epss_labels = list(epss_buckets.keys())
    epss_data = list(epss_buckets.values())

    # Build timestamp
    build_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")

    # Parse and format data timestamp
    if data_generated:
        try:
            # Parse ISO format timestamp: "2025-10-22T01:18:11.284010"
            data_dt = datetime.fromisoformat(data_generated.replace('+00:00', ''))
            data_last_updated = data_dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception as e:
            print(f"Warning: Could not parse data timestamp: {e}")
            data_last_updated = "Unknown"
    else:
        data_last_updated = "Unknown"
    
    # Convert to JSON for embedding
    vuln_json = json.dumps(vuln_data)
    
    # Generate HTML with embedded data
    html_content = f'''<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="High-risk CVE intelligence dashboard - EPSS ≥60% exploitation probability">
    <meta name="author" content="Vuln-Bot">
    <title>Vulnerability Intelligence Dashboard | Vuln-Bot</title>
    
    <!-- Tailwind CSS via CDN (v3.4 for stability) -->
    <script src="https://cdn.tailwindcss.com?plugins=forms,typography,aspect-ratio"></script>
    
    <!-- Alpine.js for interactivity -->
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>

    <!-- Chart.js for data visualizations -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

    <!-- Tailwind Configuration -->
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    colors: {{
                        primary: {{
                            50: '#ecfeff',
                            100: '#cffafe',
                            200: '#a5f3fc',
                            300: '#67e8f9',
                            400: '#22d3ee',
                            500: '#06b6d4',
                            600: '#0891b2',
                            700: '#0e7490',
                            800: '#155e75',
                            900: '#164e63',
                            950: '#083344',
                        }}
                    }}
                }}
            }}
        }}
    </script>
    
    <style type="text/tailwindcss">
        @layer utilities {{
            .scrollbar-thin::-webkit-scrollbar {{
                width: 8px;
                height: 8px;
            }}
            .scrollbar-thin::-webkit-scrollbar-track {{
                @apply bg-gray-100 dark:bg-gray-900;
            }}
            .scrollbar-thin::-webkit-scrollbar-thumb {{
                @apply bg-gray-300 dark:bg-gray-700 rounded hover:bg-gray-400 dark:hover:bg-gray-600;
            }}
        }}
        
        [x-cloak] {{ display: none !important; }}
    </style>
</head>

<body class="h-full bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 transition-colors duration-200" 
      x-data="vulnDashboard()" 
      x-init="initDashboard()"
      x-cloak>
    
    <!-- Skip to main content link for accessibility -->
    <a href="#main-content" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary-600 focus:text-white focus:rounded-lg">
        Skip to main content
    </a>
    
    <!-- Header -->
    <header class="sticky top-0 z-40 w-full bg-white/95 dark:bg-gray-900/95 backdrop-blur supports-[backdrop-filter]:bg-white/80 dark:supports-[backdrop-filter]:bg-gray-900/80 border-b border-gray-200 dark:border-gray-800 shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <!-- Main header row -->
            <div class="flex items-center justify-between h-16">
                <!-- Brand -->
                <div class="flex items-center space-x-3">
                    <div class="flex items-center justify-center w-10 h-10 bg-gradient-to-br from-primary-500 to-purple-600 rounded-xl shadow-lg">
                        <span class="text-xl" role="img" aria-label="Shield">🛡️</span>
                    </div>
                    <div class="flex flex-col">
                        <h1 class="text-lg sm:text-xl font-bold bg-gradient-to-r from-primary-600 to-purple-600 dark:from-primary-400 dark:to-purple-400 bg-clip-text text-transparent">
                            Vuln-Bot
                        </h1>
                        <p class="text-xs text-gray-600 dark:text-gray-400">CVE Intelligence Dashboard</p>
                    </div>
                </div>
                
                <!-- Actions -->
                <nav class="flex items-center space-x-2" aria-label="Primary navigation">
                    <!-- Methodology link -->
                    <a href="./methodology.html"
                       class="hidden sm:flex items-center space-x-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors text-sm font-medium focus:outline-none focus:ring-2 focus:ring-primary-500">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span>Methodology</span>
                    </a>

                    <!-- Dark mode toggle -->
                    <button @click="toggleDarkMode()"
                            type="button"
                            class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500"
                            aria-label="Toggle dark mode">
                        <svg x-show="!darkMode" class="w-5 h-5 text-gray-700 dark:text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                        </svg>
                        <svg x-show="darkMode" class="w-5 h-5 text-gray-700 dark:text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
                        </svg>
                    </button>
                    
                    <!-- GitHub link -->
                    <a href="https://github.com/williamzujkowski/vuln-bot" 
                       target="_blank" 
                       rel="noopener noreferrer"
                       class="hidden sm:flex items-center space-x-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors text-sm font-medium focus:outline-none focus:ring-2 focus:ring-primary-500">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true">
                            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                        </svg>
                        <span>GitHub</span>
                    </a>
                    
                    <!-- Export CSV -->
                    <button @click="exportCSV()" 
                            type="button"
                            class="flex items-center space-x-2 px-3 py-2 rounded-lg bg-primary-600 hover:bg-primary-700 text-white transition-colors text-sm font-medium shadow-sm hover:shadow focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                        <span class="hidden sm:inline">Export CSV</span>
                        <span class="sm:hidden">CSV</span>
                    </button>
                </nav>
            </div>
            
            <!-- Status badges row -->
            <div class="flex flex-wrap items-center gap-2 pb-3 text-xs font-medium">
                <div class="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800/50">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span>Built:</span>
                    <time datetime="{build_time}" class="font-mono">{build_time}</time>
                </div>
                <div class="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-lg bg-sky-50 dark:bg-sky-900/20 text-sky-700 dark:text-sky-400 border border-sky-200 dark:border-sky-800/50">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    <span>Data last updated:</span>
                    <time datetime="{data_generated}" class="font-mono">{data_last_updated}</time>
                </div>
            </div>
        </div>
    </header>

    <!-- Main content -->
    <main id="main-content" class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        
        <!-- Statistics Grid -->
        <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-6 sm:mb-8" aria-label="Vulnerability statistics">
            <!-- Total CVEs Card -->
            <article class="group relative overflow-hidden bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-lg transition-all duration-200 hover:-translate-y-1">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <p class="text-sm font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide">Total CVEs</p>
                        <p class="text-4xl font-bold mt-2 bg-gradient-to-r from-primary-600 to-purple-600 dark:from-primary-400 dark:to-purple-400 bg-clip-text text-transparent">
                            {total_vulns}
                        </p>
                    </div>
                    <div class="p-3 bg-gradient-to-br from-primary-100 to-purple-100 dark:from-primary-900/30 dark:to-purple-900/30 rounded-xl">
                        <svg class="w-7 h-7 text-primary-600 dark:text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                        </svg>
                    </div>
                </div>
                <div class="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-primary-500 to-purple-500 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-200"></div>
            </article>
            
            <!-- Critical Severity Card -->
            <article class="group relative overflow-hidden bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-lg transition-all duration-200 hover:-translate-y-1">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <p class="text-sm font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide">Critical</p>
                        <p class="text-4xl font-bold mt-2 text-red-600 dark:text-red-400">{critical_count}</p>
                    </div>
                    <div class="p-3 bg-red-100 dark:bg-red-900/30 rounded-xl">
                        <svg class="w-7 h-7 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                    </div>
                </div>
                <div class="absolute bottom-0 left-0 right-0 h-1 bg-red-500 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-200"></div>
            </article>
            
            <!-- High Severity Card -->
            <article class="group relative overflow-hidden bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-lg transition-all duration-200 hover:-translate-y-1">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <p class="text-sm font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide">High</p>
                        <p class="text-4xl font-bold mt-2 text-orange-600 dark:text-orange-400">{high_count}</p>
                    </div>
                    <div class="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-xl">
                        <svg class="w-7 h-7 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                        </svg>
                    </div>
                </div>
                <div class="absolute bottom-0 left-0 right-0 h-1 bg-orange-500 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-200"></div>
            </article>
            
            <!-- KEV Listed Card -->
            <article class="group relative overflow-hidden bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-lg transition-all duration-200 hover:-translate-y-1">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <p class="text-sm font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wide">KEV Listed</p>
                        <p class="text-4xl font-bold mt-2 text-purple-600 dark:text-purple-400">{kev_count}</p>
                    </div>
                    <div class="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-xl">
                        <svg class="w-7 h-7 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/>
                        </svg>
                    </div>
                </div>
                <div class="absolute bottom-0 left-0 right-0 h-1 bg-purple-500 transform scale-x-0 group-hover:scale-x-100 transition-transform duration-200"></div>
            </article>
        </section>

        <!-- Data Visualizations -->
        <section class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6 sm:mb-8" aria-label="Data visualizations">
            <!-- Severity Distribution Chart -->
            <article class="bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Distribution</h3>
                <div class="relative h-64">
                    <canvas id="severityChart" aria-label="Severity distribution pie chart"></canvas>
                </div>
            </article>

            <!-- EPSS Score Distribution Chart -->
            <article class="bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">EPSS Score Distribution</h3>
                <div class="relative h-64">
                    <canvas id="epssChart" aria-label="EPSS score distribution bar chart"></canvas>
                </div>
            </article>

            <!-- Top Vendors Chart -->
            <article class="bg-white dark:bg-gray-900 rounded-2xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm">
                <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top 10 Vendors</h3>
                <div class="relative h-64">
                    <canvas id="vendorsChart" aria-label="Top vendors by vulnerability count bar chart"></canvas>
                </div>
            </article>
        </section>

        <!-- Search and Filters -->
        <section class="bg-white dark:bg-gray-900 rounded-2xl p-4 sm:p-6 border border-gray-200 dark:border-gray-800 shadow-sm mb-6" aria-label="Search and filters">
            <!-- Search input -->
            <div class="mb-4">
                <label for="search" class="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Search CVEs</label>
                <div class="relative">
                    <div class="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <svg class="h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                    </div>
                    <input type="search" 
                           id="search"
                           x-model="searchQuery" 
                           placeholder="Search CVE ID, product, or vendor..."
                           class="block w-full pl-10 pr-3 py-3 border border-gray-300 dark:border-gray-700 rounded-xl bg-gray-50 dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-colors">
                </div>
            </div>
            
            <!-- Quick filters -->
            <div class="flex flex-wrap gap-2">
                <button @click="filterBySeverity('CRITICAL')" 
                        type="button"
                        :class="selectedSeverity === 'CRITICAL' ? 'bg-red-600 text-white border-red-600' : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-700'"
                        class="px-4 py-2 rounded-lg border font-medium text-sm transition-colors hover:shadow-md focus:outline-none focus:ring-2 focus:ring-red-500">
                    Critical
                </button>
                <button @click="filterBySeverity('HIGH')" 
                        type="button"
                        :class="selectedSeverity === 'HIGH' ? 'bg-orange-600 text-white border-orange-600' : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-700'"
                        class="px-4 py-2 rounded-lg border font-medium text-sm transition-colors hover:shadow-md focus:outline-none focus:ring-2 focus:ring-orange-500">
                    High
                </button>
                <button @click="filterByKEV()" 
                        type="button"
                        :class="showKEVOnly ? 'bg-purple-600 text-white border-purple-600' : 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-700'"
                        class="px-4 py-2 rounded-lg border font-medium text-sm transition-colors hover:shadow-md focus:outline-none focus:ring-2 focus:ring-purple-500">
                    ⭐ KEV Only
                </button>
                <button @click="resetFilters()" 
                        type="button"
                        class="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 font-medium text-sm hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors focus:outline-none focus:ring-2 focus:ring-gray-500">
                    Reset
                </button>
            </div>
            
            <!-- Results count -->
            <div class="mt-4 text-sm text-gray-600 dark:text-gray-400">
                Showing <span class="font-semibold text-gray-900 dark:text-white" x-text="filteredVulns.length"></span> of <span class="font-semibold text-gray-900 dark:text-white">{total_vulns}</span> vulnerabilities
            </div>
        </section>

        <!-- Vulnerabilities Table -->
        <section class="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden">
            <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800">
                <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Vulnerabilities</h2>
            </div>
            
            <!-- Desktop/Tablet Table View (hidden on mobile) -->
            <div class="hidden md:block overflow-x-auto scrollbar-thin">
                <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-800">
                    <thead class="bg-gray-50 dark:bg-gray-800/50">
                        <tr>
                            <th scope="col" @click="sortBy('cve_id')" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors select-none">
                                <div class="flex items-center gap-2">
                                    <span>CVE ID</span>
                                    <span class="text-sm" x-text="getSortIcon('cve_id')"></span>
                                </div>
                            </th>
                            <th scope="col" @click="sortBy('severity')" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors select-none">
                                <div class="flex items-center gap-2">
                                    <span>Severity</span>
                                    <span class="text-sm" x-text="getSortIcon('severity')"></span>
                                </div>
                            </th>
                            <th scope="col" @click="sortBy('cvss_score')" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors select-none">
                                <div class="flex items-center gap-2">
                                    <span>CVSS</span>
                                    <span class="text-sm" x-text="getSortIcon('cvss_score')"></span>
                                </div>
                            </th>
                            <th scope="col" @click="sortBy('epss_percentile')" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors select-none">
                                <div class="flex items-center gap-2">
                                    <span>EPSS %</span>
                                    <span class="text-sm" x-text="getSortIcon('epss_percentile')"></span>
                                </div>
                            </th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Product</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Vendors</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider">Exploit Status</th>
                            <th scope="col" @click="sortBy('published')" class="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors select-none">
                                <div class="flex items-center gap-2">
                                    <span>Published</span>
                                    <span class="text-sm" x-text="getSortIcon('published')"></span>
                                </div>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white dark:bg-gray-900 divide-y divide-gray-200 dark:divide-gray-800">
                        <template x-for="vuln in paginatedVulns" :key="vuln.cve_id">
                            <tr @click="openModal(vuln)" class="hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors cursor-pointer">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a :href="'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + vuln.cve_id" 
                                       target="_blank"
                                       rel="noopener noreferrer"
                                       class="text-sm font-mono font-medium text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 hover:underline focus:outline-none focus:ring-2 focus:ring-primary-500 rounded"
                                       x-text="vuln.cve_id"></a>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span x-text="vuln.severity"
                                          :class="vuln.severity === 'CRITICAL' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800' : 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 border border-orange-200 dark:border-orange-800'"
                                          class="px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wide"></span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-semibold text-gray-900 dark:text-gray-100" x-text="vuln.cvss_score.toFixed(1)"></td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100" x-text="vuln.epss_percentile.toFixed(1) + '%'"></td>
                                <td class="px-6 py-4 text-sm text-gray-700 dark:text-gray-300 max-w-xs truncate" x-text="vuln.products_display"></td>
                                <td class="px-6 py-4 text-sm text-gray-700 dark:text-gray-300 max-w-xs truncate" x-text="vuln.vendors_display"></td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span x-show="vuln.kev" class="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-bold bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-800">
                                        ⭐ KEV
                                    </span>
                                    <span x-show="!vuln.kev" class="text-sm text-gray-500 dark:text-gray-400">—</span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-600 dark:text-gray-400" x-text="vuln.published"></td>
                            </tr>
                        </template>
                    </tbody>
                </table>
            </div>

            <!-- Mobile Card View (visible only on mobile) -->
            <div class="md:hidden px-4 py-4 space-y-4">
                <template x-for="vuln in paginatedVulns" :key="vuln.cve_id">
                    <div @click="openModal(vuln)" class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition-shadow cursor-pointer">
                        <!-- Header with CVE ID and Severity -->
                        <div class="flex items-start justify-between mb-3">
                            <div class="flex-1">
                                <a :href="'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + vuln.cve_id"
                                   target="_blank"
                                   rel="noopener noreferrer"
                                   @click.stop
                                   class="text-base font-mono font-bold text-primary-600 dark:text-primary-400 hover:underline"
                                   x-text="vuln.cve_id"></a>
                            </div>
                            <span x-text="vuln.severity"
                                  :class="vuln.severity === 'CRITICAL' ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-800' : 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 border border-orange-200 dark:border-orange-800'"
                                  class="ml-3 px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wide whitespace-nowrap"></span>
                        </div>

                        <!-- Scores Grid -->
                        <div class="grid grid-cols-2 gap-3 mb-3">
                            <div class="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-2">
                                <div class="text-xs text-gray-600 dark:text-gray-400 mb-1">CVSS Score</div>
                                <div class="text-lg font-bold text-gray-900 dark:text-gray-100" x-text="vuln.cvss_score.toFixed(1)"></div>
                            </div>
                            <div class="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-2">
                                <div class="text-xs text-gray-600 dark:text-gray-400 mb-1">EPSS %</div>
                                <div class="text-lg font-bold text-gray-900 dark:text-gray-100" x-text="vuln.epss_percentile.toFixed(1) + '%'"></div>
                            </div>
                        </div>

                        <!-- Product & Vendors -->
                        <div class="space-y-2 mb-3">
                            <div>
                                <div class="text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Product</div>
                                <div class="text-sm text-gray-700 dark:text-gray-300 truncate" x-text="vuln.products_display"></div>
                            </div>
                            <div>
                                <div class="text-xs font-semibold text-gray-600 dark:text-gray-400 mb-1">Vendors</div>
                                <div class="text-sm text-gray-700 dark:text-gray-300 truncate" x-text="vuln.vendors_display"></div>
                            </div>
                        </div>

                        <!-- Footer with KEV status and Published date -->
                        <div class="flex items-center justify-between pt-3 border-t border-gray-200 dark:border-gray-700">
                            <div class="flex items-center">
                                <span x-show="vuln.kev" class="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-bold bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-400 border border-purple-200 dark:border-purple-800">
                                    ⭐ KEV
                                </span>
                                <span x-show="!vuln.kev" class="text-sm text-gray-500 dark:text-gray-400">—</span>
                            </div>
                            <div class="text-xs font-mono text-gray-600 dark:text-gray-400">
                                Published: <span x-text="vuln.published"></span>
                            </div>
                        </div>
                    </div>
                </template>
            </div>

            <!-- Pagination -->
            <div class="px-4 sm:px-6 py-4 flex items-center justify-between border-t border-gray-200 dark:border-gray-800">
                <div class="flex-1 flex items-center justify-between sm:justify-start space-x-4">
                    <div class="text-sm text-gray-700 dark:text-gray-300">
                        Page <span class="font-semibold" x-text="currentPage"></span> of <span class="font-semibold" x-text="totalPages"></span>
                    </div>
                    <div class="flex space-x-2">
                        <button @click="prevPage()" 
                                :disabled="currentPage === 1"
                                :class="currentPage === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-200 dark:hover:bg-gray-700'"
                                class="px-4 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-sm font-medium text-gray-700 dark:text-gray-300 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500">
                            Previous
                        </button>
                        <button @click="nextPage()" 
                                :disabled="currentPage === totalPages"
                                :class="currentPage === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-200 dark:hover:bg-gray-700'"
                                class="px-4 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-sm font-medium text-gray-700 dark:text-gray-300 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500">
                            Next
                        </button>
                    </div>
                </div>
            </div>
        </section>
    </main>
    
    <!-- Footer -->
    <footer class="mt-12 py-6 border-t border-gray-200 dark:border-gray-800">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <p class="text-center text-sm text-gray-600 dark:text-gray-400">
                Built with <a href="https://alpinejs.dev" target="_blank" rel="noopener noreferrer" class="text-primary-600 dark:text-primary-400 hover:underline">Alpine.js</a>
                & <a href="https://tailwindcss.com" target="_blank" rel="noopener noreferrer" class="text-primary-600 dark:text-primary-400 hover:underline">Tailwind CSS</a>
                • Data updated automatically via GitHub Actions
            </p>
        </div>
    </footer>

    <!-- CVE Detail Modal -->
    <div x-show="modalOpen"
         x-cloak
         @keydown.escape.window="closeModal()"
         class="fixed inset-0 z-50 overflow-y-auto"
         aria-labelledby="modal-title"
         role="dialog"
         aria-modal="true">

        <!-- Backdrop -->
        <div x-show="modalOpen"
             x-transition:enter="transition ease-out duration-300"
             x-transition:enter-start="opacity-0"
             x-transition:enter-end="opacity-100"
             x-transition:leave="transition ease-in duration-200"
             x-transition:leave-start="opacity-100"
             x-transition:leave-end="opacity-0"
             class="fixed inset-0 bg-gray-900/75 dark:bg-gray-950/90 backdrop-blur-sm transition-opacity"
             @click="closeModal()">
        </div>

        <!-- Modal Panel -->
        <div class="flex min-h-full items-center justify-center p-4">
            <div x-show="modalOpen"
                 x-transition:enter="transition ease-out duration-300"
                 x-transition:enter-start="opacity-0 scale-95"
                 x-transition:enter-end="opacity-100 scale-100"
                 x-transition:leave="transition ease-in duration-200"
                 x-transition:leave-start="opacity-100 scale-100"
                 x-transition:leave-end="opacity-0 scale-95"
                 @click.stop
                 class="relative w-full max-w-5xl bg-white dark:bg-gray-900 rounded-xl shadow-2xl overflow-hidden">

                <template x-if="selectedVuln">
                    <div class="flex flex-col max-h-[90vh]">
                        <!-- Modal Header -->
                        <div class="sticky top-0 z-10 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 px-6 py-4">
                            <div class="flex items-start justify-between">
                                <div class="flex-1">
                                    <h2 id="modal-title" class="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2" x-text="selectedVuln.cve_id"></h2>
                                    <div class="flex items-center gap-3 flex-wrap">
                                        <span :class="{{'
                                            'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400': selectedVuln.severity === 'CRITICAL',
                                            'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400': selectedVuln.severity === 'HIGH'
                                        }}" class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold" x-text="selectedVuln.severity"></span>

                                        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400">
                                            <span>CVSS:</span>
                                            <span class="font-bold" x-text="selectedVuln.cvss_score"></span>
                                        </span>

                                        <span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400">
                                            <span>EPSS:</span>
                                            <span class="font-bold" x-text="selectedVuln.epss_percentile.toFixed(1) + '%'"></span>
                                        </span>

                                        <span x-show="selectedVuln.kev" class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
                                            🔴 KEV Listed
                                        </span>
                                    </div>
                                </div>
                                <button @click="closeModal()"
                                        class="ml-4 rounded-lg p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500">
                                    <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            <!-- Tab Navigation -->
                            <nav class="flex gap-2 mt-4 border-b border-gray-200 dark:border-gray-700" role="tablist">
                                <button @click="switchTab('overview')"
                                        :class="activeTab === 'overview' ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'"
                                        class="px-4 py-2 border-b-2 font-medium text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                                        role="tab">
                                    Overview
                                </button>
                                <button @click="switchTab('details')"
                                        :class="activeTab === 'details' ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'"
                                        class="px-4 py-2 border-b-2 font-medium text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                                        role="tab">
                                    Technical Details
                                </button>
                                <button @click="switchTab('references')"
                                        :class="activeTab === 'references' ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'"
                                        class="px-4 py-2 border-b-2 font-medium text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                                        role="tab">
                                    References
                                </button>
                                <button @click="switchTab('enrichments')"
                                        :class="activeTab === 'enrichments' ? 'border-primary-500 text-primary-600 dark:text-primary-400' : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'"
                                        class="px-4 py-2 border-b-2 font-medium text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2"
                                        role="tab">
                                    Enrichments
                                </button>
                            </nav>
                        </div>

                        <!-- Modal Content -->
                        <div class="overflow-y-auto px-6 py-6 flex-1">
                            <!-- Overview Tab -->
                            <div x-show="activeTab === 'overview'" role="tabpanel" class="space-y-6">
                                <div>
                                    <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3">Description</h3>
                                    <p class="text-gray-700 dark:text-gray-300 leading-relaxed" x-text="selectedVuln.description"></p>
                                </div>

                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Published Date</h4>
                                        <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.published"></p>
                                    </div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Last Modified</h4>
                                        <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.last_modified"></p>
                                    </div>
                                </div>

                                <div>
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Affected Products</h4>
                                    <div class="flex flex-wrap gap-2">
                                        <template x-for="product in selectedVuln.products" :key="product">
                                            <span class="px-3 py-1 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded-full text-sm" x-text="product"></span>
                                        </template>
                                    </div>
                                </div>

                                <div>
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Vendors</h4>
                                    <div class="flex flex-wrap gap-2">
                                        <template x-for="vendor in selectedVuln.vendors" :key="vendor">
                                            <span class="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded-full text-sm" x-text="vendor"></span>
                                        </template>
                                    </div>
                                </div>

                                <div x-show="selectedVuln.ssvc && selectedVuln.ssvc.priorityTier">
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">SSVC Priority</h4>
                                    <div class="flex items-center gap-3">
                                        <span :class="{{'
                                            'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400': selectedVuln.ssvc.priorityTier === 'ACT',
                                            'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400': selectedVuln.ssvc.priorityTier === 'ATTEND',
                                            'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400': selectedVuln.ssvc.priorityTier === 'TRACK'
                                        }}" class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold" x-text="selectedVuln.ssvc.priorityTier"></span>
                                        <span class="text-sm text-gray-600 dark:text-gray-400" x-text="selectedVuln.ssvc.compactNotation"></span>
                                    </div>
                                </div>
                            </div>

                            <!-- Technical Details Tab -->
                            <div x-show="activeTab === 'details'" role="tabpanel" class="space-y-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Attack Vector</h4>
                                        <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.attack_vector || 'N/A'"></p>
                                    </div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Attack Complexity</h4>
                                        <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.attack_complexity || 'N/A'"></p>
                                    </div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Privileges Required</h4>
                                        <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.privileges_required || 'N/A'"></p>
                                    </div>
                                    <div>
                                        <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">User Interaction</h4>
                                        <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.user_interaction || 'N/A'"></p>
                                    </div>
                                </div>

                                <div>
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Exploitation Status</h4>
                                    <p class="text-gray-700 dark:text-gray-300" x-text="selectedVuln.exploitation_status"></p>
                                </div>

                                <div x-show="selectedVuln.tags && selectedVuln.tags.length > 0">
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Tags</h4>
                                    <div class="flex flex-wrap gap-2">
                                        <template x-for="tag in selectedVuln.tags" :key="tag">
                                            <span class="px-3 py-1 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded-full text-sm" x-text="tag"></span>
                                        </template>
                                    </div>
                                </div>

                                <div class="bg-gray-50 dark:bg-gray-800/50 rounded-lg p-4">
                                    <h4 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-3">Scoring Details</h4>
                                    <div class="grid grid-cols-2 gap-4">
                                        <div>
                                            <p class="text-xs text-gray-600 dark:text-gray-400 mb-1">CVSS Base Score</p>
                                            <p class="text-lg font-bold text-gray-900 dark:text-gray-100" x-text="selectedVuln.cvss_score"></p>
                                        </div>
                                        <div>
                                            <p class="text-xs text-gray-600 dark:text-gray-400 mb-1">EPSS Score</p>
                                            <p class="text-lg font-bold text-gray-900 dark:text-gray-100" x-text="selectedVuln.epss_score.toFixed(1) + '%'"></p>
                                        </div>
                                        <div>
                                            <p class="text-xs text-gray-600 dark:text-gray-400 mb-1">EPSS Percentile</p>
                                            <p class="text-lg font-bold text-gray-900 dark:text-gray-100" x-text="selectedVuln.epss_percentile.toFixed(1) + '%'"></p>
                                        </div>
                                        <div>
                                            <p class="text-xs text-gray-600 dark:text-gray-400 mb-1">Risk Score</p>
                                            <p class="text-lg font-bold text-gray-900 dark:text-gray-100" x-text="selectedVuln.risk_score"></p>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <!-- References Tab -->
                            <div x-show="activeTab === 'references'" role="tabpanel" class="space-y-4">
                                <template x-if="selectedVuln.references && selectedVuln.references.length > 0">
                                    <ul class="space-y-3">
                                        <template x-for="(ref, index) in selectedVuln.references" :key="index">
                                            <li class="border-l-4 border-primary-500 pl-4 py-2 bg-gray-50 dark:bg-gray-800/50 rounded-r-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors">
                                                <a :href="ref.url"
                                                   target="_blank"
                                                   rel="noopener noreferrer"
                                                   class="flex items-center gap-2 text-primary-600 dark:text-primary-400 hover:underline group">
                                                    <svg class="h-4 w-4 flex-shrink-0 group-hover:translate-x-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                                    </svg>
                                                    <span class="break-all" x-text="ref.url"></span>
                                                </a>
                                                <p x-show="ref.source" class="text-xs text-gray-500 dark:text-gray-400 mt-1 ml-6" x-text="'Source: ' + ref.source"></p>
                                            </li>
                                        </template>
                                    </ul>
                                </template>
                                <template x-if="!selectedVuln.references || selectedVuln.references.length === 0">
                                    <p class="text-gray-500 dark:text-gray-400 text-center py-8">No references available</p>
                                </template>
                            </div>

                            <!-- Enrichments Tab -->
                            <div x-show="activeTab === 'enrichments'" role="tabpanel" class="space-y-6">
                                <template x-if="selectedVuln.enrichments && selectedVuln.enrichments.cisa_kev">
                                    <div class="border border-red-200 dark:border-red-800 rounded-lg p-4 bg-red-50 dark:bg-red-900/10">
                                        <div class="flex items-start gap-3">
                                            <div class="flex-shrink-0 text-2xl">🔴</div>
                                            <div class="flex-1">
                                                <h4 class="text-sm font-semibold text-red-900 dark:text-red-400 mb-2">CISA Known Exploited Vulnerability</h4>
                                                <div class="space-y-2 text-sm text-red-800 dark:text-red-300">
                                                    <p x-show="selectedVuln.enrichments.cisa_kev.vendorProject">
                                                        <span class="font-medium">Vendor:</span>
                                                        <span x-text="selectedVuln.enrichments.cisa_kev.vendorProject"></span>
                                                    </p>
                                                    <p x-show="selectedVuln.enrichments.cisa_kev.product">
                                                        <span class="font-medium">Product:</span>
                                                        <span x-text="selectedVuln.enrichments.cisa_kev.product"></span>
                                                    </p>
                                                    <p x-show="selectedVuln.enrichments.cisa_kev.vulnerabilityName">
                                                        <span class="font-medium">Vulnerability:</span>
                                                        <span x-text="selectedVuln.enrichments.cisa_kev.vulnerabilityName"></span>
                                                    </p>
                                                    <p x-show="selectedVuln.enrichments.cisa_kev.dateAdded">
                                                        <span class="font-medium">Added to KEV:</span>
                                                        <span x-text="selectedVuln.enrichments.cisa_kev.dateAdded"></span>
                                                    </p>
                                                    <p x-show="selectedVuln.enrichments.cisa_kev.dueDate">
                                                        <span class="font-medium">Due Date:</span>
                                                        <span x-text="selectedVuln.enrichments.cisa_kev.dueDate"></span>
                                                    </p>
                                                    <p x-show="selectedVuln.enrichments.cisa_kev.requiredAction" class="mt-3 p-3 bg-red-100 dark:bg-red-900/20 rounded border border-red-300 dark:border-red-700">
                                                        <span class="font-medium block mb-1">Required Action:</span>
                                                        <span x-text="selectedVuln.enrichments.cisa_kev.requiredAction"></span>
                                                    </p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </template>

                                <template x-if="!selectedVuln.enrichments || Object.keys(selectedVuln.enrichments).length === 0">
                                    <p class="text-gray-500 dark:text-gray-400 text-center py-8">No enrichment data available</p>
                                </template>

                                <div x-show="selectedVuln.enrichments && Object.keys(selectedVuln.enrichments).length > 0 && !selectedVuln.enrichments.cisa_kev" class="text-sm text-gray-600 dark:text-gray-400">
                                    <p>Additional enrichment data may be available for this CVE.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </template>
            </div>
        </div>
    </div>

    <!-- Alpine.js Dashboard Component -->
    <script>
        function vulnDashboard() {{
            return {{
                // State
                vulnerabilities: {vuln_json},
                searchQuery: '',
                selectedSeverity: '',
                showKEVOnly: false,
                currentPage: 1,
                perPage: 50,
                darkMode: false,

                // Modal state
                selectedVuln: null,
                modalOpen: false,
                activeTab: 'overview',

                // Sort state
                sortColumn: null,
                sortDirection: 'asc',

                // Computed properties
                get filteredVulns() {{
                    let filtered = this.vulnerabilities;

                    // Search filter
                    if (this.searchQuery) {{
                        const query = this.searchQuery.toLowerCase();
                        filtered = filtered.filter(v =>
                            v.cve_id.toLowerCase().includes(query) ||
                            v.products.toLowerCase().includes(query) ||
                            v.vendors.some(vendor => vendor.toLowerCase().includes(query))
                        );
                    }}

                    // Severity filter
                    if (this.selectedSeverity) {{
                        filtered = filtered.filter(v => v.severity === this.selectedSeverity);
                    }}

                    // KEV filter
                    if (this.showKEVOnly) {{
                        filtered = filtered.filter(v => v.kev);
                    }}

                    // Apply sorting
                    if (this.sortColumn) {{
                        filtered = [...filtered].sort((a, b) => {{
                            let aVal = a[this.sortColumn];
                            let bVal = b[this.sortColumn];

                            // Handle severity sorting with custom order
                            if (this.sortColumn === 'severity') {{
                                const severityOrder = {{ 'CRITICAL': 2, 'HIGH': 1 }};
                                aVal = severityOrder[aVal] || 0;
                                bVal = severityOrder[bVal] || 0;
                            }}

                            // Handle numeric comparisons
                            if (typeof aVal === 'number' && typeof bVal === 'number') {{
                                return this.sortDirection === 'asc' ? aVal - bVal : bVal - aVal;
                            }}

                            // Handle string comparisons
                            const comparison = String(aVal).localeCompare(String(bVal));
                            return this.sortDirection === 'asc' ? comparison : -comparison;
                        }});
                    }}

                    return filtered;
                }},
                
                get totalPages() {{
                    return Math.ceil(this.filteredVulns.length / this.perPage);
                }},
                
                get paginatedVulns() {{
                    const start = (this.currentPage - 1) * this.perPage;
                    const end = start + this.perPage;
                    return this.filteredVulns.slice(start, end);
                }},
                
                // Methods
                initDashboard() {{
                    // Initialize dark mode from localStorage or system preference
                    const savedMode = localStorage.getItem('darkMode');
                    if (savedMode !== null) {{
                        this.darkMode = savedMode === 'true';
                    }} else {{
                        this.darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    }}

                    if (this.darkMode) {{
                        document.documentElement.classList.add('dark');
                    }} else {{
                        document.documentElement.classList.remove('dark');
                    }}

                    // Initialize charts after a short delay to ensure DOM is ready
                    setTimeout(() => this.initCharts(), 100);
                }},

                initCharts() {{
                    const isDark = this.darkMode;
                    const textColor = isDark ? '#e5e7eb' : '#374151';
                    const gridColor = isDark ? '#374151' : '#e5e7eb';

                    // 1. Severity Distribution Chart (Donut)
                    const severityCtx = document.getElementById('severityChart');
                    if (severityCtx) {{
                        const criticalCount = this.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
                        const highCount = this.vulnerabilities.filter(v => v.severity === 'HIGH').length;

                        new Chart(severityCtx, {{
                            type: 'doughnut',
                            data: {{
                                labels: ['Critical', 'High'],
                                datasets: [{{
                                    data: [criticalCount, highCount],
                                    backgroundColor: ['#dc2626', '#ea580c'],
                                    borderWidth: 2,
                                    borderColor: isDark ? '#111827' : '#ffffff'
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{
                                        labels: {{
                                            color: textColor,
                                            font: {{ size: 12 }}
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }}

                    // 2. EPSS Score Distribution Chart (Bar)
                    const epssCtx = document.getElementById('epssChart');
                    if (epssCtx) {{
                        // SERVER-CALCULATED data (avoids client-side caching issues)
                        const epssLabels = {json.dumps(epss_labels)};
                        const epssData = {json.dumps(epss_data)};

                        new Chart(epssCtx, {{
                            type: 'bar',
                            data: {{
                                labels: epssLabels,
                                datasets: [{{
                                    label: 'Count',
                                    data: epssData,
                                    backgroundColor: '#06b6d4',
                                    borderWidth: 0
                                }}]
                            }},
                            options: {{
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{ display: false }},
                                    title: {{
                                        display: false
                                    }}
                                }},
                                scales: {{
                                    y: {{
                                        beginAtZero: true,
                                        ticks: {{
                                            color: textColor,
                                            precision: 0
                                        }},
                                        grid: {{
                                            color: gridColor
                                        }}
                                    }},
                                    x: {{
                                        ticks: {{
                                            color: textColor
                                        }},
                                        grid: {{
                                            display: false
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }}

                    // 3. Top Vendors Chart (Horizontal Bar)
                    const vendorsCtx = document.getElementById('vendorsChart');
                    if (vendorsCtx) {{
                        // SERVER-CALCULATED data (avoids client-side caching issues)
                        const vendorLabels = {json.dumps(vendor_labels)};
                        const vendorData = {json.dumps(vendor_data)};

                        new Chart(vendorsCtx, {{
                            type: 'bar',
                            data: {{
                                labels: vendorLabels,
                                datasets: [{{
                                    label: 'Vulnerabilities',
                                    data: vendorData,
                                    backgroundColor: '#8b5cf6',
                                    borderWidth: 0
                                }}]
                            }},
                            options: {{
                                indexAxis: 'y',
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {{
                                    legend: {{ display: false }}
                                }},
                                scales: {{
                                    x: {{
                                        beginAtZero: true,
                                        ticks: {{
                                            color: textColor,
                                            precision: 0
                                        }},
                                        grid: {{
                                            color: gridColor
                                        }}
                                    }},
                                    y: {{
                                        ticks: {{
                                            color: textColor,
                                            font: {{ size: 11 }}
                                        }},
                                        grid: {{
                                            display: false
                                        }}
                                    }}
                                }}
                            }}
                        }});
                    }}
                }},
                
                toggleDarkMode() {{
                    this.darkMode = !this.darkMode;
                    if (this.darkMode) {{
                        document.documentElement.classList.add('dark');
                        localStorage.setItem('darkMode', 'true');
                    }} else {{
                        document.documentElement.classList.remove('dark');
                        localStorage.setItem('darkMode', 'false');
                    }}
                }},
                
                filterBySeverity(severity) {{
                    this.selectedSeverity = this.selectedSeverity === severity ? '' : severity;
                    this.currentPage = 1;
                }},
                
                filterByKEV() {{
                    this.showKEVOnly = !this.showKEVOnly;
                    this.currentPage = 1;
                }},
                
                resetFilters() {{
                    this.searchQuery = '';
                    this.selectedSeverity = '';
                    this.showKEVOnly = false;
                    this.currentPage = 1;
                }},
                
                nextPage() {{
                    if (this.currentPage < this.totalPages) {{
                        this.currentPage++;
                        window.scrollTo({{ top: 0, behavior: 'smooth' }});
                    }}
                }},
                
                prevPage() {{
                    if (this.currentPage > 1) {{
                        this.currentPage--;
                        window.scrollTo({{ top: 0, behavior: 'smooth' }});
                    }}
                }},
                
                exportCSV() {{
                    try {{
                        const headers = ['CVE ID', 'Severity', 'CVSS', 'EPSS %', 'Product', 'Vendors', 'KEV Listed', 'Published', 'Last Modified'];
                        
                        const escapeCsv = (value) => {{
                            if (value == null || value === undefined) return '';
                            const str = String(value);
                            if (str.includes(',') || str.includes('"') || str.includes('\\n')) {{
                                return `"${{str.replace(/"/g, '""')}}"`;
                            }}
                            return str;
                        }};
                        
                        const csvContent = [
                            headers.join(','),
                            ...this.filteredVulns.map(v => [
                                escapeCsv(v.cve_id),
                                escapeCsv(v.severity),
                                escapeCsv(v.cvss_score),
                                escapeCsv(v.epss_percentile.toFixed(1)),
                                escapeCsv(v.products),
                                escapeCsv(Array.isArray(v.vendors) ? v.vendors.join('; ') : v.vendors),
                                v.kev ? 'Yes' : 'No',
                                escapeCsv(v.published),
                                escapeCsv(v.last_modified)
                            ].join(','))
                        ].join('\\n');
                        
                        const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        const timestamp = new Date().toISOString().split('T')[0];
                        a.download = `vulnerabilities-${{timestamp}}.csv`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                        
                        console.log('✅ CSV export successful:', this.filteredVulns.length, 'vulnerabilities exported');
                    }} catch (error) {{
                        console.error('❌ CSV export failed:', error);
                        alert('Failed to export CSV. Please try again.');
                    }}
                }},

                // Modal methods
                openModal(vuln) {{
                    this.selectedVuln = vuln;
                    this.modalOpen = true;
                    this.activeTab = 'overview';
                    // Prevent body scroll when modal is open
                    document.body.style.overflow = 'hidden';
                }},

                closeModal() {{
                    this.modalOpen = false;
                    this.selectedVuln = null;
                    // Restore body scroll
                    document.body.style.overflow = 'auto';
                }},

                switchTab(tab) {{
                    this.activeTab = tab;
                }},

                // Sort methods
                sortBy(column) {{
                    if (this.sortColumn === column) {{
                        // Toggle direction if already sorting by this column
                        this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
                    }} else {{
                        // New column, default to ascending
                        this.sortColumn = column;
                        this.sortDirection = 'asc';
                    }}
                }},

                getSortIcon(column) {{
                    if (this.sortColumn !== column) {{
                        return '↕️'; // Both arrows when not sorting
                    }}
                    return this.sortDirection === 'asc' ? '↑' : '↓';
                }}
            }}
        }}
    </script>
</body>
</html>
'''
    
    # Write output file
    output_file = OUTPUT_DIR / "index.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"✅ Tailwind dashboard generated successfully!")
    print(f"📁 Output: {output_file}")
    print(f"📊 Statistics:")
    print(f"   • Total CVEs: {total_vulns}")
    print(f"   • Critical: {critical_count}")
    print(f"   • High: {high_count}")
    print(f"   • KEV Listed: {kev_count}")

if __name__ == "__main__":
    generate_dashboard()
