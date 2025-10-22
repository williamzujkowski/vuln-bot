#!/usr/bin/env python3
"""
Tailwind CSS-based Alpine.js dashboard generator with system dark/light mode support
"""
import json
from pathlib import Path
from datetime import datetime

OUTPUT_DIR = Path("public")
OUTPUT_DIR.mkdir(exist_ok=True)

def load_vulnerabilities():
    """Load vulnerabilities from JSON API"""
    api_file = Path("api/vulns/index.json")
    if not api_file.exists():
        print(f"Error: {api_file} not found")
        return []
    
    with open(api_file) as f:
        data = json.load(f)
    return data.get("vulnerabilities", [])

def generate_dashboard():
    """Generate Tailwind CSS-based dashboard"""
    vulns = load_vulnerabilities()
    
    # Prepare vulnerability data for JavaScript
    vuln_data = []
    for v in vulns:
        vuln_data.append({
            "cve_id": v.get("cveId", ""),
            "severity": v.get("severity", ""),
            "cvss_score": v.get("cvssScore", 0),
            "epss_percentile": v.get("epssPercentile", 0),
            "risk_score": v.get("riskScore", 0),
            "products": ", ".join(v.get("products", [])),
            "vendors": v.get("vendors", []),
            "published_short": str(v.get("publishedDate", ""))[:10],
            "last_modified_short": str(v.get("lastModifiedDate", ""))[:10],
            "kev_status": v.get("exploitationStatus") == "KNOWN_EXPLOITED",
            "exploitation_status": v.get("exploitationStatus", "UNKNOWN"),
            "enrichments": v.get("enrichments", {}),
            "description": v.get("description", ""),
            "attack_vector": v.get("attackVector", ""),
        })
    
    # Stats
    total_vulns = len(vuln_data)
    critical_count = sum(1 for v in vuln_data if v["severity"] == "CRITICAL")
    high_count = sum(1 for v in vuln_data if v["severity"] == "HIGH")
    kev_count = sum(1 for v in vuln_data if v["kev_status"])
    
    # Build timestamp
    build_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    
    html_content = f"""<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="High-risk CVE intelligence dashboard with EPSS ≥60% exploitation probability">
    <title>Vulnerability Intelligence Dashboard</title>
    
    <!-- Tailwind CSS via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    
    <!-- Alpine.js -->
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    
    <!-- Tailwind Config -->
    <script>
        tailwind.config = {{
            darkMode: 'class', // Enable class-based dark mode for manual toggle
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
                        }}
                    }}
                }}
            }}
        }}
    </script>
    
    <style>
        /* Custom scrollbar */
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        ::-webkit-scrollbar-track {{
            @apply bg-gray-900;
        }}
        ::-webkit-scrollbar-thumb {{
            @apply bg-gray-700 rounded hover:bg-gray-600;
        }}
        
        /* System dark mode detection */
        @media (prefers-color-scheme: dark) {{
            html:not(.light) {{
                color-scheme: dark;
            }}
        }}
        
        @media (prefers-color-scheme: light) {{
            html.light {{
                color-scheme: light;
            }}
        }}
    </style>
</head>
<body class="bg-white dark:bg-gray-950 text-gray-900 dark:text-gray-100 antialiased transition-colors duration-200" 
      x-data="vulnDashboard()" 
      x-init="init()"
      x-cloak>
    
    <!-- Header with Build/Data Status -->
    <header class="sticky top-0 z-50 bg-white/95 dark:bg-gray-900/95 backdrop-blur-md border-b border-gray-200 dark:border-gray-800 shadow-sm">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <!-- Main Header Row -->
            <div class="flex items-center justify-between py-4">
                <!-- Brand -->
                <div class="flex items-center space-x-3">
                    <div class="flex items-center justify-center w-10 h-10 bg-gradient-to-br from-primary-500 to-purple-600 rounded-lg shadow-lg">
                        <span class="text-xl">🛡️</span>
                    </div>
                    <div>
                        <h1 class="text-xl sm:text-2xl font-bold text-gray-900 dark:text-white">Vuln-Bot</h1>
                        <p class="text-xs text-gray-600 dark:text-gray-400">CVE Intelligence Dashboard</p>
                    </div>
                </div>
                
                <!-- Actions -->
                <nav class="flex items-center space-x-2 sm:space-x-3">
                    <!-- Dark/Light Mode Toggle -->
                    <button @click="toggleDarkMode()" 
                            class="p-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                            aria-label="Toggle dark mode">
                        <svg x-show="!darkMode" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
                        </svg>
                        <svg x-show="darkMode" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
                        </svg>
                    </button>
                    
                    <!-- GitHub Link -->
                    <a href="https://github.com/williamzujkowski/vuln-bot" 
                       target="_blank" 
                       rel="noopener noreferrer"
                       class="flex items-center space-x-2 px-3 py-2 rounded-lg bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors text-sm font-medium">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 16 16">
                            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                        </svg>
                        <span class="hidden sm:inline">GitHub</span>
                    </a>
                    
                    <!-- Export CSV -->
                    <button @click="exportCSV()" 
                            class="flex items-center space-x-2 px-3 py-2 rounded-lg bg-primary-600 hover:bg-primary-700 text-white transition-colors text-sm font-medium">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
                        </svg>
                        <span class="hidden sm:inline">Export CSV</span>
                    </button>
                </nav>
            </div>
            
            <!-- Status Badges Row -->
            <div class="flex flex-wrap items-center gap-2 pb-3 text-xs">
                <div class="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span class="font-medium">Built:</span>
                    <time datetime="{build_time}">{build_time}</time>
                </div>
                <div class="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 border border-blue-200 dark:border-blue-800">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                    </svg>
                    <span class="font-medium">Data:</span>
                    <span>Fresh (4h cycle)</span>
                </div>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        <!-- Stats Grid -->
        <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8" aria-label="Statistics">
            <!-- Total Vulnerabilities -->
            <article class="bg-white dark:bg-gray-900 rounded-xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Total CVEs</p>
                        <p class="text-3xl font-bold mt-2 bg-gradient-to-r from-primary-500 to-purple-600 bg-clip-text text-transparent">{total_vulns}</p>
                    </div>
                    <div class="p-3 bg-primary-100 dark:bg-primary-900/30 rounded-lg">
                        <svg class="w-8 h-8 text-primary-600 dark:text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
                        </svg>
                    </div>
                </div>
            </article>
            
            <!-- Critical Severity -->
            <article class="bg-white dark:bg-gray-900 rounded-xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Critical</p>
                        <p class="text-3xl font-bold mt-2 text-red-600 dark:text-red-400">{critical_count}</p>
                    </div>
                    <div class="p-3 bg-red-100 dark:bg-red-900/30 rounded-lg">
                        <svg class="w-8 h-8 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                    </div>
                </div>
            </article>
            
            <!-- High Severity -->
            <article class="bg-white dark:bg-gray-900 rounded-xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600 dark:text-gray-400">High</p>
                        <p class="text-3xl font-bold mt-2 text-orange-600 dark:text-orange-400">{high_count}</p>
                    </div>
                    <div class="p-3 bg-orange-100 dark:bg-orange-900/30 rounded-lg">
                        <svg class="w-8 h-8 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                        </svg>
                    </div>
                </div>
            </article>
            
            <!-- KEV Listed -->
            <article class="bg-white dark:bg-gray-900 rounded-xl p-6 border border-gray-200 dark:border-gray-800 shadow-sm hover:shadow-md transition-shadow">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm font-medium text-gray-600 dark:text-gray-400">KEV Listed</p>
                        <p class="text-3xl font-bold mt-2 text-purple-600 dark:text-purple-400">{kev_count}</p>
                    </div>
                    <div class="p-3 bg-purple-100 dark:bg-purple-900/30 rounded-lg">
                        <svg class="w-8 h-8 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/>
                        </svg>
                    </div>
                </div>
            </article>
        </section>

