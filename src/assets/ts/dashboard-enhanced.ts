/**
 * Enhanced Vulnerability Dashboard with Modern UI/UX
 */

import type { Vulnerability, FilterState } from "./types/vulnerability";
import { analytics } from "./analytics";

// Chart interface for Chart.js loaded via CDN
interface Chart {
  destroy(): void;
}

// Declare global Chart constructor
declare const Chart: any;

interface EnhancedDashboard {
  // Core data
  vulnerabilities: Vulnerability[];
  filteredVulns: Vulnerability[];
  paginatedVulns: Vulnerability[];
  
  // UI State
  loading: boolean;
  error: string | null;
  filtersExpanded: boolean;
  showDataInsights: boolean;
  showSettings: boolean;
  
  // Search & Filter
  searchQuery: string;
  searchSuggestions: string[];
  activeQuickFilter: string | null;
  filters: FilterState;
  
  // Sort & Pagination
  sortField: keyof Vulnerability;
  sortDirection: "asc" | "desc";
  currentPage: number;
  pageSize: number;
  totalPages: number;
  
  // Charts
  charts: {
    severity: Chart | null;
    trend: Chart | null;
    vendor: Chart | null;
    epss: Chart | null;
  };
  
  // Methods
  init(): Promise<void>;
  loadVulnerabilities(): Promise<void>;
  initializeCharts(): void;
  applyQuickFilter(filter: string): void;
  hasActiveFilters(): boolean;
  getActiveFilters(): Array<{key: string, label: string}>;
  removeFilter(key: string): void;
  copyToClipboard(text: string): void;
  showToast(message: string, type: 'success' | 'error' | 'info'): void;
  applyFilters(): void;
  sortResults(results: Vulnerability[]): Vulnerability[];
  sort(field: keyof Vulnerability): void;
  updatePagination(): void;
  previousPage(): void;
  nextPage(): void;
  resetFilters(): void;
  exportResults(): void;
  generateCSV(data: Vulnerability[]): string;
  openCveModal(cveId: string): Promise<void>;
  formatDate(date: string): string;
  calculateRiskScore(vuln: Vulnerability): number;
  calculateDaysOld(date: string): number;
  getSeverityCounts(): Record<string, number>;
  getTrendData(): { labels: string[], values: number[] };
  getTopVendors(): { labels: string[], values: number[] };
  getEPSSDistribution(): { labels: string[], values: number[], colors: string[] };
  setupSearchSuggestions(): void;
  $nextTick(callback: () => void): void;
  $watch(key: string, callback: (value: any) => void): void;
}

// Chart.js configuration with dark theme
const chartDefaults = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color: '#cbd5e1',
        font: {
          family: 'Inter, sans-serif'
        }
      }
    },
    tooltip: {
      backgroundColor: '#1e2332',
      borderColor: '#64748b',
      borderWidth: 1,
      titleColor: '#f8fafc',
      bodyColor: '#cbd5e1',
      cornerRadius: 8,
      padding: 12
    }
  },
  scales: {
    x: {
      ticks: { color: '#94a3b8' },
      grid: { color: 'rgba(148, 163, 184, 0.1)' }
    },
    y: {
      ticks: { color: '#94a3b8' },
      grid: { color: 'rgba(148, 163, 184, 0.1)' }
    }
  }
};

// Register the enhanced dashboard component with Alpine
document.addEventListener("alpine:init", () => {
  window.Alpine.data('vulnDashboard', (): EnhancedDashboard => ({
  // Initialize empty state
  vulnerabilities: [],
  filteredVulns: [],
  paginatedVulns: [],
  loading: true,
  error: null,
  filtersExpanded: true,
  showDataInsights: false,
  showSettings: false,
  searchQuery: '',
  searchSuggestions: [],
  activeQuickFilter: null,
  
  charts: {
    severity: null,
    trend: null,
    vendor: null,
    epss: null
  },
  
  // Extended from base dashboard
  filters: {
    cvssMin: 0,
    cvssMax: 10,
    epssMin: 70, // Default to high-risk
    epssMax: 100,
    severity: '',
    publishedDateFrom: '',
    publishedDateTo: '',
    lastModifiedDateFrom: '',
    lastModifiedDateTo: '',
    dateFrom: '',
    dateTo: '',
    vendor: '',
    tags: []
  },
  
  sortField: 'riskScore',
  sortDirection: 'desc',
  currentPage: 1,
  pageSize: 50,
  totalPages: 1,
  
  async init() {
    try {
      // Load data
      await this.loadVulnerabilities();
      
      // Apply initial filters
      this.applyFilters();
      
      // Initialize visualizations
      this.$nextTick(() => {
        this.initializeCharts();
      });
      
      // Setup real-time search suggestions
      this.setupSearchSuggestions();
      
      // Track page view
      analytics.trackPageView('dashboard');
      
    } catch (error) {
      this.error = error instanceof Error ? error.message : 'Failed to initialize dashboard';
      console.error('Dashboard initialization failed:', error);
    } finally {
      this.loading = false;
    }
  },
  
  async loadVulnerabilities() {
    try {
      const response = await fetch('/vuln-bot/api/vulns/index.json');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      
      const data = await response.json();
      this.vulnerabilities = data.vulnerabilities || [];
      
      // Enrich with calculated fields
      this.vulnerabilities = this.vulnerabilities.map(vuln => ({
        ...vuln,
        riskScore: this.calculateRiskScore(vuln),
        daysOld: this.calculateDaysOld(vuln.publishedDate)
      }));
      
    } catch (error) {
      throw new Error(`Failed to load vulnerabilities: ${error instanceof Error ? error.message : String(error)}`);
    }
  },
  
  calculateRiskScore(vuln: Vulnerability): number {
    // Enhanced risk scoring algorithm
    let score = 0;
    
    // CVSS contribution (40%)
    score += (vuln.cvssScore || 0) * 4;
    
    // EPSS contribution (40%)
    score += (vuln.epssPercentile || 0) * 0.4;
    
    // Severity bonus (10%)
    const severityBonus: Record<string, number> = {
      'CRITICAL': 10,
      'HIGH': 7,
      'MEDIUM': 4,
      'LOW': 1,
      'NONE': 0
    };
    score += severityBonus[vuln.severity] || 0;
    
    // Recency bonus (10%)
    const daysOld = this.calculateDaysOld(vuln.publishedDate);
    if (daysOld <= 7) score += 10;
    else if (daysOld <= 30) score += 5;
    
    return Math.round(Math.min(score, 100));
  },
  
  calculateDaysOld(date: string): number {
    const published = new Date(date);
    const now = new Date();
    return Math.floor((now.getTime() - published.getTime()) / (1000 * 60 * 60 * 24));
  },
  
  initializeCharts() {
    // Clean up existing charts
    Object.values(this.charts).forEach(chart => chart?.destroy());
    
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severityChart') as HTMLCanvasElement;
    if (severityCtx) {
      const severityCounts = this.getSeverityCounts();
      this.charts.severity = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
          labels: Object.keys(severityCounts),
          datasets: [{
            data: Object.values(severityCounts),
            backgroundColor: [
              '#dc2626', // Critical
              '#ef4444', // High
              '#f59e0b', // Medium
              '#3b82f6'  // Low
            ],
            borderWidth: 0
          }]
        },
        options: {
          ...chartDefaults,
          cutout: '70%',
          plugins: {
            ...chartDefaults.plugins,
            title: {
              display: true,
              text: `Total: ${this.filteredVulns.length}`,
              position: 'bottom',
              color: '#cbd5e1'
            }
          }
        }
      });
    }
    
    // 30-Day Trend Chart
    const trendCtx = document.getElementById('trendChart') as HTMLCanvasElement;
    if (trendCtx) {
      const trendData = this.getTrendData();
      this.charts.trend = new Chart(trendCtx, {
        type: 'line',
        data: {
          labels: trendData.labels,
          datasets: [{
            label: 'New CVEs',
            data: trendData.values,
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59, 130, 246, 0.1)',
            tension: 0.4,
            fill: true
          }]
        },
        options: chartDefaults
      });
    }
    
    // Top Vendors Chart
    const vendorCtx = document.getElementById('vendorChart') as HTMLCanvasElement;
    if (vendorCtx) {
      const vendorData = this.getTopVendors();
      this.charts.vendor = new Chart(vendorCtx, {
        type: 'bar',
        data: {
          labels: vendorData.labels,
          datasets: [{
            label: 'Vulnerabilities',
            data: vendorData.values,
            backgroundColor: '#8b5cf6'
          }]
        },
        options: {
          ...chartDefaults,
          indexAxis: 'y',
          scales: {
            ...chartDefaults.scales,
            x: {
              ...chartDefaults.scales.x,
              beginAtZero: true
            }
          }
        }
      });
    }
    
    // EPSS Distribution
    const epssCtx = document.getElementById('epssChart') as HTMLCanvasElement;
    if (epssCtx) {
      const epssData = this.getEPSSDistribution();
      this.charts.epss = new Chart(epssCtx, {
        type: 'bar',
        data: {
          labels: epssData.labels,
          datasets: [{
            label: 'Count',
            data: epssData.values,
            backgroundColor: epssData.colors
          }]
        },
        options: {
          ...chartDefaults,
          scales: {
            ...chartDefaults.scales,
            y: {
              ...chartDefaults.scales.y,
              beginAtZero: true
            }
          }
        }
      });
    }
  },
  
  getSeverityCounts() {
    const counts: Record<string, number> = {
      'CRITICAL': 0,
      'HIGH': 0,
      'MEDIUM': 0,
      'LOW': 0
    };
    
    this.filteredVulns.forEach(vuln => {
      if (vuln.severity in counts) {
        counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
      }
    });
    
    return counts;
  },
  
  getTrendData() {
    const last30Days = [];
    const counts = [];
    
    for (let i = 29; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      last30Days.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) || '');
      
      const count = this.vulnerabilities.filter(vuln => 
        vuln.publishedDate && dateStr && vuln.publishedDate.startsWith(dateStr)
      ).length;
      counts.push(count);
    }
    
    return { labels: last30Days, values: counts };
  },
  
  getTopVendors() {
    const vendorCounts = new Map<string, number>();
    
    this.filteredVulns.forEach(vuln => {
      vuln.vendors?.forEach(vendor => {
        vendorCounts.set(vendor, (vendorCounts.get(vendor) || 0) + 1);
      });
    });
    
    const sorted = Array.from(vendorCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
    
    return {
      labels: sorted.map(([vendor]) => vendor),
      values: sorted.map(([, count]) => count)
    };
  },
  
  getEPSSDistribution() {
    const ranges = [
      { label: '90-100%', min: 90, max: 100, color: '#dc2626' },
      { label: '80-89%', min: 80, max: 89, color: '#ef4444' },
      { label: '70-79%', min: 70, max: 79, color: '#f59e0b' },
      { label: '<70%', min: 0, max: 69, color: '#3b82f6' }
    ];
    
    const counts = ranges.map(range => ({
      ...range,
      count: this.filteredVulns.filter(vuln => 
        vuln.epssPercentile >= range.min && vuln.epssPercentile <= range.max
      ).length
    }));
    
    return {
      labels: counts.map(r => r.label),
      values: counts.map(r => r.count),
      colors: counts.map(r => r.color)
    };
  },
  
  applyQuickFilter(filter: string) {
    // Reset filters first
    this.resetFilters();
    
    switch (filter) {
      case 'critical':
        this.filters.severity = 'CRITICAL';
        break;
        
      case 'today':
        const today = new Date().toISOString().split('T')[0] || '';
        this.filters.publishedDateFrom = today;
        this.filters.publishedDateTo = today;
        break;
        
      case 'kev':
        this.filters.tags = ['KEV'];
        break;
        
      case 'network':
        this.filters.tags = ['network', 'remote'];
        break;
    }
    
    this.activeQuickFilter = filter;
    this.applyFilters();
    analytics.track('quick_filter', 'filter', 'apply', filter);
    this.showToast(`Filter applied: ${filter}`, 'info');
  },
  
  setupSearchSuggestions() {
    // Debounced search suggestions
    let timeout: NodeJS.Timeout;
    
    this.$watch('searchQuery', (query: string) => {
      clearTimeout(timeout);
      
      if (query.length < 2) {
        this.searchSuggestions = [];
        return;
      }
      
      timeout = setTimeout(() => {
        const suggestions = new Set<string>();
        
        // Suggest CVE IDs
        if (query.toLowerCase().startsWith('cve')) {
          this.vulnerabilities
            .filter(v => v.cveId.toLowerCase().includes(query.toLowerCase()))
            .slice(0, 5)
            .forEach(v => suggestions.add(v.cveId));
        }
        
        // Suggest vendors
        this.vulnerabilities.forEach(v => {
          v.vendors?.forEach(vendor => {
            if (vendor.toLowerCase().includes(query.toLowerCase())) {
              suggestions.add(vendor);
            }
          });
        });
        
        this.searchSuggestions = Array.from(suggestions).slice(0, 8);
      }, 300);
    });
  },
  
  hasActiveFilters(): boolean {
    return !!(
      this.searchQuery ||
      this.filters.severity ||
      this.filters.cvssMin > 0 ||
      this.filters.cvssMax < 10 ||
      this.filters.epssMin > 0 ||
      this.filters.epssMax < 100 ||
      this.filters.publishedDateFrom ||
      this.filters.vendor ||
      this.filters.tags.length > 0
    );
  },
  
  getActiveFilters(): Array<{key: string, label: string}> {
    const active = [];
    
    if (this.searchQuery) {
      active.push({ key: 'search', label: `Search: "${this.searchQuery}"` });
    }
    
    if (this.filters.severity) {
      active.push({ key: 'severity', label: `Severity: ${this.filters.severity}` });
    }
    
    if (this.filters.cvssMin > 0 || this.filters.cvssMax < 10) {
      active.push({ key: 'cvss', label: `CVSS: ${this.filters.cvssMin}-${this.filters.cvssMax}` });
    }
    
    if (this.filters.epssMin > 0 || this.filters.epssMax < 100) {
      active.push({ key: 'epss', label: `EPSS: ${this.filters.epssMin}-${this.filters.epssMax}%` });
    }
    
    return active;
  },
  
  removeFilter(key: string) {
    switch (key) {
      case 'search':
        this.searchQuery = '';
        break;
      case 'severity':
        this.filters.severity = '';
        break;
      case 'cvss':
        this.filters.cvssMin = 0;
        this.filters.cvssMax = 10;
        break;
      case 'epss':
        this.filters.epssMin = 0;
        this.filters.epssMax = 100;
        break;
    }
    
    this.applyFilters();
  },
  
  async copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      this.showToast(`Copied: ${text}`, 'success');
    } catch (error) {
      this.showToast('Failed to copy to clipboard', 'error');
    }
  },
  
  showToast(message: string, type: 'success' | 'error' | 'info' = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    // Style the toast
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      z-index: 1000;
      animation: slideIn 0.3s ease;
    `;
    
    // Type-specific colors
    const colors = {
      success: { bg: '#10b981', text: '#ffffff' },
      error: { bg: '#ef4444', text: '#ffffff' },
      info: { bg: '#3b82f6', text: '#ffffff' }
    };
    
    toast.style.backgroundColor = colors[type].bg;
    toast.style.color = colors[type].text;
    
    document.body.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
      toast.style.animation = 'slideOut 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  },
  
  // Extend base methods with enhancements
  applyFilters() {
    // Filter vulnerabilities based on current filters and search
    let results = [...this.vulnerabilities];
    
    // Apply search filter
    if (this.searchQuery) {
      const searchLower = this.searchQuery.toLowerCase();
      results = results.filter(vuln => 
        vuln.cveId.toLowerCase().includes(searchLower) ||
        vuln.title?.toLowerCase().includes(searchLower) ||
        vuln.description?.toLowerCase().includes(searchLower) ||
        vuln.vendors?.some(v => v.toLowerCase().includes(searchLower))
      );
    }
    
    // Apply severity filter
    if (this.filters.severity) {
      results = results.filter(vuln => vuln.severity === this.filters.severity);
    }
    
    // Apply CVSS range
    results = results.filter(vuln => 
      (vuln.cvssScore || 0) >= this.filters.cvssMin &&
      (vuln.cvssScore || 0) <= this.filters.cvssMax
    );
    
    // Apply EPSS range
    results = results.filter(vuln => 
      (vuln.epssPercentile || 0) >= this.filters.epssMin &&
      (vuln.epssPercentile || 0) <= this.filters.epssMax
    );
    
    // Apply date filters
    if (this.filters.publishedDateFrom) {
      results = results.filter(vuln => 
        new Date(vuln.publishedDate) >= new Date(this.filters.publishedDateFrom)
      );
    }
    
    if (this.filters.publishedDateTo) {
      results = results.filter(vuln => 
        new Date(vuln.publishedDate) <= new Date(this.filters.publishedDateTo)
      );
    }
    
    // Apply vendor filter
    if (this.filters.vendor) {
      const vendorLower = this.filters.vendor.toLowerCase();
      results = results.filter(vuln => 
        vuln.vendors?.some(v => v.toLowerCase().includes(vendorLower))
      );
    }
    
    // Apply tag filters
    if (this.filters.tags.length > 0) {
      results = results.filter(vuln => 
        this.filters.tags.every(tag => vuln.tags?.includes(tag))
      );
    }
    
    // Sort results
    results = this.sortResults(results);
    
    this.filteredVulns = results;
    this.updatePagination();
    
    // Update charts
    if (!this.loading) {
      this.$nextTick(() => {
        this.initializeCharts();
      });
    }
  },
  
  formatDate(date: string): string {
    const d = new Date(date);
    const now = new Date();
    const diffTime = Math.abs(now.getTime() - d.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  },
  
  // Sorting methods
  sortResults(results: Vulnerability[]): Vulnerability[] {
    return results.sort((a, b) => {
      const aValue = a[this.sortField];
      const bValue = b[this.sortField];
      
      if (aValue === null || aValue === undefined) return 1;
      if (bValue === null || bValue === undefined) return -1;
      
      const comparison = aValue < bValue ? -1 : aValue > bValue ? 1 : 0;
      return this.sortDirection === 'asc' ? comparison : -comparison;
    });
  },
  
  sort(field: keyof Vulnerability): void {
    if (this.sortField === field) {
      this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortField = field;
      this.sortDirection = 'desc';
    }
    this.applyFilters();
  },
  
  // Pagination methods
  updatePagination(): void {
    this.totalPages = Math.ceil(this.filteredVulns.length / this.pageSize);
    this.currentPage = Math.min(this.currentPage, Math.max(1, this.totalPages));
    
    const start = (this.currentPage - 1) * this.pageSize;
    const end = start + this.pageSize;
    this.paginatedVulns = this.filteredVulns.slice(start, end);
  },
  
  previousPage(): void {
    if (this.currentPage > 1) {
      this.currentPage--;
      this.updatePagination();
    }
  },
  
  nextPage(): void {
    if (this.currentPage < this.totalPages) {
      this.currentPage++;
      this.updatePagination();
    }
  },
  
  // Reset filters
  resetFilters(): void {
    this.searchQuery = '';
    this.filters = {
      cvssMin: 0,
      cvssMax: 10,
      epssMin: 70,
      epssMax: 100,
      severity: '',
      publishedDateFrom: '',
      publishedDateTo: '',
      lastModifiedDateFrom: '',
      lastModifiedDateTo: '',
      dateFrom: '',
      dateTo: '',
      vendor: '',
      tags: []
    };
    this.activeQuickFilter = null;
    this.applyFilters();
  },
  
  // Export functionality
  exportResults(): void {
    const csv = this.generateCSV(this.filteredVulns);
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vulnerabilities-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    
    analytics.track('export_csv', 'export', 'csv', undefined, this.filteredVulns.length);
    this.showToast(`Exported ${this.filteredVulns.length} vulnerabilities`, 'success');
  },
  
  generateCSV(data: Vulnerability[]): string {
    const headers = ['CVE ID', 'Title', 'Severity', 'CVSS Score', 'EPSS %', 'Risk Score', 'Published Date', 'Vendors'];
    const rows = data.map(vuln => [
      vuln.cveId,
      `"${vuln.title.replace(/"/g, '""')}"`,
      vuln.severity,
      vuln.cvssScore || '',
      vuln.epssPercentile || '',
      vuln.riskScore || '',
      vuln.publishedDate,
      `"${(vuln.vendors || []).join(', ')}"`
    ]);
    
    return [headers, ...rows].map(row => row.join(',')).join('\n');
  },
  
  // CVE Modal
  async openCveModal(cveId: string): Promise<void> {
    const modal = document.querySelector('#cve-modal') as any;
    if (modal && modal.__x) {
      await modal.__x.$data.openWithCve(cveId);
    }
  },
  
  // Alpine.js $nextTick
  $nextTick(callback: () => void): void {
    // Will be bound by Alpine.js
    Promise.resolve().then(callback);
  },
  
  // Alpine.js $watch
  $watch(_key: string, _callback: (value: any) => void): void {
    // Will be bound by Alpine.js
  }
  }));
});