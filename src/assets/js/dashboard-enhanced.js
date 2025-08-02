/**
 * Optimized Alpine.js Vulnerability Dashboard with Performance Enhancements
 */
import "./types/alpine";
import { analytics } from "./analytics";
import { createCveModal } from "./components/CveModal";
import { createSavedSearchComponent, SavedSearches } from "./components/SavedSearches";
// Web Worker for off-thread filtering
let filterWorker = null;
// Memoization helper
function memoize(fn) {
    const cache = new Map();
    return ((...args) => {
        const key = JSON.stringify(args);
        if (cache.has(key)) {
            return cache.get(key);
        }
        const result = fn(...args);
        cache.set(key, result);
        return result;
    });
}
document.addEventListener("alpine:init", () => {
    // Register CVE Modal component
    window.Alpine.data("cveModal", createCveModal);
    // Register Saved Search component
    window.Alpine.data("savedSearches", createSavedSearchComponent);
    window.Alpine.data("vulnDashboard", () => ({
        // Data
        vulnerabilities: [],
        filteredVulns: [],
        paginatedVulns: [],
        virtualVulns: [],
        searchQuery: "",
        fuse: null,
        // Filters
        filters: {
            cvssMin: 0,
            cvssMax: 10,
            epssMin: 50, // Default to 50% exploitation probability threshold
            epssMax: 100,
            severity: "",
            publishedDateFrom: "",
            publishedDateTo: "",
            lastModifiedDateFrom: "",
            lastModifiedDateTo: "",
            dateFrom: "",
            dateTo: "",
            vendor: "",
            tags: [],
        },
        // Sort
        sortField: "epssPercentile",
        sortDirection: "desc",
        // Pagination
        currentPage: 1,
        pageSize: 50,
        totalPages: 1,
        // Virtual Scrolling
        virtualScrolling: {
            enabled: false,
            itemHeight: 48,
            containerHeight: 600,
            scrollTop: 0,
            startIndex: 0,
            endIndex: 50,
            topSpacerHeight: 0,
            bottomSpacerHeight: 0,
            bufferSize: 10,
        },
        // State
        loading: true,
        error: null,
        initialLoad: true,
        // Performance
        searchDebounceTimer: null,
        filterCache: new Map(),
        memoizedComputations: new Map(),
        // Modal
        modal: createCveModal(),
        // Saved Searches
        savedSearches: new SavedSearches(),
        // References
        $refs: {},
        // Helper function to get date string for n days ago
        getDateDaysAgo: memoize((days) => {
            const date = new Date();
            date.setDate(date.getDate() - days);
            return date.toISOString().split("T")[0];
        }),
        // Helper function to set default date ranges
        setDefaultDateRanges() {
            if (!this.filters.publishedDateFrom && !this.filters.dateFrom) {
                this.filters.publishedDateFrom = this.getDateDaysAgo(90);
                this.filters.publishedDateTo = "";
            }
        },
        async init() {
            // Start performance timer
            analytics.startTimer("page-load");
            // Initialize Web Worker for filtering
            this.initializeWebWorker();
            // Load state from URL hash
            this.loadStateFromHash();
            // Set default date ranges if not loaded from hash
            this.setDefaultDateRanges();
            // Load vulnerability data with lazy loading
            await this.loadVulnerabilities();
            // Set up Fuse.js for fuzzy search
            this.setupSearch();
            // Apply initial filters
            await this.applyFilters();
            // Enable virtual scrolling for large datasets
            if (this.vulnerabilities.length > 500) {
                this.virtualScrolling.enabled = true;
            }
            // Mark initial load as complete
            this.initialLoad = false;
            // Watch for changes
            this.watchFilters();
            // Set up keyboard shortcuts
            this.setupKeyboardShortcuts();
            // Make modal available globally for CVE links
            window.cveModal = this.modal;
            // Track performance
            analytics.endTimer("page-load");
        },
        initializeWebWorker() {
            if (typeof Worker !== "undefined") {
                try {
                    // Create inline worker for filtering
                    const workerCode = `
              self.addEventListener('message', function(e) {
                const { vulnerabilities, filters, searchQuery } = e.data;
                let results = [...vulnerabilities];

                // Apply search filter
                if (searchQuery) {
                  const searchLower = searchQuery.toLowerCase();
                  results = results.filter(vuln => 
                    vuln.cveId.toLowerCase().includes(searchLower) ||
                    vuln.title?.toLowerCase().includes(searchLower) ||
                    vuln.vendors?.some(v => v.toLowerCase().includes(searchLower)) ||
                    vuln.products?.some(p => p.toLowerCase().includes(searchLower))
                  );
                }

                // Apply CVSS filter
                results = results.filter(vuln => {
                  const score = vuln.cvssScore || 0;
                  return score >= filters.cvssMin && score <= filters.cvssMax;
                });

                // Apply EPSS filter
                results = results.filter(vuln => {
                  const percentile = vuln.epssPercentile || 0;
                  return percentile >= filters.epssMin && percentile <= filters.epssMax;
                });

                // Apply severity filter
                if (filters.severity) {
                  results = results.filter(vuln => vuln.severity === filters.severity);
                }

                // Apply date filters
                if (filters.publishedDateFrom) {
                  const fromDate = new Date(filters.publishedDateFrom);
                  results = results.filter(vuln => new Date(vuln.publishedDate) >= fromDate);
                }

                if (filters.publishedDateTo) {
                  const toDate = new Date(filters.publishedDateTo);
                  toDate.setHours(23, 59, 59, 999);
                  results = results.filter(vuln => new Date(vuln.publishedDate) <= toDate);
                }

                // Apply vendor filter
                if (filters.vendor) {
                  const vendorLower = filters.vendor.toLowerCase();
                  results = results.filter(vuln =>
                    vuln.vendors.some(v => v.toLowerCase().includes(vendorLower))
                  );
                }

                // Apply tag filter
                if (filters.tags.length > 0) {
                  results = results.filter(vuln =>
                    filters.tags.every(tag => vuln.tags.includes(tag))
                  );
                }

                self.postMessage(results);
              });
            `;
                    const blob = new Blob([workerCode], { type: "application/javascript" });
                    const workerUrl = URL.createObjectURL(blob);
                    filterWorker = new Worker(workerUrl);
                }
                catch (error) {
                    console.warn("Failed to create Web Worker:", error);
                }
            }
        },
        async loadVulnerabilities() {
            try {
                this.loading = true;
                this.error = null;
                // Check cache first
                const cachedData = sessionStorage.getItem("vuln-data");
                const cacheTimestamp = sessionStorage.getItem("vuln-data-timestamp");
                const cacheAge = cacheTimestamp ? Date.now() - parseInt(cacheTimestamp) : Infinity;
                // Use cache if less than 5 minutes old
                if (cachedData && cacheAge < 5 * 60 * 1000) {
                    const data = JSON.parse(cachedData);
                    this.vulnerabilities = data.vulnerabilities || [];
                    this.loading = false;
                    return;
                }
                const response = await fetch("/vuln-bot/api/vulns/index.json");
                if (!response.ok) {
                    throw new Error(`Failed to load vulnerabilities: ${response.status}`);
                }
                const data = await response.json();
                this.vulnerabilities = data.vulnerabilities || [];
                // Add index for virtual scrolling
                this.vulnerabilities.forEach((vuln, index) => {
                    vuln._index = index;
                });
                // Cache the data
                sessionStorage.setItem("vuln-data", JSON.stringify(data));
                sessionStorage.setItem("vuln-data-timestamp", Date.now().toString());
                this.loading = false;
                // Set up lazy loading
                this.setupLazyLoading();
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : "Unknown error";
                this.error = errorMessage;
                this.loading = false;
                console.error("Failed to load vulnerabilities:", error);
            }
        },
        setupLazyLoading() {
            if ("IntersectionObserver" in window) {
                const observerOptions = {
                    root: null,
                    rootMargin: "100px",
                    threshold: 0.01,
                };
                const lazyLoadObserver = new IntersectionObserver((entries) => {
                    entries.forEach((entry) => {
                        if (entry.isIntersecting) {
                            const element = entry.target;
                            element.classList.add("loaded");
                            lazyLoadObserver.unobserve(element);
                        }
                    });
                }, observerOptions);
                // Use requestAnimationFrame for smooth updates
                requestAnimationFrame(() => {
                    document.querySelectorAll(".vulnerability-row[data-lazy]").forEach((row) => {
                        lazyLoadObserver.observe(row);
                    });
                });
            }
        },
        setupSearch() {
            if (this.vulnerabilities.length === 0)
                return;
            // Configure Fuse.js for fuzzy search
            const options = {
                keys: ["cveId", "title", "vendors", "products", "tags"],
                threshold: 0.3,
                includeScore: true,
            };
            this.fuse = new window.Fuse(this.vulnerabilities, options);
        },
        getCacheKey() {
            return JSON.stringify({
                search: this.searchQuery,
                filters: this.filters,
                sort: { field: this.sortField, direction: this.sortDirection },
            });
        },
        async applyFilters() {
            // Check cache first
            const cacheKey = this.getCacheKey();
            if (this.filterCache.has(cacheKey)) {
                this.filteredVulns = this.filterCache.get(cacheKey);
                this.updatePagination();
                this.saveStateToHash();
                this.announceFilterResults();
                return;
            }
            // Use Web Worker if available
            if (filterWorker && this.vulnerabilities.length > 100) {
                await this.applyFiltersWithWorker();
            }
            else {
                // Fallback to main thread filtering
                this.applyFiltersMainThread();
            }
            // Cache results
            if (this.filteredVulns.length < 1000) {
                this.filterCache.set(cacheKey, [...this.filteredVulns]);
            }
            // Clean up old cache entries
            if (this.filterCache.size > 50) {
                const firstKey = this.filterCache.keys().next().value;
                if (firstKey !== undefined) {
                    this.filterCache.delete(firstKey);
                }
            }
        },
        async applyFiltersWithWorker() {
            return new Promise((resolve) => {
                if (!filterWorker) {
                    this.applyFiltersMainThread();
                    resolve();
                    return;
                }
                filterWorker.onmessage = (e) => {
                    let results = e.data;
                    results = this.sortResults(results);
                    this.filteredVulns = results;
                    this.updatePagination();
                    this.saveStateToHash();
                    this.announceFilterResults();
                    resolve();
                };
                filterWorker.postMessage({
                    vulnerabilities: this.vulnerabilities,
                    filters: this.filters,
                    searchQuery: this.searchQuery,
                });
            });
        },
        applyFiltersMainThread() {
            if (!this.validateFilters()) {
                return;
            }
            let results = [...this.vulnerabilities];
            // Apply search with Fuse.js
            if (this.searchQuery.trim() && this.fuse) {
                const searchResults = this.fuse.search(this.searchQuery);
                results = searchResults.map((result) => result.item);
                analytics.trackSearch(this.searchQuery, results.length);
                this.savedSearches.addRecentSearch(this.searchQuery);
            }
            // Batch filter operations
            results = results.filter((vuln) => {
                // CVSS filter
                const score = vuln.cvssScore || 0;
                if (score < this.filters.cvssMin || score > this.filters.cvssMax)
                    return false;
                // EPSS filter
                const percentile = vuln.epssPercentile || 0;
                if (percentile < this.filters.epssMin || percentile > this.filters.epssMax)
                    return false;
                // Severity filter
                if (this.filters.severity && vuln.severity !== this.filters.severity)
                    return false;
                // Date filters
                const publishedFrom = this.filters.publishedDateFrom || this.filters.dateFrom;
                if (publishedFrom && new Date(vuln.publishedDate) < new Date(publishedFrom))
                    return false;
                const publishedTo = this.filters.publishedDateTo || this.filters.dateTo;
                if (publishedTo) {
                    const toDate = new Date(publishedTo);
                    toDate.setHours(23, 59, 59, 999);
                    if (new Date(vuln.publishedDate) > toDate)
                        return false;
                }
                // Vendor filter
                if (this.filters.vendor) {
                    const vendorLower = this.filters.vendor.toLowerCase();
                    if (!vuln.vendors.some((v) => v.toLowerCase().includes(vendorLower)))
                        return false;
                }
                // Tag filter
                if (this.filters.tags.length > 0) {
                    if (!this.filters.tags.every((tag) => vuln.tags.includes(tag)))
                        return false;
                }
                return true;
            });
            // Apply sorting
            results = this.sortResults(results);
            this.filteredVulns = results;
            this.updatePagination();
            this.saveStateToHash();
            this.announceFilterResults();
        },
        announceFilterResults() {
            const resultCount = this.filteredVulns.length;
            const totalCount = this.vulnerabilities.length;
            let announcement = `Showing ${resultCount} of ${totalCount} vulnerabilities`;
            // Create or update live region
            let liveRegion = document.getElementById("filter-announcement");
            if (!liveRegion) {
                liveRegion = document.createElement("div");
                liveRegion.id = "filter-announcement";
                liveRegion.className = "sr-only";
                liveRegion.setAttribute("role", "status");
                liveRegion.setAttribute("aria-live", "polite");
                liveRegion.setAttribute("aria-atomic", "true");
                document.body.appendChild(liveRegion);
            }
            liveRegion.textContent = announcement;
        },
        validateFilters() {
            const errors = [];
            if (this.filters.cvssMin > this.filters.cvssMax) {
                errors.push("CVSS minimum score cannot be greater than maximum");
            }
            if (this.filters.epssMin > this.filters.epssMax) {
                errors.push("EPSS minimum score cannot be greater than maximum");
            }
            const publishedFrom = this.filters.publishedDateFrom || this.filters.dateFrom;
            const publishedTo = this.filters.publishedDateTo || this.filters.dateTo;
            if (publishedFrom && publishedTo) {
                const fromDate = new Date(publishedFrom);
                const toDate = new Date(publishedTo);
                if (fromDate > toDate) {
                    errors.push("Published start date cannot be after end date");
                }
            }
            if (errors.length > 0) {
                this.showValidationErrors(errors);
                return false;
            }
            return true;
        },
        showValidationErrors(errors) {
            let errorRegion = document.getElementById("validation-errors");
            if (!errorRegion) {
                errorRegion = document.createElement("div");
                errorRegion.id = "validation-errors";
                errorRegion.className = "validation-errors";
                errorRegion.setAttribute("role", "alert");
                errorRegion.setAttribute("aria-live", "assertive");
                const filterSection = document.getElementById("search-filters");
                filterSection?.insertBefore(errorRegion, filterSection.firstChild);
            }
            errorRegion.innerHTML = `
          <h3>Validation Errors</h3>
          <ul>
            ${errors.map((error) => `<li>${error}</li>`).join("")}
          </ul>
        `;
            errorRegion.focus();
            setTimeout(() => {
                errorRegion.innerHTML = "";
            }, 5000);
        },
        sortResults(results) {
            const field = this.sortField;
            const direction = this.sortDirection;
            return results.sort((a, b) => {
                let aVal = a[field];
                let bVal = b[field];
                aVal ?? (aVal = "");
                bVal ?? (bVal = "");
                if (typeof field === "string" && field.includes("Date")) {
                    aVal = new Date(aVal).getTime();
                    bVal = new Date(bVal).getTime();
                }
                if (aVal < bVal)
                    return direction === "asc" ? -1 : 1;
                if (aVal > bVal)
                    return direction === "asc" ? 1 : -1;
                return 0;
            });
        },
        sort(field) {
            if (this.sortField === field) {
                this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
            }
            else {
                this.sortField = field;
                this.sortDirection = "desc";
            }
            analytics.track("sort", "interaction", "sort", field, undefined, {
                direction: this.sortDirection,
            });
            this.applyFilters();
        },
        updatePagination() {
            if (this.virtualScrolling.enabled) {
                this.calculateVirtualWindow();
            }
            else {
                this.totalPages = Math.ceil(this.filteredVulns.length / this.pageSize);
                this.currentPage = Math.min(this.currentPage, Math.max(1, this.totalPages));
                const start = (this.currentPage - 1) * this.pageSize;
                const end = start + this.pageSize;
                this.paginatedVulns = this.filteredVulns.slice(start, end);
            }
            // Set up lazy loading for new rows
            requestAnimationFrame(() => {
                this.setupLazyLoading();
            });
        },
        handleVirtualScroll() {
            if (!this.virtualScrolling.enabled || !this.$refs.tableWrapper)
                return;
            // Debounce scroll events
            if (this.searchDebounceTimer) {
                cancelAnimationFrame(this.searchDebounceTimer);
            }
            this.searchDebounceTimer = requestAnimationFrame(() => {
                this.virtualScrolling.scrollTop = this.$refs.tableWrapper.scrollTop;
                this.calculateVirtualWindow();
            });
        },
        calculateVirtualWindow() {
            const { itemHeight, containerHeight, scrollTop, bufferSize } = this.virtualScrolling;
            const totalItems = this.filteredVulns.length;
            // Calculate visible range
            const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - bufferSize);
            const endIndex = Math.min(totalItems, Math.ceil((scrollTop + containerHeight) / itemHeight) + bufferSize);
            // Update virtual window
            this.virtualScrolling.startIndex = startIndex;
            this.virtualScrolling.endIndex = endIndex;
            this.virtualScrolling.topSpacerHeight = startIndex * itemHeight;
            this.virtualScrolling.bottomSpacerHeight = (totalItems - endIndex) * itemHeight;
            // Extract visible items
            this.virtualVulns = this.filteredVulns.slice(startIndex, endIndex);
        },
        previousPage() {
            if (this.currentPage > 1) {
                this.currentPage--;
                this.updatePagination();
            }
        },
        nextPage() {
            if (this.currentPage < this.totalPages) {
                this.currentPage++;
                this.updatePagination();
            }
        },
        watchFilters() {
            // Debounced search watching
            this.$watch("searchQuery", () => {
                if (this.searchDebounceTimer) {
                    clearTimeout(this.searchDebounceTimer);
                }
                this.searchDebounceTimer = window.setTimeout(() => {
                    this.applyFilters();
                }, 300);
            });
            this.$watch("filters", () => this.applyFilters(), {
                deep: true,
            });
            this.$watch("pageSize", () => {
                this.currentPage = 1;
                this.updatePagination();
            });
        },
        saveStateToHash() {
            if (this.loading || this.vulnerabilities.length === 0 || this.initialLoad) {
                return;
            }
            const state = {
                q: this.searchQuery,
                cvssMin: this.filters.cvssMin,
                cvssMax: this.filters.cvssMax,
                epssMin: this.filters.epssMin,
                epssMax: this.filters.epssMax,
                severity: this.filters.severity,
                publishedDateFrom: this.filters.publishedDateFrom,
                publishedDateTo: this.filters.publishedDateTo,
                vendor: this.filters.vendor,
                tags: this.filters.tags.join(","),
                sort: this.sortField,
                dir: this.sortDirection,
                page: this.currentPage,
                size: this.pageSize,
            };
            // Remove empty values and defaults
            Object.keys(state).forEach((key) => {
                const value = state[key];
                if (!value ||
                    value === "" ||
                    (key === "cvssMin" && value === 0) ||
                    (key === "cvssMax" && value === 10) ||
                    (key === "epssMin" && value === 50) || // Don't include default 50% threshold
                    (key === "epssMax" && value === 100) ||
                    (key === "page" && value === 1) ||
                    (key === "size" && value === 50) ||
                    (key === "sort" && value === "epssPercentile") ||
                    (key === "dir" && value === "desc")) {
                    delete state[key];
                }
            });
            const hash = new URLSearchParams(Object.fromEntries(Object.entries(state).map(([k, v]) => [k, String(v)]))).toString();
            window.location.hash = hash;
        },
        loadStateFromHash() {
            const hash = window.location.hash.slice(1);
            if (!hash)
                return;
            const params = new URLSearchParams(hash);
            this.searchQuery = params.get("q") ?? "";
            this.filters.cvssMin = parseFloat(params.get("cvssMin") ?? "0");
            this.filters.cvssMax = parseFloat(params.get("cvssMax") ?? "10");
            this.filters.epssMin = parseInt(params.get("epssMin") ?? "50"); // Default to 50% threshold
            this.filters.epssMax = parseInt(params.get("epssMax") ?? "100");
            this.filters.severity = (params.get("severity") ?? "");
            this.filters.publishedDateFrom = params.get("publishedDateFrom") ?? "";
            this.filters.publishedDateTo = params.get("publishedDateTo") ?? "";
            this.filters.vendor = params.get("vendor") ?? "";
            const tags = params.get("tags");
            this.filters.tags = tags ? tags.split(",").filter((t) => t) : [];
            this.sortField = (params.get("sort") ?? "epssPercentile");
            this.sortDirection = (params.get("dir") ?? "desc");
            this.currentPage = parseInt(params.get("page") ?? "1");
            this.pageSize = parseInt(params.get("size") ?? "50");
        },
        getSeverityClass: memoize((score) => {
            if (score >= 9)
                return "severity-critical";
            if (score >= 7)
                return "severity-high";
            if (score >= 4)
                return "severity-medium";
            if (score > 0)
                return "severity-low";
            return "severity-none";
        }),
        formatDate: memoize((dateStr) => {
            const date = new Date(dateStr);
            return date.toLocaleDateString("en-US", {
                year: "numeric",
                month: "short",
                day: "numeric",
            });
        }),
        resetFilters() {
            this.searchQuery = "";
            this.filters = {
                cvssMin: 0,
                cvssMax: 10,
                epssMin: 50, // Reset to 50% threshold
                epssMax: 100,
                severity: "",
                publishedDateFrom: "",
                publishedDateTo: "",
                lastModifiedDateFrom: "",
                lastModifiedDateTo: "",
                dateFrom: "",
                dateTo: "",
                vendor: "",
                tags: [],
            };
            this.currentPage = 1;
            this.applyFilters();
        },
        exportResults() {
            analytics.trackExport("csv", this.filteredVulns.length);
            const headers = ["CVE ID", "Title", "Severity", "CVSS Score", "EPSS %", "Published Date"];
            const rows = this.filteredVulns.map((vuln) => [
                vuln.cveId,
                `"${vuln.title.replace(/"/g, '""')}"`,
                vuln.severity,
                vuln.cvssScore?.toString() || "",
                vuln.epssPercentile?.toString() || "",
                vuln.publishedDate,
            ]);
            const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
            const blob = new Blob([csv], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        },
        trackVulnerabilityClick(cveId, riskScore) {
            analytics.trackVulnerabilityClick(cveId, { riskScore });
        },
        async openCveModal(cveId) {
            await this.modal.openModal(cveId);
        },
        setupKeyboardShortcuts() {
            document.addEventListener("keydown", (event) => {
                if (event.target instanceof HTMLInputElement ||
                    event.target instanceof HTMLTextAreaElement) {
                    return;
                }
                switch (event.key) {
                    case "/":
                        event.preventDefault();
                        const searchInput = document.getElementById("search-input");
                        searchInput?.focus();
                        break;
                    case "r":
                        if (!event.ctrlKey && !event.metaKey) {
                            event.preventDefault();
                            this.resetFilters();
                        }
                        break;
                    case "e":
                        if (!event.ctrlKey && !event.metaKey) {
                            event.preventDefault();
                            this.exportResults();
                        }
                        break;
                    case "ArrowLeft":
                        if (!event.ctrlKey && !event.metaKey && !event.shiftKey) {
                            event.preventDefault();
                            this.previousPage();
                        }
                        break;
                    case "ArrowRight":
                        if (!event.ctrlKey && !event.metaKey && !event.shiftKey) {
                            event.preventDefault();
                            this.nextPage();
                        }
                        break;
                    case "?":
                        event.preventDefault();
                        this.showKeyboardHelp();
                        break;
                    case "Escape":
                        const helpModal = document.getElementById("keyboard-help-modal");
                        if (helpModal && !helpModal.classList.contains("hidden")) {
                            event.preventDefault();
                            helpModal.classList.add("hidden");
                        }
                        break;
                }
                if (event.key >= "1" && event.key <= "4" && !event.ctrlKey && !event.metaKey) {
                    event.preventDefault();
                    const pageSizes = [10, 20, 50, 100];
                    const index = parseInt(event.key) - 1;
                    if (index < pageSizes.length && pageSizes[index] !== undefined) {
                        this.pageSize = pageSizes[index];
                    }
                }
            });
        },
        showKeyboardHelp() {
            let helpModal = document.getElementById("keyboard-help-modal");
            if (!helpModal) {
                helpModal = document.createElement("div");
                helpModal.id = "keyboard-help-modal";
                helpModal.className = "modal-backdrop";
                helpModal.innerHTML = `
              <div class="modal-content" role="dialog" 
                   aria-labelledby="keyboard-help-title" aria-modal="true">
                <h2 id="keyboard-help-title">Keyboard Shortcuts</h2>
                <button class="modal-close" aria-label="Close help modal"
                        onclick="document.getElementById('keyboard-help-modal')
                                 .classList.add('hidden')">
                  ×
                </button>
                <dl class="keyboard-shortcuts">
                  <dt><kbd>/</kbd></dt>
                  <dd>Focus search input</dd>
                  
                  <dt><kbd>r</kbd></dt>
                  <dd>Reset all filters</dd>
                  
                  <dt><kbd>e</kbd></dt>
                  <dd>Export results as CSV</dd>
                  
                  <dt><kbd>←</kbd> <kbd>→</kbd></dt>
                  <dd>Navigate between pages</dd>
                  
                  <dt><kbd>1</kbd> - <kbd>4</kbd></dt>
                  <dd>Set page size (10, 20, 50, 100)</dd>
                  
                  <dt><kbd>?</kbd></dt>
                  <dd>Show this help</dd>
                  
                  <dt><kbd>Esc</kbd></dt>
                  <dd>Close this help</dd>
                </dl>
              </div>
            `;
                document.body.appendChild(helpModal);
            }
            helpModal.classList.remove("hidden");
            const closeButton = helpModal.querySelector(".modal-close");
            closeButton?.focus();
            analytics.track("keyboard-help", "interaction", "help", "show");
        },
        $nextTick(callback) {
            // This method is provided by Alpine.js at runtime
            // @ts-ignore
            this.$nextTick(callback);
        },
    }));
});
// Clean up on page unload
window.addEventListener("beforeunload", () => {
    if (filterWorker) {
        filterWorker.terminate();
    }
});
//# sourceMappingURL=dashboard.js.map