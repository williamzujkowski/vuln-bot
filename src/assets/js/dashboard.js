/******/ (() => {
  // webpackBootstrap
  /******/ "use strict";
  /******/ var __webpack_modules__ = {
    /***/ "./src/assets/ts/analytics.ts":
      /*!************************************!*\
  !*** ./src/assets/ts/analytics.ts ***!
  \************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ Analytics: () => /* binding */ Analytics,
          /* harmony export */ analytics: () => /* binding */ analytics,
          /* harmony export */
        });
        /**
         * Frontend analytics for vulnerability dashboard
         */
        class Analytics {
          constructor(
            config = {
              enabled: true,
              storageKey: "vuln_analytics",
              maxEvents: 100,
              flushInterval: 300000,
            }
          ) {
            this.events = [];
            this.enabled = true;
            this.timers = new Map();
            this.config = config;
            this.sessionId = this.generateSessionId();
            this.startTime = Date.now();
            // Check if analytics should be disabled (e.g., DNT header)
            const dnt = navigator.doNotTrack ?? window.doNotTrack;
            if (dnt === "1" || dnt === "yes") {
              this.enabled = false;
              return;
            }
            if (!config.enabled) {
              this.enabled = false;
              return;
            }
            // Load existing events
            this.loadEvents();
            // Set up auto-flush
            if (this.config.flushInterval) {
              this.scheduleFlush();
            }
            // Set up page unload handler to save metrics
            window.addEventListener("beforeunload", () => this.saveEvents());
          }
          generateSessionId() {
            return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
          }
          loadEvents() {
            if (!this.enabled || !this.config.storageKey) return;
            try {
              const stored = localStorage.getItem(this.config.storageKey);
              if (stored) {
                const data = JSON.parse(stored);
                this.events = data.events || [];
              }
            } catch {
              // Ignore errors
            }
          }
          saveEvents() {
            if (!this.enabled || !this.config.storageKey) return;
            const data = {
              events: this.events,
              sessionId: this.sessionId,
              lastFlush: Date.now(),
            };
            try {
              localStorage.setItem(this.config.storageKey, JSON.stringify(data));
            } catch {
              // Ignore errors
            }
          }
          scheduleFlush() {
            if (this.flushTimeout) {
              clearTimeout(this.flushTimeout);
            }
            this.flushTimeout = window.setTimeout(() => {
              this.flush();
              this.scheduleFlush();
            }, this.config.flushInterval);
          }
          isEnabled() {
            return this.enabled;
          }
          disable() {
            this.enabled = false;
          }
          enable() {
            this.enabled = true;
          }
          optOut() {
            this.enabled = false;
            this.clear();
          }
          /**
           * Track a user event
           */
          track(event, category, action, label, value, metadata) {
            if (!this.enabled) return;
            const analyticsEvent = {
              event,
              category,
              action,
              label,
              value,
              metadata,
              timestamp: Date.now(),
            };
            this.events.push(analyticsEvent);
            // Enforce max events limit
            if (this.config.maxEvents && this.events.length > this.config.maxEvents) {
              this.events = this.events.slice(-this.config.maxEvents);
            }
            this.saveEvents();
          }
          getEvents() {
            return [...this.events];
          }
          clear() {
            this.events = [];
            if (this.config.storageKey) {
              localStorage.removeItem(this.config.storageKey);
            }
          }
          // Performance tracking
          startTimer(name) {
            this.timers.set(name, performance.now());
          }
          endTimer(name, metadata) {
            const startTime = this.timers.get(name);
            if (startTime === undefined) return;
            const duration = performance.now() - startTime;
            this.timers.delete(name);
            this.track("timing", "performance", name, undefined, Math.round(duration), metadata);
          }
          // User interaction tracking
          trackVulnerabilityClick(cveId, metadata) {
            this.track("click", "vulnerability", "view", cveId, undefined, metadata);
          }
          trackSearch(query, resultCount) {
            this.track("search", "search", "query", query, resultCount);
          }
          trackFilterUsage(filterType, value, resultCount) {
            this.track("filter", "filter", filterType, value, resultCount);
          }
          trackExport(format, count) {
            this.track("export", "export", "download", format, count);
          }
          trackFilter(filterType, value) {
            this.track("filter_change", "interaction", "filter", filterType, undefined, {
              filterType,
              value,
            });
          }
          // Session tracking
          trackPageView(path) {
            this.track("pageview", "navigation", "view", path);
          }
          startSession() {
            this.sessionStartTime = performance.now();
          }
          endSession() {
            if (this.sessionStartTime === undefined) return;
            const duration = Math.round((performance.now() - this.sessionStartTime) / 1000); // seconds
            this.track("session", "user", "duration", undefined, duration);
            this.sessionStartTime = undefined;
          }
          trackEngagement(data) {
            this.track("engagement", "user", "interaction", undefined, undefined, data);
          }
          // Error tracking
          trackError(error, metadata) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            const errorStack = error instanceof Error ? error.stack : undefined;
            this.track("error", "error", "javascript", errorMessage, undefined, {
              ...metadata,
              stack: errorStack,
            });
          }
          // Data management
          getSummary() {
            const eventCounts = {};
            const categoryCounts = {};
            this.events.forEach((event) => {
              eventCounts[event.event] = (eventCounts[event.event] ?? 0) + 1;
              categoryCounts[event.category] = (categoryCounts[event.category] ?? 0) + 1;
            });
            return {
              totalEvents: this.events.length,
              eventCounts,
              categoryCounts,
              sessionDuration: Date.now() - this.startTime,
            };
          }
          exportJSON() {
            return JSON.stringify(
              {
                events: this.events,
                sessionId: this.sessionId,
                exportDate: new Date().toISOString(),
                version: "1.0.0",
              },
              null,
              2
            );
          }
          async flush() {
            if (!this.enabled || !this.config.endpoint || this.events.length === 0) {
              return;
            }
            try {
              await fetch(this.config.endpoint, {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  events: this.events,
                  sessionId: this.sessionId,
                }),
              });
              // Clear events after successful flush
              this.events = [];
              this.saveEvents();
            } catch (error) {
              // Keep events on error
              console.error("Analytics flush failed:", error);
            }
          }
          /**
           * Export all session data for debugging
           */
          exportSessionData() {
            const sessions = [];
            for (let i = 0; i < localStorage.length; i++) {
              const key = localStorage.key(i);
              if (key?.includes("vuln_analytics")) {
                try {
                  const data = JSON.parse(localStorage.getItem(key) ?? "{}");
                  sessions.push({
                    key,
                    ...data,
                  });
                } catch {
                  // Skip invalid entries
                }
              }
            }
            return JSON.stringify(sessions, null, 2);
          }
        }
        // Export singleton instance
        const analytics = new Analytics();

        /***/
      },

    /***/ "./src/assets/ts/types/alpine.ts":
      /*!***************************************!*\
  !*** ./src/assets/ts/types/alpine.ts ***!
  \***************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /**
         * Alpine.js type extensions
         */

        /***/
      },

    /******/
  };
  /************************************************************************/
  /******/ // The module cache
  /******/ var __webpack_module_cache__ = {};
  /******/
  /******/ // The require function
  /******/ function __webpack_require__(moduleId) {
    /******/ // Check if module is in cache
    /******/ var cachedModule = __webpack_module_cache__[moduleId];
    /******/ if (cachedModule !== undefined) {
      /******/ return cachedModule.exports;
      /******/
    }
    /******/ // Create a new module (and put it into the cache)
    /******/ var module = (__webpack_module_cache__[moduleId] = {
      /******/ // no module.id needed
      /******/ // no module.loaded needed
      /******/ exports: {},
      /******/
    });
    /******/
    /******/ // Execute the module function
    /******/ __webpack_modules__[moduleId](module, module.exports, __webpack_require__);
    /******/
    /******/ // Return the exports of the module
    /******/ return module.exports;
    /******/
  }
  /******/
  /************************************************************************/
  /******/ /* webpack/runtime/define property getters */
  /******/ (() => {
    /******/ // define getter functions for harmony exports
    /******/ __webpack_require__.d = (exports, definition) => {
      /******/ for (var key in definition) {
        /******/ if (
          __webpack_require__.o(definition, key) &&
          !__webpack_require__.o(exports, key)
        ) {
          /******/ Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
          /******/
        }
        /******/
      }
      /******/
    };
    /******/
  })();
  /******/
  /******/ /* webpack/runtime/hasOwnProperty shorthand */
  /******/ (() => {
    /******/ __webpack_require__.o = (obj, prop) => Object.prototype.hasOwnProperty.call(obj, prop);
    /******/
  })();
  /******/
  /******/ /* webpack/runtime/make namespace object */
  /******/ (() => {
    /******/ // define __esModule on exports
    /******/ __webpack_require__.r = (exports) => {
      /******/ if (typeof Symbol !== "undefined" && Symbol.toStringTag) {
        /******/ Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
        /******/
      }
      /******/ Object.defineProperty(exports, "__esModule", { value: true });
      /******/
    };
    /******/
  })();
  /******/
  /************************************************************************/
  var __webpack_exports__ = {};
  // This entry needs to be wrapped in an IIFE because it needs to be isolated against other modules in the chunk.
  (() => {
    /*!************************************!*\
  !*** ./src/assets/ts/dashboard.ts ***!
  \************************************/
    __webpack_require__.r(__webpack_exports__);
    /* harmony import */ var _types_alpine__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(
      /*! ./types/alpine */ "./src/assets/ts/types/alpine.ts"
    );
    /* harmony import */ var _analytics__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(
      /*! ./analytics */ "./src/assets/ts/analytics.ts"
    );
    /**
     * Alpine.js Vulnerability Dashboard - TypeScript Version
     */

    document.addEventListener("alpine:init", () => {
      window.Alpine.data("vulnDashboard", () => ({
        // Data
        vulnerabilities: [],
        filteredVulns: [],
        paginatedVulns: [],
        searchQuery: "",
        fuse: null,
        // Filters
        filters: {
          cvssMin: 0,
          cvssMax: 10,
          epssMin: 0,
          epssMax: 100,
          severity: "",
          dateFrom: "",
          dateTo: "",
          vendor: "",
          exploitationStatus: "",
          tags: [],
        },
        // Sort
        sortField: "exploitationStatus",
        sortDirection: "desc",
        // Pagination
        currentPage: 1,
        pageSize: 50,
        totalPages: 1,
        // State
        loading: true,
        error: null,
        initialLoad: true,
        async init() {
          // Start performance timer
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.startTimer("page-load");
          // Load state from URL hash
          this.loadStateFromHash();
          // Load vulnerability data
          await this.loadVulnerabilities();
          // Set up Fuse.js for fuzzy search
          this.setupSearch();
          // Apply initial filters
          this.applyFilters();
          // Mark initial load as complete
          this.initialLoad = false;
          // Watch for changes
          this.watchFilters();
          // Set up keyboard shortcuts
          this.setupKeyboardShortcuts();
          // Track performance
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.endTimer("page-load");
        },
        async loadVulnerabilities() {
          try {
            this.loading = true;
            this.error = null;
            const response = await fetch("/vuln-bot/api/vulns/index.json");
            if (!response.ok) {
              throw new Error(`Failed to load vulnerabilities: ${response.status}`);
            }
            const data = await response.json();
            this.vulnerabilities = data.vulnerabilities || [];
            this.loading = false;
            // Set up intersection observer for lazy loading
            this.setupLazyLoading();
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : "Unknown error";
            this.error = errorMessage;
            this.loading = false;
            console.error("Failed to load vulnerabilities:", error);
          }
        },
        setupLazyLoading() {
          // Create intersection observer for lazy loading table rows
          if ("IntersectionObserver" in window) {
            const observerOptions = {
              root: null,
              rootMargin: "100px", // Start loading 100px before visible
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
            // Observe vulnerability rows after render
            this.$nextTick(() => {
              document.querySelectorAll(".vulnerability-row[data-lazy]").forEach((row) => {
                lazyLoadObserver.observe(row);
              });
            });
          }
        },
        setupSearch() {
          if (this.vulnerabilities.length === 0) return;
          // Configure Fuse.js for fuzzy search
          const options = {
            keys: ["cveId", "title", "vendors", "products", "tags"],
            threshold: 0.3,
            includeScore: true,
          };
          this.fuse = new window.Fuse(this.vulnerabilities, options);
        },
        applyFilters() {
          // Validate filters first
          if (!this.validateFilters()) {
            return;
          }
          let results = [...this.vulnerabilities];
          // Apply search
          if (this.searchQuery.trim() && this.fuse) {
            const searchResults = this.fuse.search(this.searchQuery);
            results = searchResults.map((result) => result.item);
            // Track search
            _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.trackSearch(
              this.searchQuery,
              results.length
            );
          }
          // Apply CVSS filter
          results = results.filter((vuln) => {
            const score = vuln.cvssScore || 0;
            return score >= this.filters.cvssMin && score <= this.filters.cvssMax;
          });
          // Apply EPSS filter
          results = results.filter((vuln) => {
            const percentile = vuln.epssPercentile || 0;
            return percentile >= this.filters.epssMin && percentile <= this.filters.epssMax;
          });
          // Apply severity filter
          if (this.filters.severity) {
            results = results.filter((vuln) => vuln.severity === this.filters.severity);
          }
          // Apply date filter
          if (this.filters.dateFrom) {
            const fromDate = new Date(this.filters.dateFrom);
            results = results.filter((vuln) => new Date(vuln.publishedDate) >= fromDate);
          }
          if (this.filters.dateTo) {
            const toDate = new Date(this.filters.dateTo);
            results = results.filter((vuln) => new Date(vuln.publishedDate) <= toDate);
          }
          // Apply vendor filter
          if (this.filters.vendor) {
            const vendorLower = this.filters.vendor.toLowerCase();
            results = results.filter((vuln) =>
              vuln.vendors.some((v) => v.toLowerCase().includes(vendorLower))
            );
          }
          // Apply exploitation status filter
          if (this.filters.exploitationStatus) {
            results = results.filter(
              (vuln) => vuln.exploitationStatus === this.filters.exploitationStatus
            );
          }
          // Apply tag filter
          if (this.filters.tags.length > 0) {
            results = results.filter((vuln) =>
              this.filters.tags.every((tag) => vuln.tags.includes(tag))
            );
          }
          // Apply sorting
          results = this.sortResults(results);
          this.filteredVulns = results;
          this.updatePagination();
          this.saveStateToHash();
          // Announce results to screen readers
          this.announceFilterResults();
        },
        announceFilterResults() {
          const resultCount = this.filteredVulns.length;
          const totalCount = this.vulnerabilities.length;
          let announcement = `Showing ${resultCount} of ${totalCount} vulnerabilities`;
          // Add filter context
          const activeFilters = [];
          if (this.searchQuery) activeFilters.push(`matching "${this.searchQuery}"`);
          if (this.filters.severity) activeFilters.push(`severity: ${this.filters.severity}`);
          if (this.filters.cvssMin > 0 || this.filters.cvssMax < 10) {
            activeFilters.push(`CVSS: ${this.filters.cvssMin}-${this.filters.cvssMax}`);
          }
          if (this.filters.epssMin > 0 || this.filters.epssMax < 100) {
            activeFilters.push(`EPSS: ${this.filters.epssMin}%-${this.filters.epssMax}%`);
          }
          if (this.filters.vendor) activeFilters.push(`vendor: ${this.filters.vendor}`);
          if (this.filters.exploitationStatus) {
            activeFilters.push(`exploitation: ${this.filters.exploitationStatus}`);
          }
          if (this.filters.tags.length > 0) {
            activeFilters.push(`tags: ${this.filters.tags.join(", ")}`);
          }
          if (activeFilters.length > 0) {
            announcement += ` with filters: ${activeFilters.join(", ")}`;
          }
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
          // Update announcement
          liveRegion.textContent = announcement;
        },
        validateFilters() {
          const errors = [];
          // Validate CVSS range
          if (this.filters.cvssMin > this.filters.cvssMax) {
            errors.push("CVSS minimum score cannot be greater than maximum");
          }
          // Validate EPSS range
          if (this.filters.epssMin > this.filters.epssMax) {
            errors.push("EPSS minimum score cannot be greater than maximum");
          }
          // Validate date range
          if (this.filters.dateFrom && this.filters.dateTo) {
            const fromDate = new Date(this.filters.dateFrom);
            const toDate = new Date(this.filters.dateTo);
            if (fromDate > toDate) {
              errors.push("Start date cannot be after end date");
            }
          }
          // Show errors
          if (errors.length > 0) {
            this.showValidationErrors(errors);
            return false;
          }
          return true;
        },
        showValidationErrors(errors) {
          // Create or update error region
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
          // Build error list
          errorRegion.innerHTML = `
          <h3>Validation Errors</h3>
          <ul>
            ${errors.map((error) => `<li>${error}</li>`).join("")}
          </ul>
        `;
          // Focus on first error
          errorRegion.focus();
          // Clear errors after 5 seconds
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
            // Handle null/undefined values
            aVal ?? (aVal = "");
            bVal ?? (bVal = "");
            // Handle dates
            if (typeof field === "string" && field.includes("Date")) {
              aVal = new Date(aVal).getTime();
              bVal = new Date(bVal).getTime();
            }
            // Compare
            if (aVal < bVal) return direction === "asc" ? -1 : 1;
            if (aVal > bVal) return direction === "asc" ? 1 : -1;
            return 0;
          });
        },
        sort(field) {
          if (this.sortField === field) {
            // Toggle direction
            this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
          } else {
            // New field, default to descending
            this.sortField = field;
            this.sortDirection = "desc";
          }
          // Track sort change
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.track(
            "sort",
            "interaction",
            "sort",
            field,
            undefined,
            {
              direction: this.sortDirection,
            }
          );
          this.applyFilters();
        },
        updatePagination() {
          this.totalPages = Math.ceil(this.filteredVulns.length / this.pageSize);
          this.currentPage = Math.min(this.currentPage, Math.max(1, this.totalPages));
          const start = (this.currentPage - 1) * this.pageSize;
          const end = start + this.pageSize;
          this.paginatedVulns = this.filteredVulns.slice(start, end);
          // Set up lazy loading for new rows after pagination
          this.$nextTick(() => {
            this.setupLazyLoading();
          });
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
          // Watch for filter changes
          this.$watch("searchQuery", () => this.applyFilters());
          this.$watch("filters", () => this.applyFilters(), {
            deep: true,
          });
          this.$watch("pageSize", () => {
            this.currentPage = 1;
            this.updatePagination();
          });
        },
        saveStateToHash() {
          // Don't save state during initial load
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
            dateFrom: this.filters.dateFrom,
            dateTo: this.filters.dateTo,
            vendor: this.filters.vendor,
            exploitation: this.filters.exploitationStatus,
            tags: this.filters.tags.join(","),
            sort: this.sortField,
            dir: this.sortDirection,
            page: this.currentPage,
            size: this.pageSize,
          };
          // Remove empty values and defaults
          Object.keys(state).forEach((key) => {
            const value = state[key];
            if (
              !value ||
              value === "" ||
              (key === "cvssMin" && value === 0) ||
              (key === "cvssMax" && value === 10) ||
              (key === "epssMin" && value === 0) ||
              (key === "epssMax" && value === 100) ||
              (key === "page" && value === 1) ||
              (key === "size" && value === 20) ||
              (key === "sort" && value === "exploitationStatus") ||
              (key === "dir" && value === "desc")
            ) {
              delete state[key];
            }
          });
          const hash = new URLSearchParams(
            Object.fromEntries(Object.entries(state).map(([k, v]) => [k, String(v)]))
          ).toString();
          window.location.hash = hash;
        },
        loadStateFromHash() {
          const hash = window.location.hash.slice(1);
          if (!hash) return;
          const params = new URLSearchParams(hash);
          // Load search query
          this.searchQuery = params.get("q") ?? "";
          // Load filters
          this.filters.cvssMin = parseFloat(params.get("cvssMin") ?? "0");
          this.filters.cvssMax = parseFloat(params.get("cvssMax") ?? "10");
          this.filters.epssMin = parseInt(params.get("epssMin") ?? "0");
          this.filters.epssMax = parseInt(params.get("epssMax") ?? "100");
          this.filters.severity = params.get("severity") ?? "";
          this.filters.dateFrom = params.get("dateFrom") ?? "";
          this.filters.dateTo = params.get("dateTo") ?? "";
          this.filters.vendor = params.get("vendor") ?? "";
          this.filters.exploitationStatus = params.get("exploitation") ?? "";
          const tags = params.get("tags");
          this.filters.tags = tags ? tags.split(",").filter((t) => t) : [];
          // Load sorting
          this.sortField = params.get("sort") ?? "exploitationStatus";
          this.sortDirection = params.get("dir") ?? "desc";
          // Load pagination
          this.currentPage = parseInt(params.get("page") ?? "1");
          this.pageSize = parseInt(params.get("size") ?? "20");
        },
        getSeverityClass(score) {
          if (score >= 9) return "severity-critical";
          if (score >= 7) return "severity-high";
          if (score >= 4) return "severity-medium";
          if (score > 0) return "severity-low";
          return "severity-none";
        },
        formatDate(dateStr) {
          const date = new Date(dateStr);
          return date.toLocaleDateString("en-US", {
            year: "numeric",
            month: "short",
            day: "numeric",
          });
        },
        resetFilters() {
          this.searchQuery = "";
          this.filters = {
            cvssMin: 0,
            cvssMax: 10,
            epssMin: 0,
            epssMax: 100,
            severity: "",
            dateFrom: "",
            dateTo: "",
            vendor: "",
            exploitationStatus: "",
            tags: [],
          };
          this.currentPage = 1;
          this.applyFilters();
        },
        exportResults() {
          // Track export
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.trackExport(
            "csv",
            this.filteredVulns.length
          );
          // Create CSV content
          const headers = [
            "CVE ID",
            "Title",
            "Exploitation Status",
            "Severity",
            "CVSS Score",
            "EPSS %",
            "Published Date",
          ];
          const rows = this.filteredVulns.map((vuln) => [
            vuln.cveId,
            `"${vuln.title.replace(/"/g, '""')}"`,
            vuln.exploitationStatus,
            vuln.severity,
            vuln.cvssScore?.toString() || "",
            vuln.epssPercentile?.toString() || "",
            vuln.publishedDate,
          ]);
          const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
          // Download CSV
          const blob = new Blob([csv], { type: "text/csv" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`;
          a.click();
          URL.revokeObjectURL(url);
        },
        trackVulnerabilityClick(cveId, riskScore) {
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.trackVulnerabilityClick(cveId, {
            riskScore,
          });
        },
        setupKeyboardShortcuts() {
          document.addEventListener("keydown", (event) => {
            // Ignore if user is typing in an input field
            if (
              event.target instanceof HTMLInputElement ||
              event.target instanceof HTMLTextAreaElement
            ) {
              return;
            }
            // Keyboard shortcuts
            switch (event.key) {
              case "/":
                // Focus search input
                event.preventDefault();
                const searchInput = document.getElementById("search-input");
                searchInput?.focus();
                break;
              case "r":
                // Reset filters
                if (!event.ctrlKey && !event.metaKey) {
                  event.preventDefault();
                  this.resetFilters();
                }
                break;
              case "e":
                // Export results
                if (!event.ctrlKey && !event.metaKey) {
                  event.preventDefault();
                  this.exportResults();
                }
                break;
              case "ArrowLeft":
                // Previous page
                if (!event.ctrlKey && !event.metaKey && !event.shiftKey) {
                  event.preventDefault();
                  this.previousPage();
                }
                break;
              case "ArrowRight":
                // Next page
                if (!event.ctrlKey && !event.metaKey && !event.shiftKey) {
                  event.preventDefault();
                  this.nextPage();
                }
                break;
              case "?":
                // Show help
                event.preventDefault();
                this.showKeyboardHelp();
                break;
              case "Escape":
                // Close help modal if open
                const helpModal = document.getElementById("keyboard-help-modal");
                if (helpModal && !helpModal.classList.contains("hidden")) {
                  event.preventDefault();
                  helpModal.classList.add("hidden");
                }
                break;
            }
            // Number keys for page size
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
            // Create help modal
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
          // Focus the close button for accessibility
          const closeButton = helpModal.querySelector(".modal-close");
          closeButton?.focus();
          // Track help usage
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.track(
            "keyboard-help",
            "interaction",
            "help",
            "show"
          );
        },
        $nextTick(callback) {
          // This method is provided by Alpine.js at runtime
          // @ts-ignore
          this.$nextTick(callback);
        },
      }));
    });
  })();

  /******/
})();
//# sourceMappingURL=dashboard.js.map
