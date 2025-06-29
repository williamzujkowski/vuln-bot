/**
 * Alpine.js Vulnerability Dashboard - TypeScript Version
 */

import type {
  Vulnerability,
  VulnerabilityResponse,
  SeverityLevel,
  ExploitationStatus,
} from "./types/vulnerability";
import "./types/alpine";
import { analytics } from "./analytics";

type Fuse<T> = import("fuse.js").default<T>;

interface VulnDashboard {
  // Data
  vulnerabilities: Vulnerability[];
  filteredVulns: Vulnerability[];
  paginatedVulns: Vulnerability[];
  searchQuery: string;
  fuse: Fuse<Vulnerability> | null;

  // Filters
  filters: {
    cvssMin: number;
    cvssMax: number;
    epssMin: number;
    epssMax: number;
    severity: SeverityLevel | "";
    dateFrom: string;
    dateTo: string;
    vendor: string;
    exploitationStatus: ExploitationStatus | "";
    tags: string[];
  };

  // Sort
  sortField: keyof Vulnerability;
  sortDirection: "asc" | "desc";

  // Pagination
  currentPage: number;
  pageSize: number;
  totalPages: number;

  // State
  loading: boolean;
  error: string | null;
  initialLoad: boolean;

  // Methods
  init(): Promise<void>;
  loadVulnerabilities(): Promise<void>;
  setupLazyLoading(): void;
  setupSearch(): void;
  applyFilters(): void;
  validateFilters(): boolean;
  announceFilterResults(): void;
  showValidationErrors(errors: string[]): void;
  sortResults(results: Vulnerability[]): Vulnerability[];
  sort(field: keyof Vulnerability): void;
  updatePagination(): void;
  previousPage(): void;
  nextPage(): void;
  watchFilters(): void;
  saveStateToHash(): void;
  loadStateFromHash(): void;
  getSeverityClass(score: number): string;
  formatDate(dateStr: string): string;
  resetFilters(): void;
  exportResults(): void;
  trackVulnerabilityClick(cveId: string, riskScore: number): void;
  setupKeyboardShortcuts(): void;
  showKeyboardHelp(): void;
  $nextTick(callback: () => void): void;
}

document.addEventListener("alpine:init", () => {
  window.Alpine.data(
    "vulnDashboard",
    (): VulnDashboard => ({
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

      async init(): Promise<void> {
        // Start performance timer
        analytics.startTimer("page-load");

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
        analytics.endTimer("page-load");
      },

      async loadVulnerabilities(): Promise<void> {
        try {
          this.loading = true;
          this.error = null;

          const response = await fetch("/vuln-bot/api/vulns/index.json");
          if (!response.ok) {
            throw new Error(`Failed to load vulnerabilities: ${response.status}`);
          }

          const data: VulnerabilityResponse = await response.json();
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

      setupLazyLoading(): void {
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
                const element = entry.target as HTMLElement;
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

      setupSearch(): void {
        if (this.vulnerabilities.length === 0) return;

        // Configure Fuse.js for fuzzy search
        const options = {
          keys: ["cveId", "title", "vendors", "products", "tags"],
          threshold: 0.3,
          includeScore: true,
        };

        this.fuse = new window.Fuse(this.vulnerabilities, options);
      },

      applyFilters(): void {
        // Validate filters first
        if (!this.validateFilters()) {
          return;
        }

        let results: Vulnerability[] = [...this.vulnerabilities];

        // Apply search
        if (this.searchQuery.trim() && this.fuse) {
          const searchResults = this.fuse.search(this.searchQuery);
          results = searchResults.map((result: { item: Vulnerability }) => result.item);

          // Track search
          analytics.trackSearch(this.searchQuery, results.length);
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

      announceFilterResults(): void {
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

      validateFilters(): boolean {
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

      showValidationErrors(errors: string[]): void {
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

      sortResults(results: Vulnerability[]): Vulnerability[] {
        const field = this.sortField;
        const direction = this.sortDirection;

        return results.sort((a, b) => {
          let aVal: string | number = a[field] as string | number;
          let bVal: string | number = b[field] as string | number;

          // Handle null/undefined values
          aVal ??= "";
          bVal ??= "";

          // Handle dates
          if (typeof field === "string" && field.includes("Date")) {
            aVal = new Date(aVal as string).getTime();
            bVal = new Date(bVal as string).getTime();
          }

          // Compare
          if (aVal < bVal) return direction === "asc" ? -1 : 1;
          if (aVal > bVal) return direction === "asc" ? 1 : -1;
          return 0;
        });
      },

      sort(field: keyof Vulnerability): void {
        if (this.sortField === field) {
          // Toggle direction
          this.sortDirection = this.sortDirection === "asc" ? "desc" : "asc";
        } else {
          // New field, default to descending
          this.sortField = field;
          this.sortDirection = "desc";
        }

        // Track sort change
        analytics.track("sort", "interaction", "sort", field, undefined, {
          direction: this.sortDirection,
        });

        this.applyFilters();
      },

      updatePagination(): void {
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

      watchFilters(): void {
        // Watch for filter changes
        (this as unknown as { $watch: Function }).$watch("searchQuery", () => this.applyFilters());
        (this as unknown as { $watch: Function }).$watch("filters", () => this.applyFilters(), {
          deep: true,
        });
        (this as unknown as { $watch: Function }).$watch("pageSize", () => {
          this.currentPage = 1;
          this.updatePagination();
        });
      },

      saveStateToHash(): void {
        // Don't save state during initial load
        if (this.loading || this.vulnerabilities.length === 0 || this.initialLoad) {
          return;
        }

        const state: Record<string, string | number> = {
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

      loadStateFromHash(): void {
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
        this.filters.severity = (params.get("severity") ?? "") as SeverityLevel | "";
        this.filters.dateFrom = params.get("dateFrom") ?? "";
        this.filters.dateTo = params.get("dateTo") ?? "";
        this.filters.vendor = params.get("vendor") ?? "";
        this.filters.exploitationStatus = (params.get("exploitation") ?? "") as
          | ExploitationStatus
          | "";

        const tags = params.get("tags");
        this.filters.tags = tags ? tags.split(",").filter((t) => t) : [];

        // Load sorting
        this.sortField = (params.get("sort") ?? "exploitationStatus") as keyof Vulnerability;
        this.sortDirection = (params.get("dir") ?? "desc") as "asc" | "desc";

        // Load pagination
        this.currentPage = parseInt(params.get("page") ?? "1");
        this.pageSize = parseInt(params.get("size") ?? "20");
      },

      getSeverityClass(score: number): string {
        if (score >= 9) return "severity-critical";
        if (score >= 7) return "severity-high";
        if (score >= 4) return "severity-medium";
        if (score > 0) return "severity-low";
        return "severity-none";
      },

      formatDate(dateStr: string): string {
        const date = new Date(dateStr);
        return date.toLocaleDateString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric",
        });
      },

      resetFilters(): void {
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

      exportResults(): void {
        // Track export
        analytics.trackExport("csv", this.filteredVulns.length);

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

      trackVulnerabilityClick(cveId: string, riskScore: number): void {
        analytics.trackVulnerabilityClick(cveId, { riskScore });
      },

      setupKeyboardShortcuts(): void {
        document.addEventListener("keydown", (event: KeyboardEvent) => {
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
              const searchInput = document.getElementById("search-input") as HTMLInputElement;
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
              this.pageSize = pageSizes[index]!;
            }
          }
        });
      },

      showKeyboardHelp(): void {
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
        const closeButton = helpModal.querySelector(".modal-close") as HTMLButtonElement;
        closeButton?.focus();

        // Track help usage
        analytics.track("keyboard-help", "interaction", "help", "show");
      },

      $nextTick(callback: () => void): void {
        // This method is provided by Alpine.js at runtime
        // @ts-ignore
        this.$nextTick(callback);
      },
    })
  );
});
