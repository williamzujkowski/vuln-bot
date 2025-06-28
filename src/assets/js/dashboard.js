/**
 * Alpine.js Vulnerability Dashboard
 */

document.addEventListener("alpine:init", () => {
  Alpine.data("vulnDashboard", () => ({
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

    // Pagination
    currentPage: 1,
    pageSize: 20,
    totalPages: 1,

    // Sorting
    sortField: "riskScore",
    sortDirection: "desc",

    // State
    loading: true,
    error: null,
    initialLoad: true,

    async init() {
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
    },

    async loadVulnerabilities() {
      try {
        this.loading = true;
        const response = await fetch("/vuln-bot/api/vulns/index.json");
        if (!response.ok) {
          throw new Error(`Failed to load vulnerabilities: ${response.status}`);
        }

        const data = await response.json();
        this.vulnerabilities = data.vulnerabilities || [];
        this.loading = false;
      } catch (error) {
        this.error = error.message;
        this.loading = false;
        console.error("Failed to load vulnerabilities:", error);
      }
    },

    setupSearch() {
      // Configure Fuse.js for fuzzy search
      const options = {
        keys: ["cveId", "title", "vendors", "products", "tags"],
        threshold: 0.3,
        includeScore: true,
      };

      this.fuse = new Fuse(this.vulnerabilities, options);
    },

    applyFilters() {
      let results = [...this.vulnerabilities];

      // Apply search
      if (this.searchQuery.trim()) {
        const searchResults = this.fuse.search(this.searchQuery);
        results = searchResults.map((result) => result.item);
      }

      // Apply CVSS filter
      results = results.filter((vuln) => {
        const score = vuln.cvssScore || 0;
        return score >= this.filters.cvssMin && score <= this.filters.cvssMax;
      });

      // Apply EPSS filter
      results = results.filter((vuln) => {
        const score = vuln.epssScore || 0;
        return score >= this.filters.epssMin && score <= this.filters.epssMax;
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
    },

    sortResults(results) {
      const field = this.sortField;
      const direction = this.sortDirection;

      return results.sort((a, b) => {
        let aVal = a[field];
        let bVal = b[field];

        // Handle null/undefined values
        if (aVal == null) aVal = "";
        if (bVal == null) bVal = "";

        // Handle dates
        if (field.includes("Date")) {
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

      this.applyFilters();
    },

    updatePagination() {
      this.totalPages = Math.ceil(this.filteredVulns.length / this.pageSize);
      this.currentPage = Math.min(this.currentPage, Math.max(1, this.totalPages));

      const start = (this.currentPage - 1) * this.pageSize;
      const end = start + this.pageSize;
      this.paginatedVulns = this.filteredVulns.slice(start, end);
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
      this.$watch("filters", () => this.applyFilters(), { deep: true });
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
        if (
          !state[key] ||
          state[key] === "" ||
          (key === "cvssMin" && state[key] === 0) ||
          (key === "cvssMax" && state[key] === 10) ||
          (key === "epssMin" && state[key] === 0) ||
          (key === "epssMax" && state[key] === 100) ||
          (key === "page" && state[key] === 1) ||
          (key === "size" && state[key] === 20) ||
          (key === "sort" && state[key] === "riskScore") ||
          (key === "dir" && state[key] === "desc")
        ) {
          delete state[key];
        }
      });

      const hash = new URLSearchParams(state).toString();
      window.location.hash = hash;
    },

    loadStateFromHash() {
      const hash = window.location.hash.slice(1);
      if (!hash) return;

      const params = new URLSearchParams(hash);

      // Load search query
      this.searchQuery = params.get("q") || "";

      // Load filters
      this.filters.cvssMin = parseFloat(params.get("cvssMin") || 0);
      this.filters.cvssMax = parseFloat(params.get("cvssMax") || 10);
      this.filters.epssMin = parseInt(params.get("epssMin") || 0);
      this.filters.epssMax = parseInt(params.get("epssMax") || 100);
      this.filters.severity = params.get("severity") || "";
      this.filters.dateFrom = params.get("dateFrom") || "";
      this.filters.dateTo = params.get("dateTo") || "";
      this.filters.vendor = params.get("vendor") || "";
      this.filters.exploitationStatus = params.get("exploitation") || "";

      const tags = params.get("tags");
      this.filters.tags = tags ? tags.split(",").filter((t) => t) : [];

      // Load sorting
      this.sortField = params.get("sort") || "riskScore";
      this.sortDirection = params.get("dir") || "desc";

      // Load pagination
      this.currentPage = parseInt(params.get("page") || 1);
      this.pageSize = parseInt(params.get("size") || 20);
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
      // Create CSV content
      const headers = [
        "CVE ID",
        "Title",
        "Risk Score",
        "Severity",
        "CVSS Score",
        "EPSS %",
        "Published Date",
      ];
      const rows = this.filteredVulns.map((vuln) => [
        vuln.cveId,
        `"${vuln.title.replace(/"/g, '""')}"`,
        vuln.riskScore,
        vuln.severity,
        vuln.cvssScore || "",
        vuln.epssScore || "",
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
  }));
});
