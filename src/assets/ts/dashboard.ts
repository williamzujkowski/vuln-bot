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
  setupSearch(): void;
  applyFilters(): void;
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
      sortField: "riskScore",
      sortDirection: "desc",

      // Pagination
      currentPage: 1,
      pageSize: 20,
      totalPages: 1,

      // State
      loading: true,
      error: null,
      initialLoad: true,

      async init(): Promise<void> {
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
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : "Unknown error";
          this.error = errorMessage;
          this.loading = false;
          console.error("Failed to load vulnerabilities:", error);
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
        let results: Vulnerability[] = [...this.vulnerabilities];

        // Apply search
        if (this.searchQuery.trim() && this.fuse) {
          const searchResults = this.fuse.search(this.searchQuery);
          results = searchResults.map((result: any) => result.item);
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

      sortResults(results: Vulnerability[]): Vulnerability[] {
        const field = this.sortField;
        const direction = this.sortDirection;

        return results.sort((a, b) => {
          let aVal = a[field] as unknown;
          let bVal = b[field] as unknown;

          // Handle null/undefined values
          aVal ??= "";
          bVal ??= "";

          // Handle dates
          if (typeof field === "string" && field.includes("Date")) {
            aVal = new Date(aVal as string).getTime();
            bVal = new Date(bVal as string).getTime();
          }

          // Compare
          if ((aVal as any) < (bVal as any)) return direction === "asc" ? -1 : 1;
          if ((aVal as any) > (bVal as any)) return direction === "asc" ? 1 : -1;
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

        this.applyFilters();
      },

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

      watchFilters(): void {
        // Watch for filter changes
        (this as any).$watch("searchQuery", () => this.applyFilters());
        (this as any).$watch("filters", () => this.applyFilters(), { deep: true });
        (this as any).$watch("pageSize", () => {
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
            (key === "sort" && value === "riskScore") ||
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
        this.sortField = (params.get("sort") ?? "riskScore") as keyof Vulnerability;
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
          vuln.riskScore.toString(),
          vuln.severity,
          vuln.cvssScore?.toString() || "",
          vuln.epssScore?.toString() || "",
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
    })
  );
});
