(() => {
  "use strict";
  document.addEventListener("alpine:init", () => {
    window.Alpine.data("vulnDashboard", () => ({
      vulnerabilities: [],
      filteredVulns: [],
      paginatedVulns: [],
      searchQuery: "",
      fuse: null,
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
      sortField: "riskScore",
      sortDirection: "desc",
      currentPage: 1,
      pageSize: 20,
      totalPages: 1,
      loading: !0,
      error: null,
      initialLoad: !0,
      async init() {
        (this.loadStateFromHash(),
          await this.loadVulnerabilities(),
          this.setupSearch(),
          this.applyFilters(),
          (this.initialLoad = !1),
          this.watchFilters());
      },
      async loadVulnerabilities() {
        try {
          ((this.loading = !0), (this.error = null));
          const t = await fetch("/vuln-bot/api/vulns/index.json");
          if (!t.ok) throw new Error(`Failed to load vulnerabilities: ${t.status}`);
          const e = await t.json();
          ((this.vulnerabilities = e.vulnerabilities || []), (this.loading = !1));
        } catch (t) {
          const e = t instanceof Error ? t.message : "Unknown error";
          ((this.error = e),
            (this.loading = !1),
            console.error("Failed to load vulnerabilities:", t));
        }
      },
      setupSearch() {
        0 !== this.vulnerabilities.length &&
          (this.fuse = new window.Fuse(this.vulnerabilities, {
            keys: ["cveId", "title", "vendors", "products", "tags"],
            threshold: 0.3,
            includeScore: !0,
          }));
      },
      applyFilters() {
        let t = [...this.vulnerabilities];
        if (
          (this.searchQuery.trim() &&
            this.fuse &&
            (t = this.fuse.search(this.searchQuery).map((t) => t.item)),
          (t = t.filter((t) => {
            const e = t.cvssScore || 0;
            return e >= this.filters.cvssMin && e <= this.filters.cvssMax;
          })),
          (t = t.filter((t) => {
            const e = t.epssScore || 0;
            return e >= this.filters.epssMin && e <= this.filters.epssMax;
          })),
          this.filters.severity && (t = t.filter((t) => t.severity === this.filters.severity)),
          this.filters.dateFrom)
        ) {
          const e = new Date(this.filters.dateFrom);
          t = t.filter((t) => new Date(t.publishedDate) >= e);
        }
        if (this.filters.dateTo) {
          const e = new Date(this.filters.dateTo);
          t = t.filter((t) => new Date(t.publishedDate) <= e);
        }
        if (this.filters.vendor) {
          const e = this.filters.vendor.toLowerCase();
          t = t.filter((t) => t.vendors.some((t) => t.toLowerCase().includes(e)));
        }
        (this.filters.exploitationStatus &&
          (t = t.filter((t) => t.exploitationStatus === this.filters.exploitationStatus)),
          this.filters.tags.length > 0 &&
            (t = t.filter((t) => this.filters.tags.every((e) => t.tags.includes(e)))),
          (t = this.sortResults(t)),
          (this.filteredVulns = t),
          this.updatePagination(),
          this.saveStateToHash());
      },
      sortResults(t) {
        const e = this.sortField,
          s = this.sortDirection;
        return t.sort((t, i) => {
          let r = t[e],
            a = i[e];
          return (
            r ?? (r = ""),
            a ?? (a = ""),
            "string" == typeof e &&
              e.includes("Date") &&
              ((r = new Date(r).getTime()), (a = new Date(a).getTime())),
            r < a ? ("asc" === s ? -1 : 1) : r > a ? ("asc" === s ? 1 : -1) : 0
          );
        });
      },
      sort(t) {
        (this.sortField === t
          ? (this.sortDirection = "asc" === this.sortDirection ? "desc" : "asc")
          : ((this.sortField = t), (this.sortDirection = "desc")),
          this.applyFilters());
      },
      updatePagination() {
        ((this.totalPages = Math.ceil(this.filteredVulns.length / this.pageSize)),
          (this.currentPage = Math.min(this.currentPage, Math.max(1, this.totalPages))));
        const t = (this.currentPage - 1) * this.pageSize,
          e = t + this.pageSize;
        this.paginatedVulns = this.filteredVulns.slice(t, e);
      },
      previousPage() {
        this.currentPage > 1 && (this.currentPage--, this.updatePagination());
      },
      nextPage() {
        this.currentPage < this.totalPages && (this.currentPage++, this.updatePagination());
      },
      watchFilters() {
        (this.$watch("searchQuery", () => this.applyFilters()),
          this.$watch("filters", () => this.applyFilters(), { deep: !0 }),
          this.$watch("pageSize", () => {
            ((this.currentPage = 1), this.updatePagination());
          }));
      },
      saveStateToHash() {
        if (this.loading || 0 === this.vulnerabilities.length || this.initialLoad) return;
        const t = {
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
        Object.keys(t).forEach((e) => {
          const s = t[e];
          (!s ||
            "" === s ||
            ("cvssMin" === e && 0 === s) ||
            ("cvssMax" === e && 10 === s) ||
            ("epssMin" === e && 0 === s) ||
            ("epssMax" === e && 100 === s) ||
            ("page" === e && 1 === s) ||
            ("size" === e && 20 === s) ||
            ("sort" === e && "riskScore" === s) ||
            ("dir" === e && "desc" === s)) &&
            delete t[e];
        });
        const e = new URLSearchParams(
          Object.fromEntries(Object.entries(t).map(([t, e]) => [t, String(e)]))
        ).toString();
        window.location.hash = e;
      },
      loadStateFromHash() {
        const t = window.location.hash.slice(1);
        if (!t) return;
        const e = new URLSearchParams(t);
        ((this.searchQuery = e.get("q") ?? ""),
          (this.filters.cvssMin = parseFloat(e.get("cvssMin") ?? "0")),
          (this.filters.cvssMax = parseFloat(e.get("cvssMax") ?? "10")),
          (this.filters.epssMin = parseInt(e.get("epssMin") ?? "0")),
          (this.filters.epssMax = parseInt(e.get("epssMax") ?? "100")),
          (this.filters.severity = e.get("severity") ?? ""),
          (this.filters.dateFrom = e.get("dateFrom") ?? ""),
          (this.filters.dateTo = e.get("dateTo") ?? ""),
          (this.filters.vendor = e.get("vendor") ?? ""),
          (this.filters.exploitationStatus = e.get("exploitation") ?? ""));
        const s = e.get("tags");
        ((this.filters.tags = s ? s.split(",").filter((t) => t) : []),
          (this.sortField = e.get("sort") ?? "riskScore"),
          (this.sortDirection = e.get("dir") ?? "desc"),
          (this.currentPage = parseInt(e.get("page") ?? "1")),
          (this.pageSize = parseInt(e.get("size") ?? "20")));
      },
      getSeverityClass: (t) =>
        t >= 9
          ? "severity-critical"
          : t >= 7
            ? "severity-high"
            : t >= 4
              ? "severity-medium"
              : t > 0
                ? "severity-low"
                : "severity-none",
      formatDate: (t) =>
        new Date(t).toLocaleDateString("en-US", {
          year: "numeric",
          month: "short",
          day: "numeric",
        }),
      resetFilters() {
        ((this.searchQuery = ""),
          (this.filters = {
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
          }),
          (this.currentPage = 1),
          this.applyFilters());
      },
      exportResults() {
        const t = [
            ["CVE ID", "Title", "Risk Score", "Severity", "CVSS Score", "EPSS %", "Published Date"],
            ...this.filteredVulns.map((t) => [
              t.cveId,
              `"${t.title.replace(/"/g, '""')}"`,
              t.riskScore.toString(),
              t.severity,
              t.cvssScore?.toString() || "",
              t.epssScore?.toString() || "",
              t.publishedDate,
            ]),
          ]
            .map((t) => t.join(","))
            .join("\n"),
          e = new Blob([t], { type: "text/csv" }),
          s = URL.createObjectURL(e),
          i = document.createElement("a");
        ((i.href = s),
          (i.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`),
          i.click(),
          URL.revokeObjectURL(s));
      },
    }));
  });
})();
//# sourceMappingURL=dashboard.js.map
