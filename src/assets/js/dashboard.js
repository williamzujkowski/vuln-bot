(() => {
  "use strict";
  const t = new (class {
    constructor(
      t = { enabled: !0, storageKey: "vuln_analytics", maxEvents: 100, flushInterval: 3e5 }
    ) {
      ((this.events = []),
        (this.enabled = !0),
        (this.timers = new Map()),
        (this.config = t),
        (this.sessionId = this.generateSessionId()),
        (this.startTime = Date.now()));
      const e = navigator.doNotTrack ?? window.doNotTrack;
      "1" !== e && "yes" !== e && t.enabled
        ? (this.loadEvents(),
          this.config.flushInterval && this.scheduleFlush(),
          window.addEventListener("beforeunload", () => this.saveEvents()))
        : (this.enabled = !1);
    }
    generateSessionId() {
      return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
    loadEvents() {
      if (this.enabled && this.config.storageKey)
        try {
          const t = localStorage.getItem(this.config.storageKey);
          if (t) {
            const e = JSON.parse(t);
            this.events = e.events || [];
          }
        } catch {}
    }
    saveEvents() {
      if (!this.enabled || !this.config.storageKey) return;
      const t = { events: this.events, sessionId: this.sessionId, lastFlush: Date.now() };
      try {
        localStorage.setItem(this.config.storageKey, JSON.stringify(t));
      } catch {}
    }
    scheduleFlush() {
      (this.flushTimeout && clearTimeout(this.flushTimeout),
        (this.flushTimeout = window.setTimeout(() => {
          (this.flush(), this.scheduleFlush());
        }, this.config.flushInterval)));
    }
    isEnabled() {
      return this.enabled;
    }
    disable() {
      this.enabled = !1;
    }
    enable() {
      this.enabled = !0;
    }
    optOut() {
      ((this.enabled = !1), this.clear());
    }
    track(t, e, s, i, r, a) {
      if (!this.enabled) return;
      const n = {
        event: t,
        category: e,
        action: s,
        label: i,
        value: r,
        metadata: a,
        timestamp: Date.now(),
      };
      (this.events.push(n),
        this.config.maxEvents &&
          this.events.length > this.config.maxEvents &&
          (this.events = this.events.slice(-this.config.maxEvents)),
        this.saveEvents());
    }
    getEvents() {
      return [...this.events];
    }
    clear() {
      ((this.events = []),
        this.config.storageKey && localStorage.removeItem(this.config.storageKey));
    }
    startTimer(t) {
      this.timers.set(t, performance.now());
    }
    endTimer(t, e) {
      const s = this.timers.get(t);
      if (void 0 === s) return;
      const i = performance.now() - s;
      (this.timers.delete(t), this.track("timing", "performance", t, void 0, Math.round(i), e));
    }
    trackVulnerabilityClick(t, e) {
      this.track("click", "vulnerability", "view", t, void 0, e);
    }
    trackSearch(t, e) {
      this.track("search", "search", "query", t, e);
    }
    trackFilterUsage(t, e, s) {
      this.track("filter", "filter", t, e, s);
    }
    trackExport(t, e) {
      this.track("export", "export", "download", t, e);
    }
    trackFilter(t, e) {
      this.track("filter_change", "interaction", "filter", t, void 0, { filterType: t, value: e });
    }
    trackPageView(t) {
      this.track("pageview", "navigation", "view", t);
    }
    startSession() {
      this.sessionStartTime = performance.now();
    }
    endSession() {
      if (void 0 === this.sessionStartTime) return;
      const t = Math.round((performance.now() - this.sessionStartTime) / 1e3);
      (this.track("session", "user", "duration", void 0, t), (this.sessionStartTime = void 0));
    }
    trackEngagement(t) {
      this.track("engagement", "user", "interaction", void 0, void 0, t);
    }
    trackError(t, e) {
      const s = t instanceof Error ? t.message : String(t),
        i = t instanceof Error ? t.stack : void 0;
      this.track("error", "error", "javascript", s, void 0, { ...e, stack: i });
    }
    getSummary() {
      const t = {},
        e = {};
      return (
        this.events.forEach((s) => {
          ((t[s.event] = (t[s.event] ?? 0) + 1), (e[s.category] = (e[s.category] ?? 0) + 1));
        }),
        {
          totalEvents: this.events.length,
          eventCounts: t,
          categoryCounts: e,
          sessionDuration: Date.now() - this.startTime,
        }
      );
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
      if (this.enabled && this.config.endpoint && 0 !== this.events.length)
        try {
          (await fetch(this.config.endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ events: this.events, sessionId: this.sessionId }),
          }),
            (this.events = []),
            this.saveEvents());
        } catch (t) {
          console.error("Analytics flush failed:", t);
        }
    }
    exportSessionData() {
      const t = [];
      for (let e = 0; e < localStorage.length; e++) {
        const s = localStorage.key(e);
        if (s?.includes("vuln_analytics"))
          try {
            const e = JSON.parse(localStorage.getItem(s) ?? "{}");
            t.push({ key: s, ...e });
          } catch {}
      }
      return JSON.stringify(t, null, 2);
    }
  })();
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
      sortField: "exploitationStatus",
      sortDirection: "desc",
      currentPage: 1,
      pageSize: 20,
      totalPages: 1,
      loading: !0,
      error: null,
      initialLoad: !0,
      async init() {
        (t.startTimer("page-load"),
          this.loadStateFromHash(),
          await this.loadVulnerabilities(),
          this.setupSearch(),
          this.applyFilters(),
          (this.initialLoad = !1),
          this.watchFilters(),
          t.endTimer("page-load"));
      },
      async loadVulnerabilities() {
        try {
          ((this.loading = !0), (this.error = null));
          const t = await fetch("/vuln-bot/api/vulns/index.json");
          if (!t.ok) throw new Error(`Failed to load vulnerabilities: ${t.status}`);
          const e = await t.json();
          ((this.vulnerabilities = e.vulnerabilities || []),
            (this.loading = !1),
            this.setupLazyLoading());
        } catch (t) {
          const e = t instanceof Error ? t.message : "Unknown error";
          ((this.error = e),
            (this.loading = !1),
            console.error("Failed to load vulnerabilities:", t));
        }
      },
      setupLazyLoading() {
        if ("IntersectionObserver" in window) {
          const t = new IntersectionObserver(
            (e) => {
              e.forEach((e) => {
                if (e.isIntersecting) {
                  const s = e.target;
                  (s.classList.add("loaded"), t.unobserve(s));
                }
              });
            },
            { root: null, rootMargin: "100px", threshold: 0.01 }
          );
          this.$nextTick(() => {
            document.querySelectorAll(".vulnerability-row[data-lazy]").forEach((e) => {
              t.observe(e);
            });
          });
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
        if (!this.validateFilters()) return;
        let e = [...this.vulnerabilities];
        if (
          (this.searchQuery.trim() &&
            this.fuse &&
            ((e = this.fuse.search(this.searchQuery).map((t) => t.item)),
            t.trackSearch(this.searchQuery, e.length)),
          (e = e.filter((t) => {
            const e = t.cvssScore || 0;
            return e >= this.filters.cvssMin && e <= this.filters.cvssMax;
          })),
          (e = e.filter((t) => {
            const e = t.epssPercentile || 0;
            return e >= this.filters.epssMin && e <= this.filters.epssMax;
          })),
          this.filters.severity && (e = e.filter((t) => t.severity === this.filters.severity)),
          this.filters.dateFrom)
        ) {
          const t = new Date(this.filters.dateFrom);
          e = e.filter((e) => new Date(e.publishedDate) >= t);
        }
        if (this.filters.dateTo) {
          const t = new Date(this.filters.dateTo);
          e = e.filter((e) => new Date(e.publishedDate) <= t);
        }
        if (this.filters.vendor) {
          const t = this.filters.vendor.toLowerCase();
          e = e.filter((e) => e.vendors.some((e) => e.toLowerCase().includes(t)));
        }
        (this.filters.exploitationStatus &&
          (e = e.filter((t) => t.exploitationStatus === this.filters.exploitationStatus)),
          this.filters.tags.length > 0 &&
            (e = e.filter((t) => this.filters.tags.every((e) => t.tags.includes(e)))),
          (e = this.sortResults(e)),
          (this.filteredVulns = e),
          this.updatePagination(),
          this.saveStateToHash(),
          this.announceFilterResults());
      },
      announceFilterResults() {
        let t = `Showing ${this.filteredVulns.length} of ${this.vulnerabilities.length} vulnerabilities`;
        const e = [];
        (this.searchQuery && e.push(`matching "${this.searchQuery}"`),
          this.filters.severity && e.push(`severity: ${this.filters.severity}`),
          (this.filters.cvssMin > 0 || this.filters.cvssMax < 10) &&
            e.push(`CVSS: ${this.filters.cvssMin}-${this.filters.cvssMax}`),
          (this.filters.epssMin > 0 || this.filters.epssMax < 100) &&
            e.push(`EPSS: ${this.filters.epssMin}%-${this.filters.epssMax}%`),
          this.filters.vendor && e.push(`vendor: ${this.filters.vendor}`),
          this.filters.exploitationStatus &&
            e.push(`exploitation: ${this.filters.exploitationStatus}`),
          this.filters.tags.length > 0 && e.push(`tags: ${this.filters.tags.join(", ")}`),
          e.length > 0 && (t += ` with filters: ${e.join(", ")}`));
        let s = document.getElementById("filter-announcement");
        (s ||
          ((s = document.createElement("div")),
          (s.id = "filter-announcement"),
          (s.className = "sr-only"),
          s.setAttribute("role", "status"),
          s.setAttribute("aria-live", "polite"),
          s.setAttribute("aria-atomic", "true"),
          document.body.appendChild(s)),
          (s.textContent = t));
      },
      validateFilters() {
        const t = [];
        return (
          this.filters.cvssMin > this.filters.cvssMax &&
            t.push("CVSS minimum score cannot be greater than maximum"),
          this.filters.epssMin > this.filters.epssMax &&
            t.push("EPSS minimum score cannot be greater than maximum"),
          this.filters.dateFrom &&
            this.filters.dateTo &&
            new Date(this.filters.dateFrom) > new Date(this.filters.dateTo) &&
            t.push("Start date cannot be after end date"),
          !(t.length > 0 && (this.showValidationErrors(t), 1))
        );
      },
      showValidationErrors(t) {
        let e = document.getElementById("validation-errors");
        if (!e) {
          ((e = document.createElement("div")),
            (e.id = "validation-errors"),
            (e.className = "validation-errors"),
            e.setAttribute("role", "alert"),
            e.setAttribute("aria-live", "assertive"));
          const t = document.getElementById("search-filters");
          t?.insertBefore(e, t.firstChild);
        }
        ((e.innerHTML = `\n          <h3>Validation Errors</h3>\n          <ul>\n            ${t.map((t) => `<li>${t}</li>`).join("")}\n          </ul>\n        `),
          e.focus(),
          setTimeout(() => {
            e.innerHTML = "";
          }, 5e3));
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
      sort(e) {
        (this.sortField === e
          ? (this.sortDirection = "asc" === this.sortDirection ? "desc" : "asc")
          : ((this.sortField = e), (this.sortDirection = "desc")),
          t.track("sort", "interaction", "sort", e, void 0, { direction: this.sortDirection }),
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
            ("sort" === e && "exploitationStatus" === s) ||
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
          (this.sortField = e.get("sort") ?? "exploitationStatus"),
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
        t.trackExport("csv", this.filteredVulns.length);
        const e = [
            [
              "CVE ID",
              "Title",
              "Exploitation Status",
              "Severity",
              "CVSS Score",
              "EPSS %",
              "Published Date",
            ],
            ...this.filteredVulns.map((t) => [
              t.cveId,
              `"${t.title.replace(/"/g, '""')}"`,
              t.exploitationStatus,
              t.severity,
              t.cvssScore?.toString() || "",
              t.epssPercentile?.toString() || "",
              t.publishedDate,
            ]),
          ]
            .map((t) => t.join(","))
            .join("\n"),
          s = new Blob([e], { type: "text/csv" }),
          i = URL.createObjectURL(s),
          r = document.createElement("a");
        ((r.href = i),
          (r.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`),
          r.click(),
          URL.revokeObjectURL(i));
      },
      trackVulnerabilityClick(e, s) {
        t.trackVulnerabilityClick(e, { riskScore: s });
      },
      $nextTick(t) {
        this.$nextTick(t);
      },
    }));
  });
})();
//# sourceMappingURL=dashboard.js.map
