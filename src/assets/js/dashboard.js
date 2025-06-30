(() => {
  "use strict";
  const e = new (class {
    constructor(
      e = { enabled: !0, storageKey: "vuln_analytics", maxEvents: 100, flushInterval: 3e5 }
    ) {
      ((this.events = []),
        (this.enabled = !0),
        (this.timers = new Map()),
        (this.config = e),
        (this.sessionId = this.generateSessionId()),
        (this.startTime = Date.now()));
      const t = navigator.doNotTrack ?? window.doNotTrack;
      "1" !== t && "yes" !== t && e.enabled
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
          const e = localStorage.getItem(this.config.storageKey);
          if (e) {
            const t = JSON.parse(e);
            this.events = t.events || [];
          }
        } catch {}
    }
    saveEvents() {
      if (!this.enabled || !this.config.storageKey) return;
      const e = { events: this.events, sessionId: this.sessionId, lastFlush: Date.now() };
      try {
        localStorage.setItem(this.config.storageKey, JSON.stringify(e));
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
    track(e, t, s, i, a, n) {
      if (!this.enabled) return;
      const r = {
        event: e,
        category: t,
        action: s,
        label: i,
        value: a,
        metadata: n,
        timestamp: Date.now(),
      };
      (this.events.push(r),
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
    startTimer(e) {
      this.timers.set(e, performance.now());
    }
    endTimer(e, t) {
      const s = this.timers.get(e);
      if (void 0 === s) return;
      const i = performance.now() - s;
      (this.timers.delete(e), this.track("timing", "performance", e, void 0, Math.round(i), t));
    }
    trackVulnerabilityClick(e, t) {
      this.track("click", "vulnerability", "view", e, void 0, t);
    }
    trackSearch(e, t) {
      this.track("search", "search", "query", e, t);
    }
    trackFilterUsage(e, t, s) {
      this.track("filter", "filter", e, t, s);
    }
    trackExport(e, t) {
      this.track("export", "export", "download", e, t);
    }
    trackFilter(e, t) {
      this.track("filter_change", "interaction", "filter", e, void 0, { filterType: e, value: t });
    }
    trackPageView(e) {
      this.track("pageview", "navigation", "view", e);
    }
    startSession() {
      this.sessionStartTime = performance.now();
    }
    endSession() {
      if (void 0 === this.sessionStartTime) return;
      const e = Math.round((performance.now() - this.sessionStartTime) / 1e3);
      (this.track("session", "user", "duration", void 0, e), (this.sessionStartTime = void 0));
    }
    trackEngagement(e) {
      this.track("engagement", "user", "interaction", void 0, void 0, e);
    }
    trackError(e, t) {
      const s = e instanceof Error ? e.message : String(e),
        i = e instanceof Error ? e.stack : void 0;
      this.track("error", "error", "javascript", s, void 0, { ...t, stack: i });
    }
    getSummary() {
      const e = {},
        t = {};
      return (
        this.events.forEach((s) => {
          ((e[s.event] = (e[s.event] ?? 0) + 1), (t[s.category] = (t[s.category] ?? 0) + 1));
        }),
        {
          totalEvents: this.events.length,
          eventCounts: e,
          categoryCounts: t,
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
        } catch (e) {
          console.error("Analytics flush failed:", e);
        }
    }
    exportSessionData() {
      const e = [];
      for (let t = 0; t < localStorage.length; t++) {
        const s = localStorage.key(t);
        if (s?.includes("vuln_analytics"))
          try {
            const t = JSON.parse(localStorage.getItem(s) ?? "{}");
            e.push({ key: s, ...t });
          } catch {}
      }
      return JSON.stringify(e, null, 2);
    }
  })();
  function t() {
    return {
      isOpen: !1,
      vulnerability: null,
      loading: !1,
      error: null,
      activeTab: "overview",
      chunkIndex: null,
      mainIndex: null,
      async openModal(e) {
        ((this.isOpen = !0),
          (this.loading = !0),
          (this.error = null),
          (this.activeTab = "overview"),
          document.body.setAttribute("aria-hidden", "true"),
          document.body.classList.add("modal-open"));
        try {
          this.vulnerability = await this.loadVulnerabilityDetails(e);
        } catch (e) {
          ((this.error = e instanceof Error ? e.message : "Failed to load vulnerability details"),
            console.error("Failed to load CVE details:", e));
        } finally {
          ((this.loading = !1),
            setTimeout(() => {
              const e = document.querySelector('[data-modal="cve-details"]'),
                t = e?.querySelector(
                  'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
                );
              t?.focus();
            }, 0));
        }
      },
      closeModal() {
        ((this.isOpen = !1),
          (this.vulnerability = null),
          (this.error = null),
          document.body.removeAttribute("aria-hidden"),
          document.body.classList.remove("modal-open"));
        const e = document.querySelector("[data-cve-trigger]");
        e?.focus();
      },
      async loadVulnerabilityDetails(e) {
        try {
          if (!this.mainIndex) {
            const e = await fetch("/vuln-bot/api/vulns/index.json");
            e.ok && (this.mainIndex = await e.json());
          }
          let t = null;
          if (
            (this.mainIndex && (t = this.mainIndex.vulnerabilities.find((t) => t.cveId === e)), t)
          ) {
            if (!this.chunkIndex) {
              const e = await fetch("/vuln-bot/api/vulns/chunk-index.json");
              e.ok && (this.chunkIndex = await e.json());
            }
            if (this.chunkIndex && "severity-year" === this.chunkIndex.strategy) {
              const s = e.match(/CVE-(\d{4})-/);
              if (s) {
                const i = `${s[1]}-${t.severity}`,
                  a = this.chunkIndex.chunks.find((e) => e.key === i);
                if (a) {
                  const t = await fetch(`/vuln-bot/api/vulns/${a.file}`);
                  if (t.ok) {
                    const s = (await t.json()).vulnerabilities.find((t) => t.cveId === e);
                    if (s) return s;
                  }
                }
              }
            }
            return t;
          }
          const s = await fetch(`/vuln-bot/api/vulns/${e}.json`);
          if (s.ok) return await s.json();
          throw new Error(`CVE ${e} not found in any data source`);
        } catch (e) {
          throw (console.error("Failed to load CVE details:", e), e);
        }
      },
      switchTab(e) {
        this.activeTab = e;
        const t = document.createElement("div");
        (t.setAttribute("aria-live", "polite"),
          t.setAttribute("aria-atomic", "true"),
          (t.className = "sr-only"),
          (t.textContent = `Switched to ${e} tab`),
          document.body.appendChild(t),
          setTimeout(() => {
            document.body.removeChild(t);
          }, 1e3));
      },
      handleKeydown(e) {
        if (this.isOpen)
          switch (e.key) {
            case "Escape":
              (e.preventDefault(), this.closeModal());
              break;
            case "Tab":
              this.trapFocus(e);
              break;
            case "1":
            case "2":
            case "3":
            case "4":
              if (e.altKey) {
                e.preventDefault();
                const t = ["overview", "technical", "timeline", "references"],
                  s = parseInt(e.key) - 1;
                t[s] && this.switchTab(t[s]);
              }
          }
      },
      trapFocus(e) {
        const t = document.querySelector('[data-modal="cve-details"]');
        if (!t) return;
        const s = t.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          ),
          i = s[0],
          a = s[s.length - 1];
        e.shiftKey
          ? document.activeElement === i && (e.preventDefault(), a?.focus())
          : document.activeElement === a && (e.preventDefault(), i?.focus());
      },
      formatCvssVector(e) {
        const t = {},
          s = e.split("/"),
          i = {
            AV: "Attack Vector",
            AC: "Attack Complexity",
            PR: "Privileges Required",
            UI: "User Interaction",
            S: "Scope",
            C: "Confidentiality",
            I: "Integrity",
            A: "Availability",
          },
          a = {
            N: "None",
            A: "Adjacent",
            L: "Local",
            P: "Physical",
            H: "High",
            M: "Medium",
            Low: "Low",
            R: "Required",
            C: "Changed",
            U: "Unchanged",
          };
        return (
          s.forEach((e) => {
            const [s, n] = e.split(":");
            s && n && i[s] && (t[i[s]] = a[n] ?? n);
          }),
          t
        );
      },
      formatDate: (e) =>
        new Date(e).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" }),
      getRiskLevelText: (e) =>
        e >= 9
          ? "Critical Risk"
          : e >= 7
            ? "High Risk"
            : e >= 4
              ? "Medium Risk"
              : e >= 0.1
                ? "Low Risk"
                : "Informational",
      getSeverityClass: (e) =>
        e >= 9
          ? "severity-critical"
          : e >= 7
            ? "severity-high"
            : e >= 4
              ? "severity-medium"
              : e > 0
                ? "severity-low"
                : "severity-none",
      getCvssMetrics(e) {
        const t = [];
        if (
          (e.cvssScore &&
            t.push({
              label: "Base Score",
              value: e.cvssScore.toString(),
              description: this.getRiskLevelText(e.cvssScore),
            }),
          e.cvssMetrics && e.cvssMetrics.length > 0)
        ) {
          const s = e.cvssMetrics[0];
          if (s?.vectorString) {
            const e = this.formatCvssVector(s.vectorString);
            Object.entries(e).forEach(([e, s]) => {
              t.push({ label: e, value: s, description: `${e}: ${s}` });
            });
          }
        }
        return t;
      },
      getTimelineEvents(e) {
        const t = [];
        return (
          e.publishedDate &&
            t.push({ date: e.publishedDate, event: `CVE ${e.cveId} published`, type: "published" }),
          e.lastModifiedDate &&
            e.lastModifiedDate !== e.publishedDate &&
            t.push({ date: e.lastModifiedDate, event: "CVE details updated", type: "modified" }),
          t.sort((e, t) => new Date(t.date).getTime() - new Date(e.date).getTime())
        );
      },
    };
  }
  document.addEventListener("alpine:init", () => {
    (window.Alpine.data("cveModal", t),
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
          tags: [],
        },
        sortField: "epssPercentile",
        sortDirection: "desc",
        currentPage: 1,
        pageSize: 50,
        totalPages: 1,
        loading: !0,
        error: null,
        initialLoad: !0,
        modal: t(),
        async init() {
          (e.startTimer("page-load"),
            this.loadStateFromHash(),
            await this.loadVulnerabilities(),
            this.setupSearch(),
            this.applyFilters(),
            (this.initialLoad = !1),
            this.watchFilters(),
            this.setupKeyboardShortcuts(),
            (window.cveModal = this.modal),
            e.endTimer("page-load"));
        },
        async loadVulnerabilities() {
          try {
            ((this.loading = !0), (this.error = null));
            const e = await fetch("/vuln-bot/api/vulns/index.json");
            if (!e.ok) throw new Error(`Failed to load vulnerabilities: ${e.status}`);
            const t = await e.json();
            ((this.vulnerabilities = t.vulnerabilities || []),
              (this.loading = !1),
              this.setupLazyLoading());
          } catch (e) {
            const t = e instanceof Error ? e.message : "Unknown error";
            ((this.error = t),
              (this.loading = !1),
              console.error("Failed to load vulnerabilities:", e));
          }
        },
        setupLazyLoading() {
          if ("IntersectionObserver" in window) {
            const e = new IntersectionObserver(
              (t) => {
                t.forEach((t) => {
                  if (t.isIntersecting) {
                    const s = t.target;
                    (s.classList.add("loaded"), e.unobserve(s));
                  }
                });
              },
              { root: null, rootMargin: "100px", threshold: 0.01 }
            );
            this.$nextTick(() => {
              document.querySelectorAll(".vulnerability-row[data-lazy]").forEach((t) => {
                e.observe(t);
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
          let t = [...this.vulnerabilities];
          if (
            (this.searchQuery.trim() &&
              this.fuse &&
              ((t = this.fuse.search(this.searchQuery).map((e) => e.item)),
              e.trackSearch(this.searchQuery, t.length)),
            (t = t.filter((e) => {
              const t = e.cvssScore || 0;
              return t >= this.filters.cvssMin && t <= this.filters.cvssMax;
            })),
            (t = t.filter((e) => {
              const t = e.epssPercentile || 0;
              return t >= this.filters.epssMin && t <= this.filters.epssMax;
            })),
            this.filters.severity && (t = t.filter((e) => e.severity === this.filters.severity)),
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
          (this.filters.tags.length > 0 &&
            (t = t.filter((e) => this.filters.tags.every((t) => e.tags.includes(t)))),
            (t = this.sortResults(t)),
            (this.filteredVulns = t),
            this.updatePagination(),
            this.saveStateToHash(),
            this.announceFilterResults());
        },
        announceFilterResults() {
          let e = `Showing ${this.filteredVulns.length} of ${this.vulnerabilities.length} vulnerabilities`;
          const t = [];
          (this.searchQuery && t.push(`matching "${this.searchQuery}"`),
            this.filters.severity && t.push(`severity: ${this.filters.severity}`),
            (this.filters.cvssMin > 0 || this.filters.cvssMax < 10) &&
              t.push(`CVSS: ${this.filters.cvssMin}-${this.filters.cvssMax}`),
            (this.filters.epssMin > 0 || this.filters.epssMax < 100) &&
              t.push(`EPSS: ${this.filters.epssMin}%-${this.filters.epssMax}%`),
            this.filters.vendor && t.push(`vendor: ${this.filters.vendor}`),
            this.filters.tags.length > 0 && t.push(`tags: ${this.filters.tags.join(", ")}`),
            t.length > 0 && (e += ` with filters: ${t.join(", ")}`));
          let s = document.getElementById("filter-announcement");
          (s ||
            ((s = document.createElement("div")),
            (s.id = "filter-announcement"),
            (s.className = "sr-only"),
            s.setAttribute("role", "status"),
            s.setAttribute("aria-live", "polite"),
            s.setAttribute("aria-atomic", "true"),
            document.body.appendChild(s)),
            (s.textContent = e));
        },
        validateFilters() {
          const e = [];
          return (
            this.filters.cvssMin > this.filters.cvssMax &&
              e.push("CVSS minimum score cannot be greater than maximum"),
            this.filters.epssMin > this.filters.epssMax &&
              e.push("EPSS minimum score cannot be greater than maximum"),
            this.filters.dateFrom &&
              this.filters.dateTo &&
              new Date(this.filters.dateFrom) > new Date(this.filters.dateTo) &&
              e.push("Start date cannot be after end date"),
            !(e.length > 0 && (this.showValidationErrors(e), 1))
          );
        },
        showValidationErrors(e) {
          let t = document.getElementById("validation-errors");
          if (!t) {
            ((t = document.createElement("div")),
              (t.id = "validation-errors"),
              (t.className = "validation-errors"),
              t.setAttribute("role", "alert"),
              t.setAttribute("aria-live", "assertive"));
            const e = document.getElementById("search-filters");
            e?.insertBefore(t, e.firstChild);
          }
          ((t.innerHTML = `\n          <h3>Validation Errors</h3>\n          <ul>\n            ${e.map((e) => `<li>${e}</li>`).join("")}\n          </ul>\n        `),
            t.focus(),
            setTimeout(() => {
              t.innerHTML = "";
            }, 5e3));
        },
        sortResults(e) {
          const t = this.sortField,
            s = this.sortDirection;
          return e.sort((e, i) => {
            let a = e[t],
              n = i[t];
            return (
              a ?? (a = ""),
              n ?? (n = ""),
              "string" == typeof t &&
                t.includes("Date") &&
                ((a = new Date(a).getTime()), (n = new Date(n).getTime())),
              a < n ? ("asc" === s ? -1 : 1) : a > n ? ("asc" === s ? 1 : -1) : 0
            );
          });
        },
        sort(t) {
          (this.sortField === t
            ? (this.sortDirection = "asc" === this.sortDirection ? "desc" : "asc")
            : ((this.sortField = t), (this.sortDirection = "desc")),
            e.track("sort", "interaction", "sort", t, void 0, { direction: this.sortDirection }),
            this.applyFilters());
        },
        updatePagination() {
          ((this.totalPages = Math.ceil(this.filteredVulns.length / this.pageSize)),
            (this.currentPage = Math.min(this.currentPage, Math.max(1, this.totalPages))));
          const e = (this.currentPage - 1) * this.pageSize,
            t = e + this.pageSize;
          ((this.paginatedVulns = this.filteredVulns.slice(e, t)),
            this.$nextTick(() => {
              this.setupLazyLoading();
            }));
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
          const e = {
            q: this.searchQuery,
            cvssMin: this.filters.cvssMin,
            cvssMax: this.filters.cvssMax,
            epssMin: this.filters.epssMin,
            epssMax: this.filters.epssMax,
            severity: this.filters.severity,
            dateFrom: this.filters.dateFrom,
            dateTo: this.filters.dateTo,
            vendor: this.filters.vendor,
            tags: this.filters.tags.join(","),
            sort: this.sortField,
            dir: this.sortDirection,
            page: this.currentPage,
            size: this.pageSize,
          };
          Object.keys(e).forEach((t) => {
            const s = e[t];
            (!s ||
              "" === s ||
              ("cvssMin" === t && 0 === s) ||
              ("cvssMax" === t && 10 === s) ||
              ("epssMin" === t && 0 === s) ||
              ("epssMax" === t && 100 === s) ||
              ("page" === t && 1 === s) ||
              ("size" === t && 20 === s) ||
              ("sort" === t && "epssPercentile" === s) ||
              ("dir" === t && "desc" === s)) &&
              delete e[t];
          });
          const t = new URLSearchParams(
            Object.fromEntries(Object.entries(e).map(([e, t]) => [e, String(t)]))
          ).toString();
          window.location.hash = t;
        },
        loadStateFromHash() {
          const e = window.location.hash.slice(1);
          if (!e) return;
          const t = new URLSearchParams(e);
          ((this.searchQuery = t.get("q") ?? ""),
            (this.filters.cvssMin = parseFloat(t.get("cvssMin") ?? "0")),
            (this.filters.cvssMax = parseFloat(t.get("cvssMax") ?? "10")),
            (this.filters.epssMin = parseInt(t.get("epssMin") ?? "0")),
            (this.filters.epssMax = parseInt(t.get("epssMax") ?? "100")),
            (this.filters.severity = t.get("severity") ?? ""),
            (this.filters.dateFrom = t.get("dateFrom") ?? ""),
            (this.filters.dateTo = t.get("dateTo") ?? ""),
            (this.filters.vendor = t.get("vendor") ?? ""));
          const s = t.get("tags");
          ((this.filters.tags = s ? s.split(",").filter((e) => e) : []),
            (this.sortField = t.get("sort") ?? "epssPercentile"),
            (this.sortDirection = t.get("dir") ?? "desc"),
            (this.currentPage = parseInt(t.get("page") ?? "1")),
            (this.pageSize = parseInt(t.get("size") ?? "20")));
        },
        getSeverityClass: (e) =>
          e >= 9
            ? "severity-critical"
            : e >= 7
              ? "severity-high"
              : e >= 4
                ? "severity-medium"
                : e > 0
                  ? "severity-low"
                  : "severity-none",
        formatDate: (e) =>
          new Date(e).toLocaleDateString("en-US", {
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
              tags: [],
            }),
            (this.currentPage = 1),
            this.applyFilters());
        },
        exportResults() {
          e.trackExport("csv", this.filteredVulns.length);
          const t = [
              ["CVE ID", "Title", "Severity", "CVSS Score", "EPSS %", "Published Date"],
              ...this.filteredVulns.map((e) => [
                e.cveId,
                `"${e.title.replace(/"/g, '""')}"`,
                e.severity,
                e.cvssScore?.toString() || "",
                e.epssPercentile?.toString() || "",
                e.publishedDate,
              ]),
            ]
              .map((e) => e.join(","))
              .join("\n"),
            s = new Blob([t], { type: "text/csv" }),
            i = URL.createObjectURL(s),
            a = document.createElement("a");
          ((a.href = i),
            (a.download = `vulnerabilities-${new Date().toISOString().slice(0, 10)}.csv`),
            a.click(),
            URL.revokeObjectURL(i));
        },
        trackVulnerabilityClick(t, s) {
          e.trackVulnerabilityClick(t, { riskScore: s });
        },
        async openCveModal(e) {
          await this.modal.openModal(e);
        },
        setupKeyboardShortcuts() {
          document.addEventListener("keydown", (e) => {
            if (
              !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)
            ) {
              switch (e.key) {
                case "/":
                  e.preventDefault();
                  const t = document.getElementById("search-input");
                  t?.focus();
                  break;
                case "r":
                  e.ctrlKey || e.metaKey || (e.preventDefault(), this.resetFilters());
                  break;
                case "e":
                  e.ctrlKey || e.metaKey || (e.preventDefault(), this.exportResults());
                  break;
                case "ArrowLeft":
                  e.ctrlKey || e.metaKey || e.shiftKey || (e.preventDefault(), this.previousPage());
                  break;
                case "ArrowRight":
                  e.ctrlKey || e.metaKey || e.shiftKey || (e.preventDefault(), this.nextPage());
                  break;
                case "?":
                  (e.preventDefault(), this.showKeyboardHelp());
                  break;
                case "Escape":
                  const s = document.getElementById("keyboard-help-modal");
                  s &&
                    !s.classList.contains("hidden") &&
                    (e.preventDefault(), s.classList.add("hidden"));
              }
              if (e.key >= "1" && e.key <= "4" && !e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                const t = [10, 20, 50, 100],
                  s = parseInt(e.key) - 1;
                s < t.length && void 0 !== t[s] && (this.pageSize = t[s]);
              }
            }
          });
        },
        showKeyboardHelp() {
          let t = document.getElementById("keyboard-help-modal");
          (t ||
            ((t = document.createElement("div")),
            (t.id = "keyboard-help-modal"),
            (t.className = "modal-backdrop"),
            (t.innerHTML =
              '\n              <div class="modal-content" role="dialog" \n                   aria-labelledby="keyboard-help-title" aria-modal="true">\n                <h2 id="keyboard-help-title">Keyboard Shortcuts</h2>\n                <button class="modal-close" aria-label="Close help modal"\n                        onclick="document.getElementById(\'keyboard-help-modal\')\n                                 .classList.add(\'hidden\')">\n                  ×\n                </button>\n                <dl class="keyboard-shortcuts">\n                  <dt><kbd>/</kbd></dt>\n                  <dd>Focus search input</dd>\n                  \n                  <dt><kbd>r</kbd></dt>\n                  <dd>Reset all filters</dd>\n                  \n                  <dt><kbd>e</kbd></dt>\n                  <dd>Export results as CSV</dd>\n                  \n                  <dt><kbd>←</kbd> <kbd>→</kbd></dt>\n                  <dd>Navigate between pages</dd>\n                  \n                  <dt><kbd>1</kbd> - <kbd>4</kbd></dt>\n                  <dd>Set page size (10, 20, 50, 100)</dd>\n                  \n                  <dt><kbd>?</kbd></dt>\n                  <dd>Show this help</dd>\n                  \n                  <dt><kbd>Esc</kbd></dt>\n                  <dd>Close this help</dd>\n                </dl>\n              </div>\n            '),
            document.body.appendChild(t)),
            t.classList.remove("hidden"));
          const s = t.querySelector(".modal-close");
          (s?.focus(), e.track("keyboard-help", "interaction", "help", "show"));
        },
        $nextTick(e) {
          this.$nextTick(e);
        },
      })));
  });
})();
//# sourceMappingURL=dashboard.js.map
