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

    /***/ "./src/assets/ts/components/CveModal.ts":
      /*!**********************************************!*\
  !*** ./src/assets/ts/components/CveModal.ts ***!
  \**********************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ createCveModal: () => /* binding */ createCveModal,
          /* harmony export */
        });
        /**
         * CVE Details Modal Component
         * Follows WD (Web Design) standards for accessibility, interaction, and responsive design
         */
        /**
         * Creates a CVE modal Alpine.js component
         * Implements WCAG 2.1 AA accessibility standards and responsive design patterns
         */
        function createCveModal() {
          return {
            // State
            isOpen: false,
            vulnerability: null,
            loading: false,
            error: null,
            activeTab: "overview",
            chunkIndex: null,
            mainIndex: null,
            /**
             * Opens modal and loads CVE details
             * Follows focus management and ARIA standards
             */
            async openModal(cveId) {
              this.isOpen = true;
              this.loading = true;
              this.error = null;
              this.activeTab = "overview";
              // Trap focus and manage ARIA
              document.body.setAttribute("aria-hidden", "true");
              document.body.classList.add("modal-open");
              try {
                this.vulnerability = await this.loadVulnerabilityDetails(cveId);
              } catch (error) {
                this.error =
                  error instanceof Error ? error.message : "Failed to load vulnerability details";
                console.error("Failed to load CVE details:", error);
              } finally {
                this.loading = false;
                // Focus management - move to modal content
                setTimeout(() => {
                  const modal = document.querySelector('[data-modal="cve-details"]');
                  const firstFocusable = modal?.querySelector(
                    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
                  );
                  firstFocusable?.focus();
                }, 0);
              }
            },
            /**
             * Closes modal with proper cleanup
             * Restores focus to trigger element
             */
            closeModal() {
              this.isOpen = false;
              this.vulnerability = null;
              this.error = null;
              // Restore body state
              document.body.removeAttribute("aria-hidden");
              document.body.classList.remove("modal-open");
              // Return focus to trigger element
              const triggerElement = document.querySelector(`[data-cve-trigger]`);
              triggerElement?.focus();
            },
            /**
             * Loads detailed vulnerability data from chunked storage
             */
            async loadVulnerabilityDetails(cveId) {
              try {
                // Load main index if not already loaded (it contains severity info)
                if (!this.mainIndex) {
                  const indexResponse = await fetch("/vuln-bot/api/vulns/index.json");
                  if (indexResponse.ok) {
                    this.mainIndex = await indexResponse.json();
                  }
                }
                // Find the vulnerability in the main index to get its severity
                let vulnSummary = null;
                if (this.mainIndex) {
                  vulnSummary = this.mainIndex.vulnerabilities.find((v) => v.cveId === cveId);
                }
                // If found in index and we have chunk index, load from chunks
                if (vulnSummary) {
                  // Load chunk index if not already loaded
                  if (!this.chunkIndex) {
                    const chunkIndexResponse = await fetch("/vuln-bot/api/vulns/chunk-index.json");
                    if (chunkIndexResponse.ok) {
                      this.chunkIndex = await chunkIndexResponse.json();
                    }
                  }
                  // Find the right chunk based on year and severity
                  if (this.chunkIndex && this.chunkIndex.strategy === "severity-year") {
                    const yearMatch = cveId.match(/CVE-(\d{4})-/);
                    if (yearMatch) {
                      const year = yearMatch[1];
                      const severity = vulnSummary.severity;
                      const chunkKey = `${year}-${severity}`;
                      const chunk = this.chunkIndex.chunks.find((c) => c.key === chunkKey);
                      if (chunk) {
                        const chunkResponse = await fetch(`/vuln-bot/api/vulns/${chunk.file}`);
                        if (chunkResponse.ok) {
                          const chunkData = await chunkResponse.json();
                          const vuln = chunkData.vulnerabilities.find((v) => v.cveId === cveId);
                          if (vuln) {
                            return vuln;
                          }
                        }
                      }
                    }
                  }
                  // If chunk loading failed, return the summary data (it has most fields)
                  return vulnSummary;
                }
                // Fallback: try loading individual file (for backward compatibility)
                const response = await fetch(`/vuln-bot/api/vulns/${cveId}.json`);
                if (response.ok) {
                  return await response.json();
                }
                throw new Error(`CVE ${cveId} not found in any data source`);
              } catch (error) {
                console.error("Failed to load CVE details:", error);
                throw error;
              }
            },
            /**
             * Switches active tab with proper ARIA management
             */
            switchTab(tab) {
              this.activeTab = tab;
              // Announce tab change to screen readers
              const announcement = document.createElement("div");
              announcement.setAttribute("aria-live", "polite");
              announcement.setAttribute("aria-atomic", "true");
              announcement.className = "sr-only";
              announcement.textContent = `Switched to ${tab} tab`;
              document.body.appendChild(announcement);
              setTimeout(() => {
                document.body.removeChild(announcement);
              }, 1000);
            },
            /**
             * Handles keyboard navigation
             * Implements standard modal keyboard patterns
             */
            handleKeydown(event) {
              if (!this.isOpen) return;
              switch (event.key) {
                case "Escape":
                  event.preventDefault();
                  this.closeModal();
                  break;
                case "Tab":
                  this.trapFocus(event);
                  break;
                case "1":
                case "2":
                case "3":
                case "4":
                  if (event.altKey) {
                    event.preventDefault();
                    const tabs = ["overview", "technical", "timeline", "references"];
                    const tabIndex = parseInt(event.key) - 1;
                    if (tabs[tabIndex]) {
                      this.switchTab(tabs[tabIndex]);
                    }
                  }
                  break;
              }
            },
            /**
             * Implements focus trapping within modal
             * Essential for accessibility compliance
             */
            trapFocus(event) {
              const modal = document.querySelector('[data-modal="cve-details"]');
              if (!modal) return;
              const focusableElements = modal.querySelectorAll(
                'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
              );
              const firstFocusable = focusableElements[0];
              const lastFocusable = focusableElements[focusableElements.length - 1];
              if (event.shiftKey) {
                if (document.activeElement === firstFocusable) {
                  event.preventDefault();
                  lastFocusable?.focus();
                }
              } else {
                if (document.activeElement === lastFocusable) {
                  event.preventDefault();
                  firstFocusable?.focus();
                }
              }
            },
            /**
             * Parses CVSS vector string into readable components
             */
            formatCvssVector(vector) {
              const metrics = {};
              const parts = vector.split("/");
              const cvssMapping = {
                AV: "Attack Vector",
                AC: "Attack Complexity",
                PR: "Privileges Required",
                UI: "User Interaction",
                S: "Scope",
                C: "Confidentiality",
                I: "Integrity",
                A: "Availability",
              };
              const valueMapping = {
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
              parts.forEach((part) => {
                const [key, value] = part.split(":");
                if (key && value && cvssMapping[key]) {
                  metrics[cvssMapping[key]] = valueMapping[value] ?? value;
                }
              });
              return metrics;
            },
            /**
             * Formats date strings consistently
             */
            formatDate(dateStr) {
              const date = new Date(dateStr);
              return date.toLocaleDateString("en-US", {
                year: "numeric",
                month: "long",
                day: "numeric",
              });
            },
            /**
             * Gets human-readable risk level
             */
            getRiskLevelText(score) {
              if (score >= 9.0) return "Critical Risk";
              if (score >= 7.0) return "High Risk";
              if (score >= 4.0) return "Medium Risk";
              if (score >= 0.1) return "Low Risk";
              return "Informational";
            },
            /**
             * Gets CSS class for severity level
             */
            getSeverityClass(score) {
              if (score >= 9) return "severity-critical";
              if (score >= 7) return "severity-high";
              if (score >= 4) return "severity-medium";
              if (score > 0) return "severity-low";
              return "severity-none";
            },
            /**
             * Extracts CVSS metrics for display
             */
            getCvssMetrics(vulnerability) {
              const metrics = [];
              if (vulnerability.cvssScore) {
                metrics.push({
                  label: "Base Score",
                  value: vulnerability.cvssScore.toString(),
                  description: this.getRiskLevelText(vulnerability.cvssScore),
                });
              }
              if (vulnerability.cvssMetrics && vulnerability.cvssMetrics.length > 0) {
                const cvssMetric = vulnerability.cvssMetrics[0];
                if (cvssMetric?.vectorString) {
                  const vectorMetrics = this.formatCvssVector(cvssMetric.vectorString);
                  Object.entries(vectorMetrics).forEach(([label, value]) => {
                    metrics.push({
                      label,
                      value,
                      description: `${label}: ${value}`,
                    });
                  });
                }
              }
              return metrics;
            },
            /**
             * Creates timeline of vulnerability events
             */
            getTimelineEvents(vulnerability) {
              const events = [];
              if (vulnerability.publishedDate) {
                events.push({
                  date: vulnerability.publishedDate,
                  event: `CVE ${vulnerability.cveId} published`,
                  type: "published",
                });
              }
              if (
                vulnerability.lastModifiedDate &&
                vulnerability.lastModifiedDate !== vulnerability.publishedDate
              ) {
                events.push({
                  date: vulnerability.lastModifiedDate,
                  event: "CVE details updated",
                  type: "modified",
                });
              }
              // Sort by date, newest first
              return events.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
            },
          };
        }

        /***/
      },

    /***/ "./src/assets/ts/components/SavedSearches.ts":
      /*!***************************************************!*\
  !*** ./src/assets/ts/components/SavedSearches.ts ***!
  \***************************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ SavedSearches: () => /* binding */ SavedSearches,
          /* harmony export */ createSavedSearchComponent: () =>
            /* binding */ createSavedSearchComponent,
          /* harmony export */
        });
        /**
         * Saved Searches and Smart Suggestions Component
         * Provides saved search functionality and intelligent search suggestions
         */
        class SavedSearches {
          constructor() {
            this.storageKey = "vuln_saved_searches";
            this.recentSearchesKey = "vuln_recent_searches";
            this.maxSavedSearches = 20;
            this.maxRecentSearches = 10;
            this.maxSuggestions = 8;
            this.init();
          }
          init() {
            // Clean up old searches periodically
            this.cleanupOldSearches();
          }
          /**
           * Save a search with current filters
           */
          saveSearch(name, query, filters) {
            const searches = this.getSavedSearches();
            const newSearch = {
              id: this.generateId(),
              name,
              query,
              filters: { ...filters },
              timestamp: Date.now(),
            };
            // Remove existing search with same name
            const filtered = searches.filter((s) => s.name !== name);
            // Add new search at beginning
            filtered.unshift(newSearch);
            // Keep only max searches
            const trimmed = filtered.slice(0, this.maxSavedSearches);
            this.storeSavedSearches(trimmed);
            return newSearch;
          }
          /**
           * Get all saved searches
           */
          getSavedSearches() {
            try {
              const stored = localStorage.getItem(this.storageKey);
              if (stored) {
                return JSON.parse(stored);
              }
            } catch (error) {
              console.warn("Failed to load saved searches:", error);
            }
            return [];
          }
          /**
           * Delete a saved search
           */
          deleteSavedSearch(id) {
            const searches = this.getSavedSearches();
            const filtered = searches.filter((s) => s.id !== id);
            this.storeSavedSearches(filtered);
          }
          /**
           * Update search count (for analytics)
           */
          updateSearchCount(id, count) {
            const searches = this.getSavedSearches();
            const search = searches.find((s) => s.id === id);
            if (search) {
              search.count = count;
              this.storeSavedSearches(searches);
            }
          }
          /**
           * Add to recent searches
           */
          addRecentSearch(query) {
            if (!query.trim()) return;
            const recent = this.getRecentSearches();
            // Remove if already exists
            const filtered = recent.filter((q) => q !== query);
            // Add at beginning
            filtered.unshift(query);
            // Keep only max recent
            const trimmed = filtered.slice(0, this.maxRecentSearches);
            this.storeRecentSearches(trimmed);
          }
          /**
           * Get recent searches
           */
          getRecentSearches() {
            try {
              const stored = localStorage.getItem(this.recentSearchesKey);
              if (stored) {
                return JSON.parse(stored);
              }
            } catch (error) {
              console.warn("Failed to load recent searches:", error);
            }
            return [];
          }
          /**
           * Generate search suggestions based on input
           */
          generateSuggestions(input, vulnerabilities) {
            const suggestions = [];
            const inputLower = input.toLowerCase().trim();
            if (inputLower.length < 2) {
              // Show recent searches when input is short
              const recent = this.getRecentSearches();
              recent.forEach((query, index) => {
                suggestions.push({
                  text: query,
                  type: "recent",
                  weight: 100 - index * 10,
                });
              });
              return suggestions.slice(0, this.maxSuggestions);
            }
            // CVE ID suggestions
            if (inputLower.startsWith("cve-") || /^\d{4}/.test(inputLower)) {
              vulnerabilities.forEach((vuln) => {
                if (vuln.cveId.toLowerCase().includes(inputLower)) {
                  suggestions.push({
                    text: vuln.cveId,
                    type: "cve",
                    weight: 90,
                    metadata: { title: vuln.title },
                  });
                }
              });
            }
            // Vendor suggestions
            const vendors = new Set();
            vulnerabilities.forEach((vuln) => {
              vuln.vendors?.forEach((vendor) => {
                if (vendor.toLowerCase().includes(inputLower)) {
                  vendors.add(vendor);
                }
              });
            });
            vendors.forEach((vendor) => {
              suggestions.push({
                text: vendor,
                type: "vendor",
                weight: 80,
              });
            });
            // Tag suggestions
            const tags = new Set();
            vulnerabilities.forEach((vuln) => {
              vuln.tags?.forEach((tag) => {
                if (tag.toLowerCase().includes(inputLower)) {
                  tags.add(tag);
                }
              });
            });
            tags.forEach((tag) => {
              suggestions.push({
                text: tag,
                type: "tag",
                weight: 70,
              });
            });
            // Smart suggestions based on common patterns
            this.addSmartSuggestions(inputLower, suggestions);
            // Recent search suggestions that match input
            const recent = this.getRecentSearches();
            recent.forEach((query, index) => {
              if (query.toLowerCase().includes(inputLower)) {
                suggestions.push({
                  text: query,
                  type: "recent",
                  weight: 60 - index * 5,
                });
              }
            });
            // Sort by weight and remove duplicates
            const unique = new Map();
            suggestions.forEach((suggestion) => {
              const existing = unique.get(suggestion.text);
              if (!existing || existing.weight < suggestion.weight) {
                unique.set(suggestion.text, suggestion);
              }
            });
            return Array.from(unique.values())
              .sort((a, b) => b.weight - a.weight)
              .slice(0, this.maxSuggestions);
          }
          /**
           * Add smart suggestions based on patterns
           */
          addSmartSuggestions(input, suggestions) {
            const smartPatterns = [
              { pattern: /buffer.?overflow/i, suggestion: "buffer overflow", weight: 85 },
              { pattern: /sql.?injection/i, suggestion: "sql injection", weight: 85 },
              { pattern: /cross.?site/i, suggestion: "cross-site scripting", weight: 85 },
              { pattern: /remote.?code/i, suggestion: "remote code execution", weight: 85 },
              { pattern: /privilege.?escalation/i, suggestion: "privilege escalation", weight: 85 },
              { pattern: /denial.?of.?service/i, suggestion: "denial of service", weight: 85 },
              {
                pattern: /authentication.?bypass/i,
                suggestion: "authentication bypass",
                weight: 85,
              },
              { pattern: /path.?traversal/i, suggestion: "path traversal", weight: 85 },
              { pattern: /memory.?corruption/i, suggestion: "memory corruption", weight: 85 },
              {
                pattern: /information.?disclosure/i,
                suggestion: "information disclosure",
                weight: 85,
              },
            ];
            smartPatterns.forEach(({ pattern, suggestion, weight }) => {
              if (pattern.test(input) && !suggestions.some((s) => s.text === suggestion)) {
                suggestions.push({
                  text: suggestion,
                  type: "smart",
                  weight,
                });
              }
            });
            // Year-based suggestions
            if (/202[0-9]/.test(input)) {
              const year = input.match(/202[0-9]/)?.[0];
              if (year) {
                suggestions.push({
                  text: `CVE-${year}`,
                  type: "smart",
                  weight: 75,
                });
              }
            }
            // Severity suggestions
            const severities = ["critical", "high", "medium", "low"];
            severities.forEach((severity) => {
              if (severity.startsWith(input.toLowerCase())) {
                suggestions.push({
                  text: severity,
                  type: "smart",
                  weight: 70,
                });
              }
            });
          }
          /**
           * Export saved searches
           */
          exportSavedSearches() {
            const searches = this.getSavedSearches();
            return JSON.stringify(searches, null, 2);
          }
          /**
           * Import saved searches
           */
          importSavedSearches(jsonData) {
            try {
              const searches = JSON.parse(jsonData);
              if (Array.isArray(searches)) {
                // Validate structure
                const valid = searches.every(
                  (s) => s.id && s.name && typeof s.query === "string" && s.filters
                );
                if (valid) {
                  this.storeSavedSearches(searches.slice(0, this.maxSavedSearches));
                  return true;
                }
              }
            } catch (error) {
              console.warn("Failed to import saved searches:", error);
            }
            return false;
          }
          storeSavedSearches(searches) {
            try {
              localStorage.setItem(this.storageKey, JSON.stringify(searches));
            } catch (error) {
              console.warn("Failed to save searches:", error);
            }
          }
          storeRecentSearches(searches) {
            try {
              localStorage.setItem(this.recentSearchesKey, JSON.stringify(searches));
            } catch (error) {
              console.warn("Failed to save recent searches:", error);
            }
          }
          cleanupOldSearches() {
            const searches = this.getSavedSearches();
            const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000; // 90 days
            const cleaned = searches.filter((s) => s.timestamp > cutoff);
            if (cleaned.length !== searches.length) {
              this.storeSavedSearches(cleaned);
            }
          }
          generateId() {
            return `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          }
        }
        /**
         * Alpine.js component for saved searches UI
         */
        function createSavedSearchComponent() {
          return {
            savedSearches: new SavedSearches(),
            showSavedSearches: false,
            showSuggestions: false,
            suggestions: [],
            savedSearchList: [],
            newSearchName: "",
            showSaveDialog: false,
            init() {
              this.loadSavedSearches();
              this.setupSuggestionHandlers();
            },
            loadSavedSearches() {
              this.savedSearchList = this.savedSearches.getSavedSearches();
            },
            showSaveSearchDialog() {
              this.showSaveDialog = true;
              this.newSearchName = "";
              this.$nextTick(() => {
                const input = document.getElementById("search-name-input");
                input?.focus();
              });
            },
            saveCurrentSearch() {
              if (!this.newSearchName.trim()) return;
              // Get current state from parent dashboard
              const dashboard = this.getDashboard();
              if (dashboard) {
                const saved = this.savedSearches.saveSearch(
                  this.newSearchName,
                  dashboard.searchQuery,
                  dashboard.filters
                );
                this.loadSavedSearches();
                this.showSaveDialog = false;
                // Show success message
                this.showToast(`Search "${saved.name}" saved successfully`);
              }
            },
            loadSavedSearch(search) {
              const dashboard = this.getDashboard();
              if (dashboard) {
                // Apply saved search
                dashboard.searchQuery = search.query;
                dashboard.filters = { ...search.filters };
                dashboard.applyFilters();
                // Update count
                this.savedSearches.updateSearchCount(search.id, dashboard.filteredVulns.length);
                this.loadSavedSearches();
                this.showSavedSearches = false;
              }
            },
            deleteSavedSearch(id) {
              this.savedSearches.deleteSavedSearch(id);
              this.loadSavedSearches();
            },
            setupSuggestionHandlers() {
              // Handle input events for suggestions
              const searchInput = document.getElementById("search-input");
              if (searchInput) {
                searchInput.addEventListener("input", (e) => {
                  this.updateSuggestions(e.target.value);
                });
                searchInput.addEventListener("focus", () => {
                  this.showSuggestions = true;
                });
                searchInput.addEventListener("blur", () => {
                  // Delay hiding to allow clicks on suggestions
                  setTimeout(() => {
                    this.showSuggestions = false;
                  }, 200);
                });
              }
            },
            updateSuggestions(input) {
              const dashboard = this.getDashboard();
              if (dashboard) {
                this.suggestions = this.savedSearches.generateSuggestions(
                  input,
                  dashboard.vulnerabilities
                );
                this.showSuggestions = input.length > 0 && this.suggestions.length > 0;
              }
            },
            applySuggestion(suggestion) {
              const dashboard = this.getDashboard();
              if (dashboard) {
                dashboard.searchQuery = suggestion.text;
                this.savedSearches.addRecentSearch(suggestion.text);
                dashboard.applyFilters();
                this.showSuggestions = false;
              }
            },
            getSuggestionIcon(type) {
              switch (type) {
                case "recent":
                  return "🕒";
                case "vendor":
                  return "🏢";
                case "cve":
                  return "🔍";
                case "tag":
                  return "🏷️";
                case "smart":
                  return "💡";
                default:
                  return "🔍";
              }
            },
            getDashboard() {
              // Get reference to main dashboard component
              return window.vulnDashboard;
            },
            showToast(message) {
              // Simple toast notification
              const toast = document.createElement("div");
              toast.className = "toast";
              toast.textContent = message;
              toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4ade80;
        color: white;
        padding: 12px 24px;
        border-radius: 8px;
        z-index: 1000;
        animation: slideIn 0.3s ease;
      `;
              document.body.appendChild(toast);
              setTimeout(() => {
                toast.remove();
              }, 3000);
            },
            $nextTick(callback) {
              // This method is provided by Alpine.js at runtime
              // @ts-ignore
              this.$nextTick(callback);
            },
          };
        }

        /***/
      },

    /***/ "./src/assets/ts/components/SecurityAlerts.ts":
      /*!****************************************************!*\
  !*** ./src/assets/ts/components/SecurityAlerts.ts ***!
  \****************************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ QuickActionsManager: () => /* binding */ QuickActionsManager,
          /* harmony export */ SecurityAlertSystem: () => /* binding */ SecurityAlertSystem,
          /* harmony export */ createSecurityComponent: () => /* binding */ createSecurityComponent,
          /* harmony export */
        });
        /**
         * Security Alert System and Quick Actions Component
         * Provides contextual security alerts and quick action buttons for vulnerability management
         */
        class SecurityAlertSystem {
          constructor() {
            this.alerts = [];
            this.alertContainer = null;
            this.maxAlerts = 5;
            this.subscribers = [];
            this.init();
          }
          init() {
            this.createAlertContainer();
            this.setupKeyboardShortcuts();
          }
          createAlertContainer() {
            this.alertContainer = document.createElement("div");
            this.alertContainer.id = "security-alerts-container";
            this.alertContainer.className = "security-alerts-container";
            this.alertContainer.setAttribute("role", "status");
            this.alertContainer.setAttribute("aria-live", "polite");
            this.alertContainer.setAttribute("aria-atomic", "false");
            document.body.appendChild(this.alertContainer);
          }
          /**
           * Add a security alert
           */
          addAlert(alert) {
            const newAlert = {
              ...alert,
              id: this.generateId(),
              timestamp: Date.now(),
            };
            // Add to beginning of array (most recent first)
            this.alerts.unshift(newAlert);
            // Limit number of alerts
            if (this.alerts.length > this.maxAlerts) {
              this.alerts = this.alerts.slice(0, this.maxAlerts);
            }
            this.renderAlerts();
            this.notifySubscribers();
            // Auto-hide if specified
            if (alert.autoHide) {
              setTimeout(() => {
                this.removeAlert(newAlert.id);
              }, alert.autoHide);
            }
            return newAlert.id;
          }
          /**
           * Remove an alert by ID
           */
          removeAlert(id) {
            this.alerts = this.alerts.filter((alert) => alert.id !== id);
            this.renderAlerts();
            this.notifySubscribers();
          }
          /**
           * Clear all alerts
           */
          clearAlerts() {
            this.alerts = [];
            this.renderAlerts();
            this.notifySubscribers();
          }
          /**
           * Get all current alerts
           */
          getAlerts() {
            return [...this.alerts];
          }
          /**
           * Subscribe to alert changes
           */
          subscribe(callback) {
            this.subscribers.push(callback);
            // Return unsubscribe function
            return () => {
              this.subscribers = this.subscribers.filter((sub) => sub !== callback);
            };
          }
          notifySubscribers() {
            this.subscribers.forEach((callback) => callback(this.getAlerts()));
          }
          renderAlerts() {
            if (!this.alertContainer) return;
            this.alertContainer.innerHTML = "";
            this.alerts.forEach((alert) => {
              const alertElement = this.createAlertElement(alert);
              this.alertContainer.appendChild(alertElement);
            });
          }
          createAlertElement(alert) {
            const alertDiv = document.createElement("div");
            alertDiv.className = `security-alert security-alert--${alert.type}`;
            alertDiv.setAttribute("role", "alert");
            alertDiv.setAttribute("aria-labelledby", `alert-title-${alert.id}`);
            alertDiv.setAttribute("aria-describedby", `alert-message-${alert.id}`);
            const iconMap = {
              critical: "🚨",
              warning: "⚠️",
              info: "ℹ️",
              success: "✅",
            };
            alertDiv.innerHTML = `
      <div class="security-alert__header">
        <span class="security-alert__icon" aria-hidden="true">${iconMap[alert.type]}</span>
        <h3 id="alert-title-${alert.id}" class="security-alert__title">${alert.title}</h3>
        ${
          alert.dismissible
            ? `
          <button 
            class="security-alert__dismiss" 
            aria-label="Dismiss alert"
            onclick="securityAlerts.removeAlert('${alert.id}')"
          >
            ×
          </button>
        `
            : ""
        }
      </div>
      <div id="alert-message-${alert.id}" class="security-alert__message">
        ${alert.message}
      </div>
      ${
        alert.actions && alert.actions.length > 0
          ? `
        <div class="security-alert__actions">
          ${alert.actions
            .map(
              (action) => `
            <button 
              class="security-alert__action security-alert__action--${action.type}"
              onclick="securityAlerts.executeAction('${alert.id}', '${action.id}')"
              ${action.shortcut ? `title="Shortcut: ${action.shortcut}"` : ""}
            >
              ${action.icon ? `<span class="action-icon">${action.icon}</span>` : ""}
              ${action.label}
            </button>
          `
            )
            .join("")}
        </div>
      `
          : ""
      }
      <div class="security-alert__timestamp">
        ${new Date(alert.timestamp).toLocaleTimeString()}
      </div>
    `;
            return alertDiv;
          }
          /**
           * Execute an action from an alert
           */
          async executeAction(alertId, actionId) {
            const alert = this.alerts.find((a) => a.id === alertId);
            if (!alert?.actions) return;
            const action = alert.actions.find((a) => a.id === actionId);
            if (!action) return;
            try {
              await action.handler();
            } catch (error) {
              console.error("Failed to execute alert action:", error);
              this.addAlert({
                type: "critical",
                title: "Action Failed",
                message: `Failed to execute action: ${error instanceof Error ? error.message : "Unknown error"}`,
                priority: 100,
                dismissible: true,
                autoHide: 5000,
              });
            }
          }
          setupKeyboardShortcuts() {
            document.addEventListener("keydown", (event) => {
              // Alt + A to show/focus alerts
              if (event.altKey && event.key === "a") {
                event.preventDefault();
                this.focusFirstAlert();
              }
              // Escape to dismiss focused alert
              if (event.key === "Escape" && document.activeElement?.closest(".security-alert")) {
                const alertElement = document.activeElement.closest(".security-alert");
                const alertId = alertElement
                  ?.querySelector('[id^="alert-title-"]')
                  ?.id.replace("alert-title-", "");
                if (alertId) {
                  this.removeAlert(alertId);
                }
              }
            });
          }
          focusFirstAlert() {
            const firstAlert = this.alertContainer?.querySelector(".security-alert");
            firstAlert?.focus();
          }
          generateId() {
            return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          }
        }
        /**
         * Quick Actions Manager for security-specific operations
         */
        class QuickActionsManager {
          constructor() {
            this.actions = new Map();
            this.container = null;
            this.init();
            this.registerDefaultActions();
          }
          init() {
            this.createContainer();
          }
          createContainer() {
            this.container = document.createElement("div");
            this.container.id = "quick-actions-container";
            this.container.className = "quick-actions-container";
            this.container.setAttribute("role", "toolbar");
            this.container.setAttribute("aria-label", "Quick security actions");
            // Position in top-right corner
            this.container.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 1000;
      display: flex;
      gap: 8px;
      background: rgba(255, 255, 255, 0.95);
      border-radius: 12px;
      padding: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      backdrop-filter: blur(8px);
    `;
            document.body.appendChild(this.container);
          }
          /**
           * Register a quick action
           */
          registerAction(action) {
            this.actions.set(action.id, action);
            this.renderActions();
          }
          /**
           * Remove a quick action
           */
          removeAction(id) {
            this.actions.delete(id);
            this.renderActions();
          }
          renderActions() {
            if (!this.container) return;
            this.container.innerHTML = "";
            this.actions.forEach((action) => {
              const button = document.createElement("button");
              button.className = `quick-action quick-action--${action.type}`;
              button.setAttribute("aria-label", action.label);
              button.setAttribute(
                "title",
                action.shortcut ? `${action.label} (${action.shortcut})` : action.label
              );
              button.innerHTML = `
        ${action.icon ? `<span class="quick-action__icon">${action.icon}</span>` : ""}
        <span class="quick-action__label">${action.label}</span>
      `;
              button.onclick = async () => {
                try {
                  await action.handler();
                } catch (error) {
                  console.error("Quick action failed:", error);
                }
              };
              this.container.appendChild(button);
            });
          }
          registerDefaultActions() {
            // Emergency: Show only critical vulnerabilities
            this.registerAction({
              id: "emergency-filter",
              label: "Emergency",
              icon: "🚨",
              type: "danger",
              shortcut: "Alt+E",
              handler: () => {
                const dashboard = window.vulnDashboard;
                if (dashboard) {
                  dashboard.filters.severity = "CRITICAL";
                  dashboard.filters.epssMin = 90;
                  dashboard.applyFilters();
                  window.securityAlerts.addAlert({
                    type: "warning",
                    title: "Emergency Filter Applied",
                    message: "Showing only Critical vulnerabilities with EPSS ≥ 90%",
                    priority: 90,
                    dismissible: true,
                    autoHide: 5000,
                  });
                }
              },
            });
            // Quick export for SIEM
            this.registerAction({
              id: "siem-export",
              label: "SIEM Export",
              icon: "📡",
              type: "primary",
              shortcut: "Alt+S",
              handler: () => {
                const dashboard = window.vulnDashboard;
                if (dashboard) {
                  // Export in SIEM-friendly JSON format
                  const siemData = dashboard.filteredVulns.map((vuln) => ({
                    timestamp: new Date().toISOString(),
                    event_type: "vulnerability_alert",
                    severity: vuln.severity,
                    cve_id: vuln.cveId,
                    cvss_score: vuln.cvssScore,
                    epss_score: vuln.epssPercentile,
                    vendors: vuln.vendors,
                    products: vuln.products,
                    tags: vuln.tags,
                    published_date: vuln.publishedDate,
                  }));
                  const blob = new Blob([JSON.stringify(siemData, null, 2)], {
                    type: "application/json",
                  });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `vuln-siem-export-${new Date().toISOString().slice(0, 10)}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                  window.securityAlerts.addAlert({
                    type: "success",
                    title: "SIEM Export Complete",
                    message: `Exported ${siemData.length} vulnerabilities in SIEM format`,
                    priority: 70,
                    dismissible: true,
                    autoHide: 3000,
                  });
                }
              },
            });
            // Risk assessment summary
            this.registerAction({
              id: "risk-summary",
              label: "Risk Summary",
              icon: "📊",
              type: "secondary",
              shortcut: "Alt+R",
              handler: () => {
                const dashboard = window.vulnDashboard;
                if (dashboard) {
                  const vulns = dashboard.filteredVulns;
                  const critical = vulns.filter((v) => v.severity === "CRITICAL").length;
                  const high = vulns.filter((v) => v.severity === "HIGH").length;
                  const highEpss = vulns.filter((v) => v.epssPercentile >= 80).length;
                  window.securityAlerts.addAlert({
                    type: "info",
                    title: "Risk Assessment Summary",
                    message: `
              <strong>Current Risk Profile:</strong><br>
              • ${critical} Critical vulnerabilities<br>
              • ${high} High severity vulnerabilities<br>
              • ${highEpss} vulnerabilities with EPSS ≥ 80%<br>
              • Total filtered: ${vulns.length} vulnerabilities
            `,
                    priority: 60,
                    dismissible: true,
                    actions: [
                      {
                        id: "focus-critical",
                        label: "Focus on Critical",
                        type: "danger",
                        handler: () => {
                          dashboard.filters.severity = "CRITICAL";
                          dashboard.applyFilters();
                        },
                      },
                      {
                        id: "high-exploitation",
                        label: "High Exploitation Risk",
                        type: "primary",
                        handler: () => {
                          dashboard.filters.epssMin = 80;
                          dashboard.applyFilters();
                        },
                      },
                    ],
                  });
                }
              },
            });
            // Setup keyboard shortcuts for quick actions
            document.addEventListener("keydown", (event) => {
              if (event.altKey) {
                switch (event.key.toLowerCase()) {
                  case "e":
                    event.preventDefault();
                    this.actions.get("emergency-filter")?.handler();
                    break;
                  case "s":
                    event.preventDefault();
                    this.actions.get("siem-export")?.handler();
                    break;
                  case "r":
                    event.preventDefault();
                    this.actions.get("risk-summary")?.handler();
                    break;
                }
              }
            });
          }
        }
        /**
         * Alpine.js component for security alerts and quick actions
         */
        function createSecurityComponent() {
          return {
            alertSystem: new SecurityAlertSystem(),
            quickActions: new QuickActionsManager(),
            alerts: [],
            showAlerts: true,
            init() {
              // Subscribe to alert updates
              this.alertSystem.subscribe((alerts) => {
                this.alerts = alerts;
              });
              // Set up contextual security monitoring
              this.setupSecurityMonitoring();
              // Make globally available
              window.securityAlerts = this.alertSystem;
              window.quickActions = this.quickActions;
            },
            setupSecurityMonitoring() {
              // Monitor for high-risk vulnerability patterns
              // Note: This will be called manually when vulnerabilities change
              const monitorVulnerabilities = (vulns) => {
                if (!vulns || vulns.length === 0) return;
                const highEpssCount = vulns.filter((v) => v.epssPercentile >= 90).length;
                const recentCritical = vulns.filter((v) => {
                  const publishedDate = new Date(v.publishedDate);
                  const daysSincePublished =
                    (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60 * 24);
                  return v.severity === "CRITICAL" && daysSincePublished <= 7;
                }).length;
                // Alert for newly published critical vulnerabilities
                if (recentCritical > 0) {
                  this.alertSystem.addAlert({
                    type: "critical",
                    title: "New Critical Vulnerabilities Detected",
                    message:
                      `${recentCritical} critical vulnerabilities published in the last 7 days ` +
                      "require immediate attention.",
                    priority: 100,
                    dismissible: true,
                    actions: [
                      {
                        id: "view-recent-critical",
                        label: "View Recent Critical",
                        type: "danger",
                        handler: () => {
                          const dashboard = window.vulnDashboard;
                          if (dashboard) {
                            dashboard.filters.severity = "CRITICAL";
                            dashboard.filters.publishedDateFrom = new Date(
                              Date.now() - 7 * 24 * 60 * 60 * 1000
                            )
                              .toISOString()
                              .split("T")[0];
                            dashboard.applyFilters();
                          }
                        },
                      },
                    ],
                  });
                }
                // Alert for high exploitation probability
                if (highEpssCount > 5) {
                  this.alertSystem.addAlert({
                    type: "warning",
                    title: "High Exploitation Risk Detected",
                    message:
                      `${highEpssCount} vulnerabilities have EPSS scores ≥ 90%, ` +
                      "indicating very high exploitation likelihood.",
                    priority: 80,
                    dismissible: true,
                    actions: [
                      {
                        id: "focus-high-epss",
                        label: "Focus High EPSS",
                        type: "primary",
                        handler: () => {
                          const dashboard = window.vulnDashboard;
                          if (dashboard) {
                            dashboard.filters.epssMin = 90;
                            dashboard.applyFilters();
                          }
                        },
                      },
                    ],
                  });
                }
              };
              // Make monitoring function available for manual calls
              this.monitorVulnerabilities = monitorVulnerabilities;
            },
            toggleAlerts() {
              this.showAlerts = !this.showAlerts;
            },
            dismissAlert(id) {
              this.alertSystem.removeAlert(id);
            },
            clearAllAlerts() {
              this.alertSystem.clearAlerts();
            },
          };
        }

        /***/
      },

    /***/ "./src/assets/ts/components/VirtualScroll.ts":
      /*!***************************************************!*\
  !*** ./src/assets/ts/components/VirtualScroll.ts ***!
  \***************************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ VirtualScrollManager: () => /* binding */ VirtualScrollManager,
          /* harmony export */ createVirtualTableComponent: () =>
            /* binding */ createVirtualTableComponent,
          /* harmony export */
        });
        /**
         * Virtual Scrolling Component for Performance Optimization
         * Renders only visible rows to handle large datasets efficiently
         */
        class VirtualScrollManager {
          constructor(container, config) {
            this.items = [];
            this.startIndex = 0;
            this.endIndex = 0;
            this.scrollTop = 0;
            this.totalHeight = 0;
            this.renderedItems = new Map();
            this.resizeObserver = null;
            this.scrollTimeout = null;
            this.container = container;
            this.config = config;
            this.init();
          }
          init() {
            this.setupContainer();
            this.setupViewport();
            this.setupScrollListener();
            this.setupResizeObserver();
          }
          setupContainer() {
            this.container.style.position = "relative";
            this.container.style.overflow = "auto";
            this.container.style.height = `${this.config.containerHeight}px`;
          }
          setupViewport() {
            this.viewport = document.createElement("div");
            this.viewport.className = "virtual-scroll-viewport";
            this.viewport.style.cssText = `
      position: relative;
      width: 100%;
      min-height: 100%;
    `;
            this.container.appendChild(this.viewport);
          }
          setupScrollListener() {
            let ticking = false;
            this.container.addEventListener("scroll", () => {
              if (!ticking) {
                requestAnimationFrame(() => {
                  this.handleScroll();
                  ticking = false;
                });
                ticking = true;
              }
              // Track scrolling state for optimizations
              if (this.scrollTimeout) {
                clearTimeout(this.scrollTimeout);
              }
              this.scrollTimeout = window.setTimeout(() => {
                // Scrolling ended
              }, 150);
            });
          }
          setupResizeObserver() {
            if ("ResizeObserver" in window) {
              this.resizeObserver = new ResizeObserver(() => {
                this.updateLayout();
              });
              this.resizeObserver.observe(this.container);
            }
          }
          handleScroll() {
            this.scrollTop = this.container.scrollTop;
            this.updateVisibleRange();
            this.renderItems();
          }
          updateVisibleRange() {
            const containerHeight = this.container.clientHeight;
            const itemHeight = this.config.itemHeight;
            // Calculate visible range with overscan
            const startIndex = Math.max(
              0,
              Math.floor(this.scrollTop / itemHeight) - this.config.overscan
            );
            const visibleItemCount = Math.ceil(containerHeight / itemHeight);
            const endIndex = Math.min(
              this.items.length,
              startIndex + visibleItemCount + this.config.overscan * 2
            );
            this.startIndex = startIndex;
            this.endIndex = endIndex;
          }
          renderItems() {
            // Clear existing rendered items that are outside the visible range
            this.renderedItems.forEach((element, id) => {
              const itemIndex = this.items.findIndex((item) => item.id === id);
              if (itemIndex < this.startIndex || itemIndex >= this.endIndex) {
                element.remove();
                this.renderedItems.delete(id);
              }
            });
            // Render items in the visible range
            for (let i = this.startIndex; i < this.endIndex; i++) {
              const item = this.items[i];
              if (!item) continue;
              if (!this.renderedItems.has(item.id)) {
                const element = this.config.renderItem(item, i);
                this.positionItem(element, i);
                this.viewport.appendChild(element);
                this.renderedItems.set(item.id, element);
              }
            }
            // Update total height for scrollbar
            this.updateTotalHeight();
          }
          positionItem(element, index) {
            const item = this.items[index];
            if (!item) return;
            const itemHeight = this.config.getItemHeight
              ? this.config.getItemHeight(item, index)
              : this.config.itemHeight;
            element.style.position = "absolute";
            element.style.top = `${index * this.config.itemHeight}px`;
            element.style.height = `${itemHeight}px`;
            element.style.width = "100%";
            element.style.boxSizing = "border-box";
          }
          updateTotalHeight() {
            this.totalHeight = this.items.length * this.config.itemHeight;
            this.viewport.style.height = `${this.totalHeight}px`;
          }
          updateLayout() {
            this.updateVisibleRange();
            this.renderItems();
          }
          /**
           * Set the items to be rendered
           */
          setItems(items) {
            this.items = items;
            this.updateLayout();
          }
          /**
           * Update a specific item
           */
          updateItem(id, data) {
            const index = this.items.findIndex((item) => item.id === id);
            if (index >= 0 && this.items[index]) {
              this.items[index].data = data;
              // Re-render if item is currently visible
              if (index >= this.startIndex && index < this.endIndex) {
                const existingElement = this.renderedItems.get(id);
                if (existingElement) {
                  existingElement.remove();
                  this.renderedItems.delete(id);
                }
                const item = this.items[index];
                if (item) {
                  const newElement = this.config.renderItem(item, index);
                  this.positionItem(newElement, index);
                  this.viewport.appendChild(newElement);
                  this.renderedItems.set(id, newElement);
                }
              }
            }
          }
          /**
           * Add new items
           */
          addItems(newItems) {
            this.items.push(...newItems);
            this.updateLayout();
          }
          /**
           * Remove items
           */
          removeItems(ids) {
            this.items = this.items.filter((item) => !ids.includes(item.id));
            // Remove from rendered items
            ids.forEach((id) => {
              const element = this.renderedItems.get(id);
              if (element) {
                element.remove();
                this.renderedItems.delete(id);
              }
            });
            this.updateLayout();
          }
          /**
           * Scroll to a specific item
           */
          scrollToItem(id) {
            const index = this.items.findIndex((item) => item.id === id);
            if (index >= 0) {
              const targetScrollTop = index * this.config.itemHeight;
              this.container.scrollTo({
                top: targetScrollTop,
                behavior: "smooth",
              });
            }
          }
          /**
           * Get current scroll position info
           */
          getScrollInfo() {
            return {
              scrollTop: this.scrollTop,
              startIndex: this.startIndex,
              endIndex: this.endIndex,
              totalItems: this.items.length,
              visibleItems: this.endIndex - this.startIndex,
            };
          }
          /**
           * Cleanup
           */
          destroy() {
            if (this.resizeObserver) {
              this.resizeObserver.disconnect();
            }
            if (this.scrollTimeout) {
              clearTimeout(this.scrollTimeout);
            }
            this.renderedItems.clear();
          }
        }
        /**
         * Alpine.js component for virtual scrolling vulnerability table
         */
        function createVirtualTableComponent() {
          return {
            virtualScroll: null,
            isVirtualized: false,
            virtualizationThreshold: 100, // Virtualize when more than 100 items
            init() {
              // Note: Manual watching will be set up by the parent component
            },
            handleVulnerabilityChange(vulnerabilities) {
              const shouldVirtualize = vulnerabilities.length > this.virtualizationThreshold;
              if (shouldVirtualize && !this.isVirtualized) {
                this.enableVirtualization(vulnerabilities);
              } else if (!shouldVirtualize && this.isVirtualized) {
                this.disableVirtualization();
              } else if (this.isVirtualized && this.virtualScroll) {
                this.updateVirtualItems(vulnerabilities);
              }
            },
            enableVirtualization(vulnerabilities) {
              const tableContainer = document.querySelector(".vuln-table");
              if (!tableContainer) return;
              // Hide regular table
              const regularTable = tableContainer.querySelector("table");
              if (regularTable) {
                regularTable.style.display = "none";
              }
              // Create virtual scroll container
              const virtualContainer = document.createElement("div");
              virtualContainer.className = "virtual-vuln-table";
              virtualContainer.style.height = "600px"; // Fixed height for virtual scrolling
              tableContainer.appendChild(virtualContainer);
              const config = {
                itemHeight: 60, // Approximate row height
                containerHeight: 600,
                overscan: 5,
                renderItem: (item, index) => {
                  return this.renderVulnerabilityRow(item.data, index);
                },
              };
              this.virtualScroll = new VirtualScrollManager(virtualContainer, config);
              this.updateVirtualItems(vulnerabilities);
              this.isVirtualized = true;
              // Show virtualization indicator
              this.showVirtualizationStatus(true, vulnerabilities.length);
            },
            disableVirtualization() {
              if (this.virtualScroll) {
                this.virtualScroll.destroy();
                this.virtualScroll = null;
              }
              // Remove virtual container
              const virtualContainer = document.querySelector(".virtual-vuln-table");
              if (virtualContainer) {
                virtualContainer.remove();
              }
              // Show regular table
              const regularTable = document.querySelector(".vuln-table table");
              if (regularTable) {
                regularTable.style.display = "";
              }
              this.isVirtualized = false;
              this.showVirtualizationStatus(false, 0);
            },
            updateVirtualItems(vulnerabilities) {
              if (!this.virtualScroll) return;
              const items = vulnerabilities.map((vuln) => ({
                id: vuln.cveId,
                data: vuln,
              }));
              this.virtualScroll.setItems(items);
            },
            renderVulnerabilityRow(vulnerability, _index) {
              const row = document.createElement("div");
              row.className = "virtual-vuln-row";
              row.setAttribute("role", "row");
              // Apply zebra striping
              if (_index % 2 === 1) {
                row.classList.add("virtual-vuln-row--alt");
              }
              row.innerHTML = `
        <div class="virtual-vuln-cell virtual-vuln-cell--cve">
          <button 
            type="button"
            class="cve-link-button"
            onclick="window.vulnDashboard.openCveModal('${vulnerability.cveId}')"
            aria-label="View details for ${vulnerability.cveId}"
          >
            ${vulnerability.cveId}
          </button>
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--title">
          ${this.truncateText(vulnerability.title, 80)}
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--cvss">
          <span class="score ${this.getSeverityClass(vulnerability.cvssScore)}" 
                aria-label="CVSS score: ${vulnerability.cvssScore}, " +
                  "severity: ${vulnerability.severity}">
            ${vulnerability.cvssScore ?? "N/A"}
          </span>
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--epss">
          <span aria-label="EPSS percentile: ${vulnerability.epssPercentile}%">
            ${vulnerability.epssPercentile}%
          </span>
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--date">
          <time datetime="${vulnerability.publishedDate}" 
                aria-label="Published on ${this.formatDate(vulnerability.publishedDate)}">
            ${this.formatDate(vulnerability.publishedDate)}
          </time>
        </div>
      `;
              // Add hover and focus interactions
              row.addEventListener("mouseenter", () => {
                row.classList.add("virtual-vuln-row--hover");
              });
              row.addEventListener("mouseleave", () => {
                row.classList.remove("virtual-vuln-row--hover");
              });
              return row;
            },
            showVirtualizationStatus(enabled, itemCount) {
              let statusElement = document.getElementById("virtualization-status");
              if (!statusElement) {
                statusElement = document.createElement("div");
                statusElement.id = "virtualization-status";
                statusElement.className = "virtualization-status";
                statusElement.setAttribute("role", "status");
                statusElement.setAttribute("aria-live", "polite");
                const tableSection = document.querySelector(".vuln-table-section");
                if (tableSection) {
                  tableSection.insertBefore(statusElement, tableSection.firstChild);
                }
              }
              if (enabled) {
                statusElement.innerHTML = `
          <div class="virtualization-indicator">
            <span class="virtualization-icon">⚡</span>
            <span class="virtualization-text">
              Virtual scrolling enabled for ${itemCount.toLocaleString()} items
            </span>
            <span class="virtualization-help">
              Only visible rows are rendered for optimal performance
            </span>
          </div>
        `;
                statusElement.style.display = "block";
              } else {
                statusElement.style.display = "none";
              }
            },
            truncateText(text, maxLength) {
              if (text.length <= maxLength) return text;
              return text.substring(0, maxLength - 3) + "...";
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
            scrollToTop() {
              if (this.virtualScroll) {
                this.virtualScroll.scrollToItem(
                  this.virtualScroll.getScrollInfo().startIndex.toString()
                );
              } else {
                const tableContainer = document.querySelector(".vuln-table");
                if (tableContainer) {
                  tableContainer.scrollTo({ top: 0, behavior: "smooth" });
                }
              }
            },
            getPerformanceInfo() {
              if (this.virtualScroll) {
                const info = this.virtualScroll.getScrollInfo();
                return {
                  virtualized: true,
                  totalItems: info.totalItems,
                  renderedItems: info.visibleItems,
                  scrollPosition: Math.round((info.scrollTop / (info.totalItems * 60)) * 100),
                };
              }
              return {
                virtualized: false,
                totalItems: 0,
                renderedItems: 0,
                scrollPosition: 0,
              };
            },
          };
        }

        /***/
      },

    /***/ "./src/assets/ts/components/WidgetManager.ts":
      /*!***************************************************!*\
  !*** ./src/assets/ts/components/WidgetManager.ts ***!
  \***************************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ WidgetManager: () => /* binding */ WidgetManager,
          /* harmony export */ createWidgetManager: () => /* binding */ createWidgetManager,
          /* harmony export */
        });
        /**
         * Widget Management System for Dashboard Customization
         */
        class WidgetManager {
          constructor() {
            this.storageKey = "vuln_widget_preferences";
            this.defaultLayouts = this.createDefaultLayouts();
            this.preferences = this.loadPreferences();
          }
          /**
           * Create default dashboard layouts
           */
          createDefaultLayouts() {
            return [
              {
                id: "security-analyst",
                name: "Security Analyst",
                widgets: [
                  {
                    id: "filters",
                    type: "filters",
                    title: "Search & Filters",
                    size: "full",
                    visible: true,
                    order: 1,
                    config: { collapsed: false },
                  },
                  {
                    id: "vulnerability-table",
                    type: "table",
                    title: "Vulnerabilities",
                    size: "large",
                    visible: true,
                    order: 2,
                    config: { pageSize: 50 },
                  },
                  {
                    id: "risk-stats",
                    type: "stats",
                    title: "Risk Overview",
                    size: "small",
                    visible: true,
                    order: 3,
                    config: { showTrends: true },
                  },
                ],
                gridTemplate: "repeat(12, 1fr)",
                breakpoints: {
                  desktop: { template: "repeat(12, 1fr)", columns: 12 },
                  tablet: { template: "repeat(8, 1fr)", columns: 8 },
                  mobile: { template: "1fr", columns: 1 },
                },
                lastModified: Date.now(),
              },
              {
                id: "executive-dashboard",
                name: "Executive Dashboard",
                widgets: [
                  {
                    id: "risk-overview",
                    type: "chart",
                    title: "Risk Distribution",
                    size: "medium",
                    visible: true,
                    order: 1,
                    config: { chartType: "donut" },
                  },
                  {
                    id: "trend-chart",
                    type: "chart",
                    title: "CVE Trends",
                    size: "medium",
                    visible: true,
                    order: 2,
                    config: { chartType: "line", period: "30d" },
                  },
                  {
                    id: "key-metrics",
                    type: "stats",
                    title: "Key Metrics",
                    size: "full",
                    visible: true,
                    order: 3,
                    config: { showComparison: true },
                  },
                  {
                    id: "top-vendors",
                    type: "chart",
                    title: "Most Affected Vendors",
                    size: "medium",
                    visible: true,
                    order: 4,
                    config: { chartType: "bar", limit: 10 },
                  },
                  {
                    id: "recent-activity",
                    type: "timeline",
                    title: "Recent Activity",
                    size: "medium",
                    visible: true,
                    order: 5,
                    config: { limit: 10 },
                  },
                ],
                gridTemplate: "repeat(12, 1fr)",
                breakpoints: {
                  desktop: { template: "repeat(12, 1fr)", columns: 12 },
                  tablet: { template: "repeat(8, 1fr)", columns: 8 },
                  mobile: { template: "1fr", columns: 1 },
                },
                lastModified: Date.now(),
              },
              {
                id: "researcher-view",
                name: "Researcher View",
                widgets: [
                  {
                    id: "advanced-filters",
                    type: "filters",
                    title: "Advanced Search",
                    size: "medium",
                    visible: true,
                    order: 1,
                    config: { showAdvanced: true },
                  },
                  {
                    id: "saved-searches",
                    type: "filters",
                    title: "Saved Searches",
                    size: "small",
                    visible: true,
                    order: 2,
                    config: { component: "saved-searches" },
                  },
                  {
                    id: "detailed-table",
                    type: "table",
                    title: "Detailed Results",
                    size: "full",
                    visible: true,
                    order: 3,
                    config: { showAllColumns: true, pageSize: 100 },
                  },
                  {
                    id: "export-tools",
                    type: "custom",
                    title: "Export Tools",
                    size: "small",
                    visible: true,
                    order: 4,
                    config: { formats: ["json", "csv", "pdf"] },
                  },
                ],
                gridTemplate: "repeat(12, 1fr)",
                breakpoints: {
                  desktop: { template: "repeat(12, 1fr)", columns: 12 },
                  tablet: { template: "repeat(8, 1fr)", columns: 8 },
                  mobile: { template: "1fr", columns: 1 },
                },
                lastModified: Date.now(),
              },
            ];
          }
          /**
           * Load preferences from localStorage
           */
          loadPreferences() {
            try {
              const stored = localStorage.getItem(this.storageKey);
              if (stored) {
                const parsed = JSON.parse(stored);
                // Merge with defaults to handle version updates
                return {
                  currentLayoutId: parsed.currentLayoutId ?? "security-analyst",
                  layouts: [...this.defaultLayouts, ...(parsed.layouts ?? [])],
                  customWidgets: parsed.customWidgets ?? [],
                };
              }
            } catch (error) {
              console.warn("Failed to load widget preferences:", error);
            }
            return {
              currentLayoutId: "security-analyst",
              layouts: this.defaultLayouts,
              customWidgets: [],
            };
          }
          /**
           * Save preferences to localStorage
           */
          savePreferences() {
            try {
              localStorage.setItem(this.storageKey, JSON.stringify(this.preferences));
            } catch (error) {
              console.error("Failed to save widget preferences:", error);
            }
          }
          /**
           * Get current layout
           */
          getCurrentLayout() {
            return (
              this.preferences.layouts.find(
                (layout) => layout.id === this.preferences.currentLayoutId
              ) ??
              this.preferences.layouts[0] ??
              null
            );
          }
          /**
           * Get all available layouts
           */
          getLayouts() {
            return this.preferences.layouts;
          }
          /**
           * Switch to a different layout
           */
          switchLayout(layoutId) {
            const layout = this.preferences.layouts.find((l) => l.id === layoutId);
            if (layout) {
              this.preferences.currentLayoutId = layoutId;
              this.savePreferences();
              return true;
            }
            return false;
          }
          /**
           * Create a new custom layout
           */
          createLayout(name, baseLayoutId) {
            const baseLayout = baseLayoutId
              ? this.preferences.layouts.find((l) => l.id === baseLayoutId)
              : this.getCurrentLayout();
            const newLayout = {
              id: `custom-${Date.now()}`,
              name,
              widgets: baseLayout ? [...baseLayout.widgets] : [],
              gridTemplate: baseLayout?.gridTemplate ?? "repeat(12, 1fr)",
              breakpoints: baseLayout?.breakpoints ?? {
                desktop: { template: "repeat(12, 1fr)", columns: 12 },
                tablet: { template: "repeat(8, 1fr)", columns: 8 },
                mobile: { template: "1fr", columns: 1 },
              },
              lastModified: Date.now(),
            };
            this.preferences.layouts.push(newLayout);
            this.savePreferences();
            return newLayout.id;
          }
          /**
           * Update widget configuration
           */
          updateWidget(layoutId, widgetId, updates) {
            const layout = this.preferences.layouts.find((l) => l.id === layoutId);
            if (!layout) return false;
            const widget = layout.widgets.find((w) => w.id === widgetId);
            if (!widget) return false;
            Object.assign(widget, updates);
            layout.lastModified = Date.now();
            this.savePreferences();
            return true;
          }
          /**
           * Add widget to layout
           */
          addWidget(layoutId, widget) {
            const layout = this.preferences.layouts.find((l) => l.id === layoutId);
            if (!layout) return false;
            const newWidget = {
              ...widget,
              id: `widget-${Date.now()}`,
              order: Math.max(...layout.widgets.map((w) => w.order), 0) + 1,
            };
            layout.widgets.push(newWidget);
            layout.lastModified = Date.now();
            this.savePreferences();
            return true;
          }
          /**
           * Remove widget from layout
           */
          removeWidget(layoutId, widgetId) {
            const layout = this.preferences.layouts.find((l) => l.id === layoutId);
            if (!layout) return false;
            const index = layout.widgets.findIndex((w) => w.id === widgetId);
            if (index === -1) return false;
            layout.widgets.splice(index, 1);
            layout.lastModified = Date.now();
            this.savePreferences();
            return true;
          }
          /**
           * Reorder widgets in layout
           */
          reorderWidgets(layoutId, widgetOrder) {
            const layout = this.preferences.layouts.find((l) => l.id === layoutId);
            if (!layout) return false;
            // Update order based on new positions
            widgetOrder.forEach((widgetId, index) => {
              const widget = layout.widgets.find((w) => w.id === widgetId);
              if (widget) {
                widget.order = index + 1;
              }
            });
            layout.widgets.sort((a, b) => a.order - b.order);
            layout.lastModified = Date.now();
            this.savePreferences();
            return true;
          }
          /**
           * Delete custom layout
           */
          deleteLayout(layoutId) {
            const index = this.preferences.layouts.findIndex((l) => l.id === layoutId);
            if (index === -1) return false;
            // Don't delete default layouts
            const layout = this.preferences.layouts[index];
            if (layout && this.defaultLayouts.some((dl) => dl.id === layout.id)) {
              return false;
            }
            this.preferences.layouts.splice(index, 1);
            // Switch to first available layout if current was deleted
            if (this.preferences.currentLayoutId === layoutId) {
              this.preferences.currentLayoutId =
                this.preferences.layouts[0]?.id ?? "security-analyst";
            }
            this.savePreferences();
            return true;
          }
          /**
           * Export layout configuration
           */
          exportLayout(layoutId) {
            const layout = this.preferences.layouts.find((l) => l.id === layoutId);
            if (!layout) return null;
            return JSON.stringify(layout, null, 2);
          }
          /**
           * Import layout configuration
           */
          importLayout(configJson) {
            try {
              const layout = JSON.parse(configJson);
              // Validate required fields
              if (!layout.id || !layout.name || !Array.isArray(layout.widgets)) {
                throw new Error("Invalid layout configuration");
              }
              // Generate new ID if conflicting
              if (this.preferences.layouts.some((l) => l.id === layout.id)) {
                layout.id = `imported-${Date.now()}`;
                layout.name = `${layout.name} (Imported)`;
              }
              layout.lastModified = Date.now();
              this.preferences.layouts.push(layout);
              this.savePreferences();
              return layout.id;
            } catch (error) {
              console.error("Failed to import layout:", error);
              return null;
            }
          }
          /**
           * Reset to default layouts
           */
          resetToDefaults() {
            this.preferences = {
              currentLayoutId: "security-analyst",
              layouts: this.defaultLayouts,
              customWidgets: [],
            };
            this.savePreferences();
          }
          /**
           * Get widget grid CSS classes based on size and breakpoint
           */
          getWidgetGridClasses(widget, breakpoint = "desktop") {
            const sizeMap = {
              desktop: {
                small: "widget-small col-span-3",
                medium: "widget-medium col-span-6",
                large: "widget-large col-span-9",
                full: "widget-full col-span-12",
              },
              tablet: {
                small: "widget-small col-span-4",
                medium: "widget-medium col-span-8",
                large: "widget-large col-span-8",
                full: "widget-full col-span-8",
              },
              mobile: {
                small: "widget-small col-span-1",
                medium: "widget-medium col-span-1",
                large: "widget-large col-span-1",
                full: "widget-full col-span-1",
              },
            };
            return sizeMap[breakpoint][widget.size] || "col-span-6";
          }
        }
        /**
         * Create widget manager instance for Alpine.js
         */
        function createWidgetManager() {
          const manager = new WidgetManager();
          return {
            manager,
            currentLayout: manager.getCurrentLayout(),
            isEditMode: false,
            availableLayouts: manager.getLayouts(),
            // Layout management
            switchLayout(layoutId) {
              if (manager.switchLayout(layoutId)) {
                this.currentLayout = manager.getCurrentLayout();
              }
            },
            createLayout(name, baseLayoutId) {
              const newId = manager.createLayout(name, baseLayoutId);
              this.availableLayouts = manager.getLayouts();
              this.switchLayout(newId);
            },
            deleteLayout(layoutId) {
              if (manager.deleteLayout(layoutId)) {
                this.availableLayouts = manager.getLayouts();
                this.currentLayout = manager.getCurrentLayout();
              }
            },
            // Widget management
            toggleWidget(widgetId) {
              if (!this.currentLayout) return;
              const widget = this.currentLayout.widgets.find((w) => w.id === widgetId);
              if (widget) {
                manager.updateWidget(this.currentLayout.id, widgetId, { visible: !widget.visible });
                this.refreshLayout();
              }
            },
            updateWidgetConfig(widgetId, config) {
              if (!this.currentLayout) return;
              manager.updateWidget(this.currentLayout.id, widgetId, { config });
              this.refreshLayout();
            },
            // Edit mode
            toggleEditMode() {
              this.isEditMode = !this.isEditMode;
            },
            // Utility methods
            refreshLayout() {
              this.currentLayout = manager.getCurrentLayout();
            },
            getVisibleWidgets() {
              return (
                this.currentLayout?.widgets
                  .filter((w) => w.visible)
                  .sort((a, b) => a.order - b.order) ?? []
              );
            },
            exportCurrentLayout() {
              if (!this.currentLayout) return null;
              return manager.exportLayout(this.currentLayout.id);
            },
            importLayout(configJson) {
              const newId = manager.importLayout(configJson);
              if (newId) {
                this.availableLayouts = manager.getLayouts();
                this.switchLayout(newId);
                return true;
              }
              return false;
            },
            resetToDefaults() {
              manager.resetToDefaults();
              this.availableLayouts = manager.getLayouts();
              this.currentLayout = manager.getCurrentLayout();
            },
          };
        }

        /***/
      },

    /***/ "./src/assets/ts/components/widgets/StatsWidget.ts":
      /*!*********************************************************!*\
  !*** ./src/assets/ts/components/widgets/StatsWidget.ts ***!
  \*********************************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ StatsWidget: () => /* binding */ StatsWidget,
          /* harmony export */ createStatsWidget: () => /* binding */ createStatsWidget,
          /* harmony export */
        });
        /**
         * Statistics Widget for Dashboard
         * Displays key vulnerability metrics and trends
         */
        class StatsWidget {
          constructor(config = {}) {
            this.config = config;
            this.vulnerabilities = [];
            this.previousData = [];
          }
          /**
           * Update widget with new vulnerability data
           */
          updateData(vulnerabilities, previousData) {
            this.vulnerabilities = vulnerabilities ?? [];
            this.previousData = previousData ?? [];
          }
          /**
           * Calculate key statistics
           */
          getStatistics() {
            const stats = [];
            // Total vulnerabilities
            const totalChange = this.config.showTrends ? this.calculateChange("total") : undefined;
            stats.push({
              label: "Total CVEs",
              value: this.vulnerabilities.length,
              ...(totalChange && { change: totalChange }),
              icon: "shield-alert",
              color: "primary",
            });
            // Critical vulnerabilities
            const critical = this.vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
            const criticalChange = this.config.showTrends
              ? this.calculateChange("critical")
              : undefined;
            stats.push({
              label: "Critical",
              value: critical,
              ...(criticalChange && { change: criticalChange }),
              icon: "alert-triangle",
              color: "error",
            });
            // High severity vulnerabilities
            const high = this.vulnerabilities.filter((v) => v.severity === "HIGH").length;
            const highChange = this.config.showTrends ? this.calculateChange("high") : undefined;
            stats.push({
              label: "High Severity",
              value: high,
              ...(highChange && { change: highChange }),
              icon: "alert-circle",
              color: "warning",
            });
            // High EPSS scores (>= 90%)
            const highEpss = this.vulnerabilities.filter((v) => v.epssPercentile >= 90).length;
            const highEpssChange = this.config.showTrends
              ? this.calculateChange("highEpss")
              : undefined;
            stats.push({
              label: "High EPSS (90%+)",
              value: highEpss,
              ...(highEpssChange && { change: highEpssChange }),
              icon: "trending-up",
              color: "error",
            });
            // KEV (Known Exploited Vulnerabilities)
            const kev = this.vulnerabilities.filter((v) => v.tags?.includes("KEV")).length;
            const kevChange = this.config.showTrends ? this.calculateChange("kev") : undefined;
            stats.push({
              label: "KEV Listed",
              value: kev,
              ...(kevChange && { change: kevChange }),
              icon: "zap",
              color: "error",
            });
            // Average CVSS score
            const avgCvss =
              this.vulnerabilities.length > 0
                ? (
                    this.vulnerabilities.reduce((sum, v) => sum + (v.cvssScore ?? 0), 0) /
                    this.vulnerabilities.length
                  ).toFixed(1)
                : "0.0";
            const avgCvssChange = this.config.showTrends
              ? this.calculateChange("avgCvss")
              : undefined;
            stats.push({
              label: "Avg CVSS",
              value: avgCvss,
              ...(avgCvssChange && { change: avgCvssChange }),
              icon: "bar-chart",
              color: "primary",
            });
            // Recent vulnerabilities (last 7 days)
            const recentDate = new Date();
            recentDate.setDate(recentDate.getDate() - 7);
            const recent = this.vulnerabilities.filter((v) => {
              const pubDate = new Date(v.publishedDate);
              return pubDate >= recentDate;
            }).length;
            const recentChange = this.config.showTrends
              ? this.calculateChange("recent")
              : undefined;
            stats.push({
              label: "Last 7 Days",
              value: recent,
              ...(recentChange && { change: recentChange }),
              icon: "clock",
              color: "primary",
            });
            // Top affected vendor
            const vendorCounts = this.getVendorCounts();
            const topVendor = vendorCounts[0];
            if (topVendor) {
              stats.push({
                label: `Top Vendor`,
                value: `${topVendor.vendor} (${topVendor.count})`,
                icon: "building",
                color: "primary",
              });
            }
            return stats;
          }
          /**
           * Calculate percentage change from previous period
           */
          calculateChange(metric) {
            if (!this.previousData || this.previousData.length === 0) {
              return undefined;
            }
            let currentValue;
            let previousValue;
            switch (metric) {
              case "total":
                currentValue = this.vulnerabilities.length;
                previousValue = this.previousData.length;
                break;
              case "critical":
                currentValue = this.vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
                previousValue = this.previousData.filter((v) => v.severity === "CRITICAL").length;
                break;
              case "high":
                currentValue = this.vulnerabilities.filter((v) => v.severity === "HIGH").length;
                previousValue = this.previousData.filter((v) => v.severity === "HIGH").length;
                break;
              case "highEpss":
                currentValue = this.vulnerabilities.filter((v) => v.epssPercentile >= 90).length;
                previousValue = this.previousData.filter((v) => v.epssPercentile >= 90).length;
                break;
              case "kev":
                currentValue = this.vulnerabilities.filter((v) => v.tags?.includes("KEV")).length;
                previousValue = this.previousData.filter((v) => v.tags?.includes("KEV")).length;
                break;
              case "avgCvss":
                currentValue =
                  this.vulnerabilities.length > 0
                    ? this.vulnerabilities.reduce((sum, v) => sum + (v.cvssScore ?? 0), 0) /
                      this.vulnerabilities.length
                    : 0;
                previousValue =
                  this.previousData.length > 0
                    ? this.previousData.reduce((sum, v) => sum + (v.cvssScore ?? 0), 0) /
                      this.previousData.length
                    : 0;
                break;
              case "recent":
                const recentDate = new Date();
                recentDate.setDate(recentDate.getDate() - 7);
                currentValue = this.vulnerabilities.filter((v) => {
                  const pubDate = new Date(v.publishedDate);
                  return pubDate >= recentDate;
                }).length;
                previousValue = this.previousData.filter((v) => {
                  const pubDate = new Date(v.publishedDate);
                  const compareDate = new Date(recentDate);
                  compareDate.setDate(compareDate.getDate() - 7);
                  return pubDate >= compareDate && pubDate < recentDate;
                }).length;
                break;
              default:
                return undefined;
            }
            if (previousValue === 0) {
              return currentValue > 0
                ? {
                    value: 100,
                    direction: "positive",
                    period: this.config.period ?? "7d",
                  }
                : undefined;
            }
            const changePercent = ((currentValue - previousValue) / previousValue) * 100;
            const direction =
              changePercent > 0 ? "positive" : changePercent < 0 ? "negative" : "neutral";
            return {
              value: Math.abs(Math.round(changePercent)),
              direction,
              period: this.config.period ?? "7d",
            };
          }
          /**
           * Get vendor vulnerability counts
           */
          getVendorCounts() {
            const vendorMap = new Map();
            this.vulnerabilities.forEach((vuln) => {
              const vendors = vuln.vendors;
              if (vendors && Array.isArray(vendors)) {
                vendors.forEach((vendor) => {
                  if (vendor && typeof vendor === "string") {
                    vendorMap.set(vendor, (vendorMap.get(vendor) ?? 0) + 1);
                  }
                });
              }
            });
            return Array.from(vendorMap.entries())
              .map(([vendor, count]) => ({ vendor, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 10);
          }
          /**
           * Get severity distribution
           */
          getSeverityDistribution() {
            const severityMap = new Map();
            const total = this.vulnerabilities.length;
            this.vulnerabilities.forEach((vuln) => {
              const severity = vuln.severity ?? "UNKNOWN";
              severityMap.set(severity, (severityMap.get(severity) ?? 0) + 1);
            });
            return Array.from(severityMap.entries())
              .map(([severity, count]) => ({
                severity,
                count,
                percentage: total > 0 ? Math.round((count / total) * 100) : 0,
              }))
              .sort((a, b) => {
                const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
                return (order[b.severity] ?? 0) - (order[a.severity] ?? 0);
              });
          }
          /**
           * Get EPSS distribution ranges
           */
          getEpssDistribution() {
            const ranges = [
              { range: "90-100%", min: 90, max: 100 },
              { range: "70-89%", min: 70, max: 89 },
              { range: "50-69%", min: 50, max: 69 },
              { range: "25-49%", min: 25, max: 49 },
              { range: "0-24%", min: 0, max: 24 },
            ];
            const total = this.vulnerabilities.length;
            return ranges.map(({ range, min, max }) => {
              const count = this.vulnerabilities.filter((vuln) => {
                const epss = vuln.epssPercentile ?? 0;
                return epss >= min && epss <= max;
              }).length;
              return {
                range,
                count,
                percentage: total > 0 ? Math.round((count / total) * 100) : 0,
              };
            });
          }
          /**
           * Get timeline data for trend analysis
           */
          getTimelineData(days = 30) {
            const timeline = [];
            const endDate = new Date();
            for (let i = days - 1; i >= 0; i--) {
              const date = new Date(endDate);
              date.setDate(date.getDate() - i);
              const dateStr = date.toISOString().split("T")[0] ?? "";
              const dayVulns = this.vulnerabilities.filter((vuln) => {
                const pubDate = new Date(vuln.publishedDate).toISOString().split("T")[0];
                return pubDate === dateStr;
              });
              timeline.push({
                date: dateStr,
                count: dayVulns.length,
                critical: dayVulns.filter((v) => v.severity === "CRITICAL").length,
                high: dayVulns.filter((v) => v.severity === "HIGH").length,
              });
            }
            return timeline;
          }
        }
        /**
         * Create stats widget for Alpine.js
         */
        function createStatsWidget(config = {}) {
          const widget = new StatsWidget(config);
          return {
            widget,
            statistics: [],
            severityDistribution: [],
            epssDistribution: [],
            timelineData: [],
            loading: false,
            error: null,
            // Initialize with data
            init(vulnerabilities, previousData) {
              this.updateData(vulnerabilities, previousData);
            },
            // Update widget data
            updateData(vulnerabilities, previousData) {
              this.loading = true;
              this.error = null;
              try {
                widget.updateData(vulnerabilities, previousData);
                this.statistics = widget.getStatistics();
                this.severityDistribution = widget.getSeverityDistribution();
                this.epssDistribution = widget.getEpssDistribution();
                this.timelineData = widget.getTimelineData();
              } catch (error) {
                this.error = "Failed to calculate statistics";
                console.error("Stats widget error:", error);
              } finally {
                this.loading = false;
              }
            },
            // Get formatted change text
            getChangeText(change) {
              if (!change) return "";
              const sign =
                change.direction === "positive" ? "+" : change.direction === "negative" ? "-" : "";
              return `${sign}${change.value}% vs ${change.period}`;
            },
            // Get change CSS class
            getChangeClass(change) {
              if (!change) return "";
              return `stat-change ${change.direction}`;
            },
            // Format large numbers
            formatValue(value) {
              if (typeof value === "number") {
                if (value >= 1000000) {
                  return (value / 1000000).toFixed(1) + "M";
                } else if (value >= 1000) {
                  return (value / 1000).toFixed(1) + "K";
                }
                return value.toString();
              }
              return value;
            },
            // Get icon SVG
            getIcon(iconName) {
              const icons = {
                "shield-alert":
                  '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
                "alert-triangle":
                  '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="m12 17 .01 0"/>',
                "alert-circle":
                  '<circle cx="12" cy="12" r="10"/><path d="m9 9 6 6"/><path d="m15 9-6 6"/>',
                "trending-up":
                  '<polyline points="22,7 13.5,15.5 8.5,10.5 2,17"/><polyline points="16,7 22,7 22,13"/>',
                zap: '<polygon points="13,2 3,14 12,14 11,22 21,10 12,10 13,2"/>',
                "bar-chart":
                  '<line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/>',
                clock: '<circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/>',
                building:
                  '<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12h4"/><path d="M6 8h4"/><path d="M16 8h2"/><path d="M16 12h2"/><path d="M16 16h2"/>',
              };
              return icons[iconName] ?? "";
            },
          };
        }

        /***/
      },

    /***/ "./src/assets/ts/components/widgets/TimelineWidget.ts":
      /*!************************************************************!*\
  !*** ./src/assets/ts/components/widgets/TimelineWidget.ts ***!
  \************************************************************/
      /***/ (__unused_webpack_module, __webpack_exports__, __webpack_require__) => {
        __webpack_require__.r(__webpack_exports__);
        /* harmony export */ __webpack_require__.d(__webpack_exports__, {
          /* harmony export */ TimelineWidget: () => /* binding */ TimelineWidget,
          /* harmony export */ createTimelineWidget: () => /* binding */ createTimelineWidget,
          /* harmony export */
        });
        /**
         * Timeline Widget for Dashboard
         * Displays recent vulnerability activity in chronological order
         */
        class TimelineWidget {
          constructor(config = {}) {
            this.config = config;
            this.vulnerabilities = [];
            this.previousData = [];
            this.config = {
              limit: 10,
              showTypes: ["published", "modified", "kev-added"],
              ...config,
            };
          }
          /**
           * Update widget with new vulnerability data
           */
          updateData(vulnerabilities, previousData) {
            this.vulnerabilities = vulnerabilities ?? [];
            this.previousData = previousData ?? [];
          }
          /**
           * Generate timeline events from vulnerability data
           */
          getTimelineEvents() {
            const events = [];
            // Process current vulnerabilities for published events
            this.vulnerabilities.forEach((vuln) => {
              if (this.config.showTypes?.includes("published")) {
                events.push({
                  id: `${vuln.cveId}-published`,
                  type: "published",
                  title: `${vuln.cveId} Published`,
                  description: this.truncateText(
                    (vuln.title ?? vuln.description ?? "No description available").toString(),
                    100
                  ),
                  date: vuln.publishedDate,
                  cveId: vuln.cveId,
                  severity: vuln.severity,
                  metadata: {
                    cvssScore: vuln.cvssScore,
                    epssPercentile: vuln.epssPercentile,
                    vendors: vuln.vendors?.slice(0, 3),
                  },
                });
              }
              // Add modified events if last modified is different from published
              if (
                this.config.showTypes?.includes("modified") &&
                vuln.lastModifiedDate !== vuln.publishedDate
              ) {
                const modifiedDate = new Date(vuln.lastModifiedDate);
                const publishedDate = new Date(vuln.publishedDate);
                // Only include if modified more than 1 day after published
                if (modifiedDate.getTime() - publishedDate.getTime() > 24 * 60 * 60 * 1000) {
                  events.push({
                    id: `${vuln.cveId}-modified`,
                    type: "modified",
                    title: `${vuln.cveId} Updated`,
                    description: `CVE details updated: ${this.truncateText((vuln.title ?? "Information updated").toString(), 80)}`,
                    date: vuln.lastModifiedDate,
                    cveId: vuln.cveId,
                    severity: vuln.severity,
                    metadata: {
                      cvssScore: vuln.cvssScore,
                      epssPercentile: vuln.epssPercentile,
                    },
                  });
                }
              }
              // Add KEV events
              if (this.config.showTypes?.includes("kev-added") && vuln.tags?.includes("KEV")) {
                events.push({
                  id: `${vuln.cveId}-kev`,
                  type: "kev-added",
                  title: `${vuln.cveId} Added to KEV`,
                  description: `Added to CISA Known Exploited Vulnerabilities catalog`,
                  date: vuln.lastModifiedDate, // Use last modified as KEV date
                  cveId: vuln.cveId,
                  severity: vuln.severity,
                  metadata: {
                    cvssScore: vuln.cvssScore,
                    epssPercentile: vuln.epssPercentile,
                  },
                });
              }
            });
            // Add synthetic events for trends and patterns
            if (this.config.showTypes?.includes("epss-updated")) {
              this.addEpssUpdateEvents(events);
            }
            if (this.config.showTypes?.includes("severity-changed")) {
              this.addSeverityChangeEvents(events);
            }
            // Sort events by date (newest first) and limit
            return events
              .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
              .slice(0, this.config.limit ?? 10);
          }
          /**
           * Add EPSS update events (simulated based on high EPSS scores)
           */
          addEpssUpdateEvents(events) {
            const highEpssVulns = this.vulnerabilities.filter((v) => v.epssPercentile >= 90);
            highEpssVulns.slice(0, 3).forEach((vuln) => {
              events.push({
                id: `${vuln.cveId}-epss-high`,
                type: "epss-updated",
                title: `High EPSS Score Alert`,
                description: `${vuln.cveId} now has ${vuln.epssPercentile}% exploitation probability`,
                date: vuln.lastModifiedDate,
                cveId: vuln.cveId,
                severity: vuln.severity,
                metadata: {
                  epssPercentile: vuln.epssPercentile,
                  cvssScore: vuln.cvssScore,
                },
              });
            });
          }
          /**
           * Add severity change events (detected by comparing with previous data)
           */
          addSeverityChangeEvents(events) {
            if (!this.previousData) return;
            const previousMap = new Map(this.previousData.map((v) => [v.cveId, v]));
            this.vulnerabilities.forEach((vuln) => {
              const previous = previousMap.get(vuln.cveId);
              if (previous && previous.severity !== vuln.severity) {
                events.push({
                  id: `${vuln.cveId}-severity-change`,
                  type: "severity-changed",
                  title: `Severity Updated`,
                  description:
                    `${vuln.cveId} severity changed from ` +
                    `${previous.severity} to ${vuln.severity}`,
                  date: vuln.lastModifiedDate,
                  cveId: vuln.cveId,
                  severity: vuln.severity,
                  metadata: {
                    previousSeverity: previous.severity,
                    newSeverity: vuln.severity,
                    cvssScore: vuln.cvssScore,
                  },
                });
              }
            });
          }
          /**
           * Get summary statistics for timeline
           */
          getTimelineSummary(days = 7) {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - days);
            const recentVulns = this.vulnerabilities.filter((v) => {
              const pubDate = new Date(v.publishedDate);
              return pubDate >= cutoffDate;
            });
            const modifiedVulns = this.vulnerabilities.filter((v) => {
              const modDate = new Date(v.lastModifiedDate);
              const pubDate = new Date(v.publishedDate);
              return modDate >= cutoffDate && modDate.getTime() !== pubDate.getTime();
            });
            const kevVulns = this.vulnerabilities.filter((v) => {
              return v.tags?.includes("KEV") && new Date(v.lastModifiedDate) >= cutoffDate;
            });
            const totalEvents = recentVulns.length + modifiedVulns.length + kevVulns.length;
            return {
              totalEvents,
              newCves: recentVulns.length,
              modifiedCves: modifiedVulns.length,
              kevAdditions: kevVulns.length,
              averagePerDay: Math.round((totalEvents / days) * 10) / 10,
            };
          }
          /**
           * Get activity by day for the last N days
           */
          getActivityByDay(days = 30) {
            const activity = [];
            const endDate = new Date();
            for (let i = days - 1; i >= 0; i--) {
              const date = new Date(endDate);
              date.setDate(date.getDate() - i);
              const dateStr = date.toISOString().split("T")[0] ?? "";
              const published = this.vulnerabilities.filter((v) => {
                const pubDate = new Date(v.publishedDate).toISOString().split("T")[0];
                return pubDate === dateStr;
              }).length;
              const modified = this.vulnerabilities.filter((v) => {
                const modDate = new Date(v.lastModifiedDate).toISOString().split("T")[0];
                const pubDate = new Date(v.publishedDate).toISOString().split("T")[0];
                return modDate === dateStr && pubDate !== dateStr;
              }).length;
              activity.push({
                date: dateStr,
                published,
                modified,
                total: published + modified,
              });
            }
            return activity;
          }
          /**
           * Get most active vendors in timeline
           */
          getMostActiveVendors(days = 7) {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - days);
            const recentVulns = this.vulnerabilities.filter((v) => {
              const pubDate = new Date(v.publishedDate);
              return pubDate >= cutoffDate;
            });
            const vendorMap = new Map();
            recentVulns.forEach((vuln) => {
              const vendors = vuln.vendors;
              if (vendors && Array.isArray(vendors)) {
                vendors.forEach((vendor) => {
                  if (vendor && typeof vendor === "string") {
                    vendorMap.set(vendor, (vendorMap.get(vendor) ?? 0) + 1);
                  }
                });
              }
            });
            return Array.from(vendorMap.entries())
              .map(([vendor, count]) => ({ vendor, count }))
              .sort((a, b) => b.count - a.count)
              .slice(0, 5);
          }
          /**
           * Truncate text to specified length
           */
          truncateText(text, maxLength) {
            if (text.length <= maxLength) return text;
            return text.substring(0, maxLength - 3).trim() + "...";
          }
          /**
           * Format relative time
           */
          formatRelativeTime(dateString) {
            const date = new Date(dateString);
            const now = new Date();
            const diffMs = now.getTime() - date.getTime();
            const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
            const diffMinutes = Math.floor(diffMs / (1000 * 60));
            if (diffDays > 0) {
              return `${diffDays} day${diffDays === 1 ? "" : "s"} ago`;
            } else if (diffHours > 0) {
              return `${diffHours} hour${diffHours === 1 ? "" : "s"} ago`;
            } else if (diffMinutes > 0) {
              return `${diffMinutes} minute${diffMinutes === 1 ? "" : "s"} ago`;
            } else {
              return "Just now";
            }
          }
        }
        /**
         * Create timeline widget for Alpine.js
         */
        function createTimelineWidget(config = {}) {
          const widget = new TimelineWidget(config);
          return {
            widget,
            events: [],
            summary: null,
            activityData: [],
            activeVendors: [],
            loading: false,
            error: null,
            selectedTimeRange: "7d",
            // Initialize with data
            init(vulnerabilities, previousData) {
              this.updateData(vulnerabilities, previousData);
            },
            // Update widget data
            updateData(vulnerabilities, previousData) {
              this.loading = true;
              this.error = null;
              try {
                widget.updateData(vulnerabilities, previousData);
                this.refreshData();
              } catch (error) {
                this.error = "Failed to load timeline data";
                console.error("Timeline widget error:", error);
              } finally {
                this.loading = false;
              }
            },
            // Refresh all timeline data
            refreshData() {
              const days = this.getDaysFromRange(this.selectedTimeRange);
              this.events = widget.getTimelineEvents();
              this.summary = widget.getTimelineSummary(days);
              this.activityData = widget.getActivityByDay(days);
              this.activeVendors = widget.getMostActiveVendors(days);
            },
            // Change time range
            changeTimeRange(range) {
              this.selectedTimeRange = range;
              this.refreshData();
            },
            // Get days from range string
            getDaysFromRange(range) {
              switch (range) {
                case "1d":
                  return 1;
                case "7d":
                  return 7;
                case "30d":
                  return 30;
                case "90d":
                  return 90;
                default:
                  return 7;
              }
            },
            // Get event type icon
            getEventIcon(type) {
              const icons = {
                published: "📄",
                modified: "✏️",
                "kev-added": "⚠️",
                "epss-updated": "📈",
                "severity-changed": "🔄",
              };
              return icons[type] ?? "📄";
            },
            // Get event type color class
            getEventColorClass(type) {
              const classes = {
                published: "event-published",
                modified: "event-modified",
                "kev-added": "event-kev",
                "epss-updated": "event-epss",
                "severity-changed": "event-severity",
              };
              return classes[type] ?? "event-default";
            },
            // Get severity badge class
            getSeverityClass(severity) {
              if (!severity) return "";
              return `severity-${severity.toLowerCase()}`;
            },
            // Format date for display
            formatDate(dateString) {
              const date = new Date(dateString);
              return date.toLocaleDateString("en-US", {
                month: "short",
                day: "numeric",
                hour: "2-digit",
                minute: "2-digit",
              });
            },
            // Format relative time
            formatRelativeTime(dateString) {
              return widget.formatRelativeTime(dateString);
            },
            // Open CVE modal (if available)
            openCveDetails(cveId) {
              // This would integrate with the main dashboard's modal
              // Access through global Alpine context or event system
              const event = new CustomEvent("open-cve-modal", { detail: { cveId } });
              document.dispatchEvent(event);
            },
            // Get activity chart data
            getChartData() {
              return this.activityData.map((item) => ({
                x: item.date,
                y: item.total,
                published: item.published,
                modified: item.modified,
              }));
            },
            // Get time range options
            getTimeRangeOptions() {
              return [
                { value: "1d", label: "Last 24 hours" },
                { value: "7d", label: "Last 7 days" },
                { value: "30d", label: "Last 30 days" },
                { value: "90d", label: "Last 90 days" },
              ];
            },
          };
        }

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
    /* harmony import */ var _components_CveModal__WEBPACK_IMPORTED_MODULE_2__ =
      __webpack_require__(/*! ./components/CveModal */ "./src/assets/ts/components/CveModal.ts");
    /* harmony import */ var _components_SavedSearches__WEBPACK_IMPORTED_MODULE_3__ =
      __webpack_require__(
        /*! ./components/SavedSearches */ "./src/assets/ts/components/SavedSearches.ts"
      );
    /* harmony import */ var _components_SecurityAlerts__WEBPACK_IMPORTED_MODULE_4__ =
      __webpack_require__(
        /*! ./components/SecurityAlerts */ "./src/assets/ts/components/SecurityAlerts.ts"
      );
    /* harmony import */ var _components_VirtualScroll__WEBPACK_IMPORTED_MODULE_5__ =
      __webpack_require__(
        /*! ./components/VirtualScroll */ "./src/assets/ts/components/VirtualScroll.ts"
      );
    /* harmony import */ var _components_WidgetManager__WEBPACK_IMPORTED_MODULE_6__ =
      __webpack_require__(
        /*! ./components/WidgetManager */ "./src/assets/ts/components/WidgetManager.ts"
      );
    /* harmony import */ var _components_widgets_StatsWidget__WEBPACK_IMPORTED_MODULE_7__ =
      __webpack_require__(
        /*! ./components/widgets/StatsWidget */ "./src/assets/ts/components/widgets/StatsWidget.ts"
      );
    /* harmony import */ var _components_widgets_TimelineWidget__WEBPACK_IMPORTED_MODULE_8__ =
      __webpack_require__(
        /*! ./components/widgets/TimelineWidget */ "./src/assets/ts/components/widgets/TimelineWidget.ts"
      );
    /**
     * Alpine.js Vulnerability Dashboard - TypeScript Version
     */

    document.addEventListener("alpine:init", () => {
      // Register CVE Modal component
      window.Alpine.data(
        "cveModal",
        _components_CveModal__WEBPACK_IMPORTED_MODULE_2__.createCveModal
      );
      // Register Saved Search component
      window.Alpine.data(
        "savedSearches",
        _components_SavedSearches__WEBPACK_IMPORTED_MODULE_3__.createSavedSearchComponent
      );
      // Register Security Alerts component
      window.Alpine.data(
        "securitySystem",
        _components_SecurityAlerts__WEBPACK_IMPORTED_MODULE_4__.createSecurityComponent
      );
      // Register Virtual Table component
      window.Alpine.data(
        "virtualTable",
        _components_VirtualScroll__WEBPACK_IMPORTED_MODULE_5__.createVirtualTableComponent
      );
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
          publishedDateFrom: "",
          publishedDateTo: "",
          lastModifiedDateFrom: "",
          lastModifiedDateTo: "",
          dateFrom: "", // deprecated, keeping for backwards compatibility
          dateTo: "", // deprecated, keeping for backwards compatibility
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
        // State
        loading: true,
        error: null,
        initialLoad: true,
        // Modal
        modal: (0, _components_CveModal__WEBPACK_IMPORTED_MODULE_2__.createCveModal)(),
        // Saved Searches
        savedSearches: new _components_SavedSearches__WEBPACK_IMPORTED_MODULE_3__.SavedSearches(),
        // Helper function to get date string for n days ago
        getDateDaysAgo(days) {
          const date = new Date();
          date.setDate(date.getDate() - days);
          return date.toISOString().split("T")[0]; // YYYY-MM-DD format
        },
        // Helper function to set default date ranges
        setDefaultDateRanges() {
          // Only set defaults if not already loaded from hash
          if (!this.filters.publishedDateFrom && !this.filters.dateFrom) {
            this.filters.publishedDateFrom = this.getDateDaysAgo(90);
            this.filters.publishedDateTo = ""; // Empty means "today"
          }
          // Keep lastModifiedDate filters empty by default (users can set if needed)
        },
        async init() {
          // Start performance timer
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.startTimer("page-load");
          // Load state from URL hash
          this.loadStateFromHash();
          // Set default date ranges if not loaded from hash
          this.setDefaultDateRanges();
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
          // Make modal available globally for CVE links
          window.cveModal = this.modal;
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
            // Track search and add to recent searches
            _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.trackSearch(
              this.searchQuery,
              results.length
            );
            this.savedSearches.addRecentSearch(this.searchQuery);
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
          // Apply published date filter (use new fields or fall back to deprecated fields)
          const publishedFrom = this.filters.publishedDateFrom || this.filters.dateFrom;
          if (publishedFrom) {
            const fromDate = new Date(publishedFrom);
            results = results.filter((vuln) => new Date(vuln.publishedDate) >= fromDate);
          }
          const publishedTo = this.filters.publishedDateTo || this.filters.dateTo;
          if (publishedTo) {
            const toDate = new Date(publishedTo);
            toDate.setHours(23, 59, 59, 999); // Include entire day
            results = results.filter((vuln) => new Date(vuln.publishedDate) <= toDate);
          }
          // Apply last modified date filter
          if (this.filters.lastModifiedDateFrom) {
            const fromDate = new Date(this.filters.lastModifiedDateFrom);
            results = results.filter((vuln) => new Date(vuln.lastModifiedDate) >= fromDate);
          }
          if (this.filters.lastModifiedDateTo) {
            const toDate = new Date(this.filters.lastModifiedDateTo);
            toDate.setHours(23, 59, 59, 999); // Include entire day
            results = results.filter((vuln) => new Date(vuln.lastModifiedDate) <= toDate);
          }
          // Apply vendor filter
          if (this.filters.vendor) {
            const vendorLower = this.filters.vendor.toLowerCase();
            results = results.filter((vuln) =>
              vuln.vendors.some((v) => v.toLowerCase().includes(vendorLower))
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
          if (this.filters.tags.length > 0) {
            activeFilters.push(`tags: ${this.filters.tags.join(", ")}`);
          }
          // Date filters
          const publishedFrom = this.filters.publishedDateFrom || this.filters.dateFrom;
          const publishedTo = this.filters.publishedDateTo || this.filters.dateTo;
          if (publishedFrom || publishedTo) {
            const fromStr = publishedFrom ? `from ${publishedFrom}` : "";
            const toStr = publishedTo ? `to ${publishedTo}` : "";
            activeFilters.push(`published ${fromStr} ${toStr}`.trim());
          }
          if (this.filters.lastModifiedDateFrom || this.filters.lastModifiedDateTo) {
            const fromStr = this.filters.lastModifiedDateFrom
              ? `from ${this.filters.lastModifiedDateFrom}`
              : "";
            const toStr = this.filters.lastModifiedDateTo
              ? `to ${this.filters.lastModifiedDateTo}`
              : "";
            activeFilters.push(`last modified ${fromStr} ${toStr}`.trim());
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
          // Validate published date range
          const publishedFrom = this.filters.publishedDateFrom || this.filters.dateFrom;
          const publishedTo = this.filters.publishedDateTo || this.filters.dateTo;
          if (publishedFrom && publishedTo) {
            const fromDate = new Date(publishedFrom);
            const toDate = new Date(publishedTo);
            if (fromDate > toDate) {
              errors.push("Published start date cannot be after end date");
            }
          }
          // Validate last modified date range
          if (this.filters.lastModifiedDateFrom && this.filters.lastModifiedDateTo) {
            const fromDate = new Date(this.filters.lastModifiedDateFrom);
            const toDate = new Date(this.filters.lastModifiedDateTo);
            if (fromDate > toDate) {
              errors.push("Last modified start date cannot be after end date");
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
            publishedDateFrom: this.filters.publishedDateFrom,
            publishedDateTo: this.filters.publishedDateTo,
            lastModifiedDateFrom: this.filters.lastModifiedDateFrom,
            lastModifiedDateTo: this.filters.lastModifiedDateTo,
            dateFrom: this.filters.dateFrom, // Keep for backwards compatibility
            dateTo: this.filters.dateTo, // Keep for backwards compatibility
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
            if (
              !value ||
              value === "" ||
              (key === "cvssMin" && value === 0) ||
              (key === "cvssMax" && value === 10) ||
              (key === "epssMin" && value === 0) ||
              (key === "epssMax" && value === 100) ||
              (key === "page" && value === 1) ||
              (key === "size" && value === 50) ||
              (key === "sort" && value === "epssPercentile") ||
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
          this.filters.publishedDateFrom = params.get("publishedDateFrom") ?? "";
          this.filters.publishedDateTo = params.get("publishedDateTo") ?? "";
          this.filters.lastModifiedDateFrom = params.get("lastModifiedDateFrom") ?? "";
          this.filters.lastModifiedDateTo = params.get("lastModifiedDateTo") ?? "";
          this.filters.dateFrom = params.get("dateFrom") ?? ""; // Keep for backwards compatibility
          this.filters.dateTo = params.get("dateTo") ?? ""; // Keep for backwards compatibility
          this.filters.vendor = params.get("vendor") ?? "";
          const tags = params.get("tags");
          this.filters.tags = tags ? tags.split(",").filter((t) => t) : [];
          // Load sorting
          this.sortField = params.get("sort") ?? "epssPercentile";
          this.sortDirection = params.get("dir") ?? "desc";
          // Load pagination
          this.currentPage = parseInt(params.get("page") ?? "1");
          this.pageSize = parseInt(params.get("size") ?? "50");
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
          // Don't re-apply default date ranges after reset - show ALL data
          this.applyFilters();
        },
        exportResults() {
          // Track export
          _analytics__WEBPACK_IMPORTED_MODULE_1__.analytics.trackExport(
            "csv",
            this.filteredVulns.length
          );
          // Create CSV content
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
        async openCveModal(cveId) {
          await this.modal.openModal(cveId);
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
              case "s":
                // Show saved searches (Ctrl+S or Cmd+S)
                if (event.ctrlKey || event.metaKey) {
                  event.preventDefault();
                  const savedSearchComponent = window.savedSearches;
                  if (savedSearchComponent) {
                    savedSearchComponent.showSavedSearches =
                      !savedSearchComponent.showSavedSearches;
                  }
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
    // Make widget components available globally for Alpine.js
    window.createWidgetManager =
      _components_WidgetManager__WEBPACK_IMPORTED_MODULE_6__.createWidgetManager;
    window.createStatsWidget =
      _components_widgets_StatsWidget__WEBPACK_IMPORTED_MODULE_7__.createStatsWidget;
    window.createTimelineWidget =
      _components_widgets_TimelineWidget__WEBPACK_IMPORTED_MODULE_8__.createTimelineWidget;
    // Helper function to get widget component instance
    window.getWidgetComponent = function (widget) {
      return {
        widget,
        // Return empty data object - individual widgets will handle their own initialization
        init() {
          // Widget-specific initialization will happen in the widget components
        },
      };
    };
  })();

  /******/
})();
//# sourceMappingURL=dashboard.js.map
