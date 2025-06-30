/**
 * CVE Details Modal Component
 * Follows WD (Web Design) standards for accessibility, interaction, and responsive design
 */

import type { Vulnerability } from "../types/vulnerability";

export interface CveModalData {
  isOpen: boolean;
  vulnerability: Vulnerability | null;
  loading: boolean;
  error: string | null;
  activeTab: "overview" | "technical" | "timeline" | "references";
  chunkIndex: any | null;
  mainIndex: any | null;
}

export interface CveModalMethods {
  openModal(cveId: string): Promise<void>;
  closeModal(): void;
  loadVulnerabilityDetails(cveId: string): Promise<Vulnerability>;
  switchTab(tab: CveModalData["activeTab"]): void;
  handleKeydown(event: KeyboardEvent): void;
  trapFocus(event: KeyboardEvent): void;
  formatCvssVector(vector: string): { [key: string]: string };
  formatDate(dateStr: string): string;
  getRiskLevelText(score: number): string;
  getSeverityClass(score: number): string;
  getCvssMetrics(
    vulnerability: Vulnerability
  ): Array<{ label: string; value: string; description: string }>;
  getTimelineEvents(
    vulnerability: Vulnerability
  ): Array<{ date: string; event: string; type: "published" | "modified" | "discovered" }>;
}

export type CveModal = CveModalData & CveModalMethods;

/**
 * Creates a CVE modal Alpine.js component
 * Implements WCAG 2.1 AA accessibility standards and responsive design patterns
 */
export function createCveModal(): CveModal {
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
    async openModal(cveId: string): Promise<void> {
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
          const modal = document.querySelector('[data-modal="cve-details"]') as HTMLElement;
          const firstFocusable = modal?.querySelector(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          ) as HTMLElement;
          firstFocusable?.focus();
        }, 0);
      }
    },

    /**
     * Closes modal with proper cleanup
     * Restores focus to trigger element
     */
    closeModal(): void {
      this.isOpen = false;
      this.vulnerability = null;
      this.error = null;

      // Restore body state
      document.body.removeAttribute("aria-hidden");
      document.body.classList.remove("modal-open");

      // Return focus to trigger element
      const triggerElement = document.querySelector(`[data-cve-trigger]`) as HTMLElement;
      triggerElement?.focus();
    },

    /**
     * Loads detailed vulnerability data from chunked storage
     */
    async loadVulnerabilityDetails(cveId: string): Promise<Vulnerability> {
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
          vulnSummary = this.mainIndex.vulnerabilities.find((v: any) => v.cveId === cveId);
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

              const chunk = this.chunkIndex.chunks.find((c: any) => c.key === chunkKey);
              if (chunk) {
                const chunkResponse = await fetch(`/vuln-bot/api/vulns/${chunk.file}`);
                if (chunkResponse.ok) {
                  const chunkData = await chunkResponse.json();
                  const vuln = chunkData.vulnerabilities.find((v: any) => v.cveId === cveId);
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
    switchTab(tab: CveModalData["activeTab"]): void {
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
    handleKeydown(event: KeyboardEvent): void {
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
            const tabs: CveModalData["activeTab"][] = [
              "overview",
              "technical",
              "timeline",
              "references",
            ];
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
    trapFocus(event: KeyboardEvent): void {
      const modal = document.querySelector('[data-modal="cve-details"]') as HTMLElement;
      if (!modal) return;

      const focusableElements = modal.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );

      const firstFocusable = focusableElements[0];
      const lastFocusable = focusableElements[focusableElements.length - 1];

      if (event.shiftKey) {
        if (document.activeElement === firstFocusable) {
          event.preventDefault();
          (lastFocusable as HTMLElement)?.focus();
        }
      } else {
        if (document.activeElement === lastFocusable) {
          event.preventDefault();
          (firstFocusable as HTMLElement)?.focus();
        }
      }
    },

    /**
     * Parses CVSS vector string into readable components
     */
    formatCvssVector(vector: string): { [key: string]: string } {
      const metrics: { [key: string]: string } = {};
      const parts = vector.split("/");

      const cvssMapping: { [key: string]: string } = {
        AV: "Attack Vector",
        AC: "Attack Complexity",
        PR: "Privileges Required",
        UI: "User Interaction",
        S: "Scope",
        C: "Confidentiality",
        I: "Integrity",
        A: "Availability",
      };

      const valueMapping: { [key: string]: string } = {
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
    formatDate(dateStr: string): string {
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
    getRiskLevelText(score: number): string {
      if (score >= 9.0) return "Critical Risk";
      if (score >= 7.0) return "High Risk";
      if (score >= 4.0) return "Medium Risk";
      if (score >= 0.1) return "Low Risk";
      return "Informational";
    },

    /**
     * Gets CSS class for severity level
     */
    getSeverityClass(score: number): string {
      if (score >= 9) return "severity-critical";
      if (score >= 7) return "severity-high";
      if (score >= 4) return "severity-medium";
      if (score > 0) return "severity-low";
      return "severity-none";
    },

    /**
     * Extracts CVSS metrics for display
     */
    getCvssMetrics(
      vulnerability: Vulnerability
    ): Array<{ label: string; value: string; description: string }> {
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
    getTimelineEvents(
      vulnerability: Vulnerability
    ): Array<{ date: string; event: string; type: "published" | "modified" | "discovered" }> {
      const events = [];

      if (vulnerability.publishedDate) {
        events.push({
          date: vulnerability.publishedDate,
          event: `CVE ${vulnerability.cveId} published`,
          type: "published" as const,
        });
      }

      if (
        vulnerability.lastModifiedDate &&
        vulnerability.lastModifiedDate !== vulnerability.publishedDate
      ) {
        events.push({
          date: vulnerability.lastModifiedDate,
          event: "CVE details updated",
          type: "modified" as const,
        });
      }

      // Sort by date, newest first
      return events.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
    },
  };
}
