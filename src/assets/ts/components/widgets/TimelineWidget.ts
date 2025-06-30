/**
 * Timeline Widget for Dashboard
 * Displays recent vulnerability activity in chronological order
 */

export interface TimelineEvent {
  id: string;
  type: "published" | "modified" | "kev-added" | "epss-updated" | "severity-changed";
  title: string;
  description: string;
  date: string;
  cveId?: string;
  severity?: string;
  metadata?: Record<string, any>;
}

export class TimelineWidget {
  private vulnerabilities: any[] = [];
  private previousData: any[] = [];

  constructor(private config: { limit?: number; showTypes?: string[] } = {}) {
    this.config = {
      limit: 10,
      showTypes: ["published", "modified", "kev-added"],
      ...config,
    };
  }

  /**
   * Update widget with new vulnerability data
   */
  updateData(vulnerabilities: any[], previousData?: any[]): void {
    this.vulnerabilities = vulnerabilities ?? [];
    this.previousData = previousData ?? [];
  }

  /**
   * Generate timeline events from vulnerability data
   */
  getTimelineEvents(): TimelineEvent[] {
    const events: TimelineEvent[] = [];

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
  private addEpssUpdateEvents(events: TimelineEvent[]): void {
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
  private addSeverityChangeEvents(events: TimelineEvent[]): void {
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
            `${vuln.cveId} severity changed from ` + `${previous.severity} to ${vuln.severity}`,
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
  getTimelineSummary(days: number = 7): {
    totalEvents: number;
    newCves: number;
    modifiedCves: number;
    kevAdditions: number;
    averagePerDay: number;
  } {
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
  getActivityByDay(days: number = 30): Array<{
    date: string;
    published: number;
    modified: number;
    total: number;
  }> {
    const activity: Array<{
      date: string;
      published: number;
      modified: number;
      total: number;
    }> = [];

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
  getMostActiveVendors(days: number = 7): Array<{ vendor: string; count: number }> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    const recentVulns = this.vulnerabilities.filter((v) => {
      const pubDate = new Date(v.publishedDate);
      return pubDate >= cutoffDate;
    });

    const vendorMap = new Map<string, number>();

    recentVulns.forEach((vuln) => {
      const vendors = vuln.vendors;
      if (vendors && Array.isArray(vendors)) {
        vendors.forEach((vendor: string) => {
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
  private truncateText(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3).trim() + "...";
  }

  /**
   * Format relative time
   */
  formatRelativeTime(dateString: string): string {
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
export function createTimelineWidget(config: { limit?: number; showTypes?: string[] } = {}) {
  const widget = new TimelineWidget(config);

  return {
    widget,
    events: [] as TimelineEvent[],
    summary: null as any,
    activityData: [] as any[],
    activeVendors: [] as any[],
    loading: false,
    error: null as string | null,
    selectedTimeRange: "7d",

    // Initialize with data
    init(vulnerabilities: any[], previousData?: any[]) {
      this.updateData(vulnerabilities, previousData);
    },

    // Update widget data
    updateData(vulnerabilities: any[], previousData?: any[]) {
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
    changeTimeRange(range: string) {
      this.selectedTimeRange = range;
      this.refreshData();
    },

    // Get days from range string
    getDaysFromRange(range: string): number {
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
    getEventIcon(type: string): string {
      const icons: Record<string, string> = {
        published: "📄",
        modified: "✏️",
        "kev-added": "⚠️",
        "epss-updated": "📈",
        "severity-changed": "🔄",
      };
      return icons[type] ?? "📄";
    },

    // Get event type color class
    getEventColorClass(type: string): string {
      const classes: Record<string, string> = {
        published: "event-published",
        modified: "event-modified",
        "kev-added": "event-kev",
        "epss-updated": "event-epss",
        "severity-changed": "event-severity",
      };
      return classes[type] ?? "event-default";
    },

    // Get severity badge class
    getSeverityClass(severity?: string): string {
      if (!severity) return "";
      return `severity-${severity.toLowerCase()}`;
    },

    // Format date for display
    formatDate(dateString: string): string {
      const date = new Date(dateString);
      return date.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    },

    // Format relative time
    formatRelativeTime(dateString: string): string {
      return widget.formatRelativeTime(dateString);
    },

    // Open CVE modal (if available)
    openCveDetails(cveId: string) {
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
