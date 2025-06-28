/**
 * Frontend analytics for vulnerability dashboard
 */

interface AnalyticsEvent {
  event: string;
  category: string;
  action: string;
  label?: string;
  value?: number;
  metadata?: Record<string, any>;
  timestamp: string;
}

class Analytics {
  private events: AnalyticsEvent[] = [];
  private sessionId: string;
  private startTime: number;
  private isEnabled: boolean = true;

  constructor() {
    this.sessionId = this.generateSessionId();
    this.startTime = Date.now();

    // Check if analytics should be disabled (e.g., DNT header)
    if (navigator.doNotTrack === "1") {
      this.isEnabled = false;
    }

    // Set up page unload handler to save metrics
    window.addEventListener("beforeunload", () => this.flush());
  }

  private generateSessionId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Track a user event
   */
  track(
    event: string,
    category: string,
    action: string,
    label?: string,
    value?: number,
    metadata?: Record<string, unknown>
  ) {
    if (!this.isEnabled) return;

    const analyticsEvent: AnalyticsEvent = {
      event,
      category,
      action,
      timestamp: new Date().toISOString(),
    };

    if (label !== undefined) analyticsEvent.label = label;
    if (value !== undefined) analyticsEvent.value = value;
    if (metadata !== undefined) analyticsEvent.metadata = metadata;

    this.events.push(analyticsEvent);

    // Flush events if buffer is getting large
    if (this.events.length >= 50) {
      this.flush();
    }
  }

  /**
   * Track search queries
   */
  trackSearch(query: string, resultCount: number) {
    this.track("search", "interaction", "search", query, resultCount, { query, resultCount });
  }

  /**
   * Track filter changes
   */
  trackFilter(filterType: string, value: any) {
    this.track("filter_change", "interaction", "filter", filterType, undefined, {
      filterType,
      value,
    });
  }

  /**
   * Track sort changes
   */
  trackSort(field: string, direction: string) {
    this.track("sort_change", "interaction", "sort", `${field}_${direction}`, undefined, {
      field,
      direction,
    });
  }

  /**
   * Track page views
   */
  trackPageView(page: number, pageSize: number) {
    this.track("page_view", "navigation", "pagination", `page_${page}`, pageSize, {
      page,
      pageSize,
    });
  }

  /**
   * Track CSV exports
   */
  trackExport(format: string, count: number) {
    this.track("export", "interaction", "export", format, count, { format, count });
  }

  /**
   * Track vulnerability clicks
   */
  trackVulnerabilityClick(cveId: string, riskScore: number) {
    this.track("vulnerability_click", "interaction", "click", cveId, riskScore, {
      cveId,
      riskScore,
    });
  }

  /**
   * Track performance metrics
   */
  trackPerformance() {
    if (!window.performance || !this.isEnabled) return;

    const perfData = window.performance.timing;
    const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
    const domReadyTime = perfData.domContentLoadedEventEnd - perfData.navigationStart;

    this.track("performance", "technical", "page_load", undefined, pageLoadTime, {
      pageLoadTime,
      domReadyTime,
      sessionDuration: Date.now() - this.startTime,
    });
  }

  /**
   * Get session summary
   */
  getSessionSummary() {
    const sessionDuration = (Date.now() - this.startTime) / 1000; // in seconds

    const eventCounts = this.events.reduce(
      (acc, event) => {
        acc[event.event] = (acc[event.event] ?? 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    );

    return {
      sessionId: this.sessionId,
      sessionDuration,
      eventCount: this.events.length,
      eventTypes: eventCounts,
      startTime: new Date(this.startTime).toISOString(),
      endTime: new Date().toISOString(),
    };
  }

  /**
   * Flush events to storage
   */
  private flush() {
    if (!this.isEnabled || this.events.length === 0) return;

    try {
      // Store in localStorage for now (could be sent to a server endpoint)
      const storageKey = `vuln_analytics_${this.sessionId}`;
      const existingData = localStorage.getItem(storageKey);
      const existing = existingData ? JSON.parse(existingData) : { events: [] };

      existing.events.push(...this.events);
      existing.summary = this.getSessionSummary();

      localStorage.setItem(storageKey, JSON.stringify(existing));

      // Clear events buffer
      this.events = [];

      // Clean up old sessions (keep last 10)
      this.cleanupOldSessions();
    } catch (error) {
      console.error("Failed to save analytics:", error);
    }
  }

  /**
   * Clean up old analytics sessions
   */
  private cleanupOldSessions() {
    try {
      const keys = Object.keys(localStorage).filter((key) => key.startsWith("vuln_analytics_"));

      if (keys.length > 10) {
        // Sort by timestamp and remove oldest
        keys
          .sort()
          .slice(0, -10)
          .forEach((key) => {
            localStorage.removeItem(key);
          });
      }
    } catch (error) {
      console.error("Failed to cleanup old sessions:", error);
    }
  }

  /**
   * Export analytics data
   */
  exportAnalytics(): string {
    const allSessions = Object.keys(localStorage)
      .filter((key) => key.startsWith("vuln_analytics_"))
      .map((key) => {
        try {
          return JSON.parse(localStorage.getItem(key) ?? "{}");
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    return JSON.stringify(allSessions, null, 2);
  }
}

// Export singleton instance
export const analytics = new Analytics();
