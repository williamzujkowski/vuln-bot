/**
 * Frontend analytics for vulnerability dashboard
 */

import type { AnalyticsConfig } from "./types";

interface AnalyticsEvent {
  event: string;
  category: string;
  action: string;
  label?: string | undefined;
  value?: number | undefined;
  metadata?: Record<string, unknown> | undefined;
  timestamp: number;
}

interface StoredData {
  events: AnalyticsEvent[];
  sessionId: string;
  lastFlush: number;
}

export class Analytics {
  private events: AnalyticsEvent[] = [];
  private sessionId: string;
  private startTime: number;
  private enabled: boolean = true;
  private config: AnalyticsConfig;
  private timers: Map<string, number> = new Map();
  private flushTimeout?: number | undefined;
  private sessionStartTime?: number | undefined;

  constructor(
    config: AnalyticsConfig = {
      enabled: true,
      storageKey: "vuln_analytics",
      maxEvents: 100,
      flushInterval: 300000,
    }
  ) {
    this.config = config;
    this.sessionId = this.generateSessionId();
    this.startTime = Date.now();

    // Check if analytics should be disabled (e.g., DNT header)
    const dnt =
      (navigator as unknown as { doNotTrack?: string }).doNotTrack ??
      (window as unknown as { doNotTrack?: string }).doNotTrack;
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

  private generateSessionId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private loadEvents(): void {
    if (!this.enabled || !this.config.storageKey) return;

    try {
      const stored = localStorage.getItem(this.config.storageKey);
      if (stored) {
        const data: StoredData = JSON.parse(stored);
        this.events = data.events || [];
      }
    } catch {
      // Ignore errors
    }
  }

  private saveEvents(): void {
    if (!this.enabled || !this.config.storageKey) return;

    const data: StoredData = {
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

  private scheduleFlush(): void {
    if (this.flushTimeout) {
      clearTimeout(this.flushTimeout);
    }

    this.flushTimeout = window.setTimeout(() => {
      this.flush();
      this.scheduleFlush();
    }, this.config.flushInterval);
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  disable(): void {
    this.enabled = false;
  }

  enable(): void {
    this.enabled = true;
  }

  optOut(): void {
    this.enabled = false;
    this.clear();
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
  ): void {
    if (!this.enabled) return;

    const analyticsEvent: AnalyticsEvent = {
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

  getEvents(): AnalyticsEvent[] {
    return [...this.events];
  }

  clear(): void {
    this.events = [];
    if (this.config.storageKey) {
      localStorage.removeItem(this.config.storageKey);
    }
  }

  // Performance tracking
  startTimer(name: string): void {
    this.timers.set(name, performance.now());
  }

  endTimer(name: string, metadata?: Record<string, unknown>): void {
    const startTime = this.timers.get(name);
    if (startTime === undefined) return;

    const duration = performance.now() - startTime;
    this.timers.delete(name);

    this.track("timing", "performance", name, undefined, Math.round(duration), metadata);
  }

  // User interaction tracking
  trackVulnerabilityClick(cveId: string, metadata?: Record<string, unknown>): void {
    this.track("click", "vulnerability", "view", cveId, undefined, metadata);
  }

  trackSearch(query: string, resultCount: number): void {
    this.track("search", "search", "query", query, resultCount);
  }

  trackFilterUsage(filterType: string, value: string, resultCount: number): void {
    this.track("filter", "filter", filterType, value, resultCount);
  }

  trackExport(format: string, count: number): void {
    this.track("export", "export", "download", format, count);
  }

  trackFilter(filterType: string, value: unknown): void {
    this.track("filter_change", "interaction", "filter", filterType, undefined, {
      filterType,
      value,
    });
  }

  // Session tracking
  trackPageView(path: string): void {
    this.track("pageview", "navigation", "view", path);
  }

  startSession(): void {
    this.sessionStartTime = performance.now();
  }

  endSession(): void {
    if (this.sessionStartTime === undefined) return;

    const duration = Math.round((performance.now() - this.sessionStartTime) / 1000); // seconds
    this.track("session", "user", "duration", undefined, duration);
    this.sessionStartTime = undefined;
  }

  trackEngagement(data: Record<string, unknown>): void {
    this.track("engagement", "user", "interaction", undefined, undefined, data);
  }

  // Error tracking
  trackError(error: Error | string, metadata?: Record<string, unknown>): void {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const errorStack = error instanceof Error ? error.stack : undefined;

    this.track("error", "error", "javascript", errorMessage, undefined, {
      ...metadata,
      stack: errorStack,
    });
  }

  // Data management
  getSummary() {
    const eventCounts: Record<string, number> = {};
    const categoryCounts: Record<string, number> = {};

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

  exportJSON(): string {
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

  async flush(): Promise<void> {
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
export const analytics = new Analytics();
