/**
 * Tests for the Analytics Module
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { Analytics } from "../src/assets/ts/analytics";
import type { AnalyticsConfig } from "../src/assets/ts/types";

describe("Analytics", () => {
  let analytics: Analytics;
  let mockConfig: AnalyticsConfig;
  let localStorageMock: { [key: string]: string };

  beforeEach(() => {
    // Mock localStorage
    localStorageMock = {};
    global.localStorage = {
      getItem: vi.fn((key) => localStorageMock[key] ?? null),
      setItem: vi.fn((key, value) => {
        localStorageMock[key] = value;
      }),
      removeItem: vi.fn((key) => {
        delete localStorageMock[key];
      }),
      clear: vi.fn(() => {
        localStorageMock = {};
      }),
      length: 0,
      key: vi.fn(() => null),
    } as any;

    // Mock performance.now()
    global.performance = {
      now: vi.fn(() => 1000),
    } as any;

    // Mock navigator
    Object.defineProperty(global.navigator, "doNotTrack", {
      value: null,
      configurable: true,
    });

    // Setup config
    mockConfig = {
      enabled: true,
      storageKey: "vuln_analytics",
      maxEvents: 100,
      flushInterval: 300000, // 5 minutes
    };

    analytics = new Analytics(mockConfig);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("Privacy", () => {
    it('should respect Do Not Track header when "1"', () => {
      Object.defineProperty(global.navigator, "doNotTrack", {
        value: "1",
        configurable: true,
      });

      const dntAnalytics = new Analytics(mockConfig);
      expect(dntAnalytics.isEnabled()).toBe(false);
    });

    it('should respect Do Not Track header when "yes"', () => {
      Object.defineProperty(global.navigator, "doNotTrack", {
        value: "yes",
        configurable: true,
      });

      const dntAnalytics = new Analytics(mockConfig);
      expect(dntAnalytics.isEnabled()).toBe(false);
    });

    it("should allow tracking when DNT is not set", () => {
      Object.defineProperty(global.navigator, "doNotTrack", {
        value: "0",
        configurable: true,
      });

      const analytics = new Analytics(mockConfig);
      expect(analytics.isEnabled()).toBe(true);
    });

    it("should not track events when disabled", () => {
      analytics.disable();
      analytics.track("test", "category", "action");

      expect(localStorage.setItem).not.toHaveBeenCalled();
    });

    it("should allow opting out", () => {
      analytics.track("before", "test", "action");
      expect(localStorage.setItem).toHaveBeenCalledTimes(1);

      analytics.optOut();
      expect(analytics.isEnabled()).toBe(false);

      analytics.track("after", "test", "action");
      expect(localStorage.setItem).toHaveBeenCalledTimes(1); // No additional calls
    });

    it("should clear data on opt out", () => {
      analytics.track("test", "category", "action");
      analytics.optOut();

      expect(localStorage.removeItem).toHaveBeenCalledWith("vuln_analytics");
    });
  });

  describe("Event Tracking", () => {
    it("should track basic events", () => {
      analytics.track("click", "button", "export");

      const events = analytics.getEvents();
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        event: "click",
        category: "button",
        action: "export",
      });
    });

    it("should track events with all parameters", () => {
      const metadata = { format: "csv", rows: 100 };
      analytics.track("download", "export", "csv", "full-export", 100, metadata);

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "download",
        category: "export",
        action: "csv",
        label: "full-export",
        value: 100,
        metadata,
      });
    });

    it("should add timestamp to events", () => {
      const before = Date.now();
      analytics.track("test", "category", "action");
      const after = Date.now();

      const event = analytics.getEvents()[0];
      expect(event.timestamp).toBeGreaterThanOrEqual(before);
      expect(event.timestamp).toBeLessThanOrEqual(after);
    });

    it("should persist events to localStorage", () => {
      analytics.track("test", "category", "action");

      expect(localStorage.setItem).toHaveBeenCalledWith("vuln_analytics", expect.any(String));

      const savedData = JSON.parse(localStorageMock["vuln_analytics"]);
      expect(savedData.events).toHaveLength(1);
    });

    it("should load existing events from localStorage", () => {
      // Pre-populate localStorage
      const existingEvents = {
        events: [
          {
            event: "pageview",
            category: "page",
            action: "view",
            timestamp: Date.now() - 1000,
          },
        ],
      };
      localStorageMock["vuln_analytics"] = JSON.stringify(existingEvents);

      const newAnalytics = new Analytics(mockConfig);
      const events = newAnalytics.getEvents();

      expect(events).toHaveLength(1);
      expect(events[0].event).toBe("pageview");
    });
  });

  describe("Event Limits", () => {
    it("should respect max events limit", () => {
      const limitedConfig = { ...mockConfig, maxEvents: 5 };
      const limitedAnalytics = new Analytics(limitedConfig);

      // Track 10 events
      for (let i = 0; i < 10; i++) {
        limitedAnalytics.track("test", "category", `action${i}`);
      }

      const events = limitedAnalytics.getEvents();
      expect(events).toHaveLength(5);
      // Should keep the most recent events
      expect(events[4].action).toBe("action9");
    });

    it("should remove oldest events when limit exceeded", () => {
      const limitedConfig = { ...mockConfig, maxEvents: 3 };
      const limitedAnalytics = new Analytics(limitedConfig);

      limitedAnalytics.track("old", "category", "action1");
      limitedAnalytics.track("middle", "category", "action2");
      limitedAnalytics.track("new", "category", "action3");
      limitedAnalytics.track("newest", "category", "action4");

      const events = limitedAnalytics.getEvents();
      expect(events).toHaveLength(3);
      expect(events[0].event).toBe("middle");
      expect(events[2].event).toBe("newest");
    });
  });

  describe("Performance Tracking", () => {
    it("should track performance metrics", () => {
      analytics.startTimer("search");

      // Simulate time passing
      (global.performance.now as any).mockReturnValue(1500);

      analytics.endTimer("search", { resultCount: 42 });

      const events = analytics.getEvents();
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        event: "timing",
        category: "performance",
        action: "search",
        value: 500, // 1500 - 1000
        metadata: { resultCount: 42 },
      });
    });

    it("should handle missing timer gracefully", () => {
      // End timer that was never started
      analytics.endTimer("nonexistent");

      const events = analytics.getEvents();
      expect(events).toHaveLength(0);
    });

    it("should track multiple concurrent timers", () => {
      analytics.startTimer("search");
      analytics.startTimer("filter");

      (global.performance.now as any).mockReturnValue(1200);
      analytics.endTimer("filter");

      (global.performance.now as any).mockReturnValue(1800);
      analytics.endTimer("search");

      const events = analytics.getEvents();
      expect(events).toHaveLength(2);
      expect(events[0].action).toBe("filter");
      expect(events[0].value).toBe(200);
      expect(events[1].action).toBe("search");
      expect(events[1].value).toBe(800);
    });
  });

  describe("User Interactions", () => {
    it("should track vulnerability clicks", () => {
      analytics.trackVulnerabilityClick("CVE-2024-12345", {
        severity: "CRITICAL",
        riskScore: 95,
      });

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "click",
        category: "vulnerability",
        action: "view",
        label: "CVE-2024-12345",
        metadata: {
          severity: "CRITICAL",
          riskScore: 95,
        },
      });
    });

    it("should track search queries", () => {
      analytics.trackSearch("microsoft RCE", 15);

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "search",
        category: "search",
        action: "query",
        label: "microsoft RCE",
        value: 15,
      });
    });

    it("should track filter usage", () => {
      analytics.trackFilterUsage("severity", "CRITICAL", 8);

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "filter",
        category: "filter",
        action: "severity",
        label: "CRITICAL",
        value: 8,
      });
    });

    it("should track exports", () => {
      analytics.trackExport("csv", 150);

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "export",
        category: "export",
        action: "download",
        label: "csv",
        value: 150,
      });
    });
  });

  describe("Session Management", () => {
    it("should track page views", () => {
      analytics.trackPageView("/");
      analytics.trackPageView("/about");

      const events = analytics.getEvents();
      expect(events).toHaveLength(2);
      expect(events[0].label).toBe("/");
      expect(events[1].label).toBe("/about");
    });

    it("should track session duration", () => {
      analytics.startSession();

      (global.performance.now as any).mockReturnValue(300000); // 5 minutes
      analytics.endSession();

      const events = analytics.getEvents();
      const sessionEvent = events.find((e) => e.event === "session");
      expect(sessionEvent).toBeDefined();
      expect(sessionEvent?.value).toBeGreaterThanOrEqual(299);
      expect(sessionEvent?.value).toBeLessThanOrEqual(301); // Allow for rounding
    });

    it("should track user engagement", () => {
      analytics.trackEngagement({
        timeOnPage: 120,
        scrollDepth: 80,
        interactions: 5,
      });

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "engagement",
        category: "user",
        action: "interaction",
        metadata: {
          timeOnPage: 120,
          scrollDepth: 80,
          interactions: 5,
        },
      });
    });
  });

  describe("Error Tracking", () => {
    it("should track errors", () => {
      const error = new Error("API request failed");
      analytics.trackError(error, { endpoint: "/api/vulns" });

      const event = analytics.getEvents()[0];
      expect(event).toMatchObject({
        event: "error",
        category: "error",
        action: "javascript",
        label: "API request failed",
        metadata: {
          endpoint: "/api/vulns",
          stack: expect.stringContaining("Error: API request failed"),
        },
      });
    });

    it("should handle non-Error objects", () => {
      analytics.trackError("String error", { context: "validation" });

      const event = analytics.getEvents()[0];
      expect(event.label).toBe("String error");
      expect(event.metadata?.context).toBe("validation");
    });
  });

  describe("Data Management", () => {
    it("should clear all events", () => {
      analytics.track("test1", "category", "action");
      analytics.track("test2", "category", "action");

      expect(analytics.getEvents()).toHaveLength(2);

      analytics.clear();
      expect(analytics.getEvents()).toHaveLength(0);
      expect(localStorage.removeItem).toHaveBeenCalledWith("vuln_analytics");
    });

    it("should get event summary", () => {
      analytics.track("click", "button", "export");
      analytics.track("click", "button", "filter");
      analytics.track("search", "search", "query");
      analytics.track("click", "link", "external");

      const summary = analytics.getSummary();

      expect(summary.totalEvents).toBe(4);
      expect(summary.eventCounts.click).toBe(3);
      expect(summary.eventCounts.search).toBe(1);
      expect(summary.categoryCounts.button).toBe(2);
      expect(summary.categoryCounts.search).toBe(1);
    });

    it("should export events as JSON", () => {
      analytics.track("test", "category", "action");

      const exported = analytics.exportJSON();
      const parsed = JSON.parse(exported);

      expect(parsed.events).toHaveLength(1);
      expect(parsed.exportDate).toBeDefined();
      expect(parsed.version).toBeDefined();
    });
  });

  describe("Auto-flush", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("should auto-flush events after interval", () => {
      const testAnalytics = new Analytics(mockConfig);
      const flushSpy = vi.spyOn(testAnalytics, "flush");

      testAnalytics.track("test", "category", "action");

      // Fast-forward time
      vi.advanceTimersByTime(mockConfig.flushInterval);

      expect(flushSpy).toHaveBeenCalled();
    });

    it("should send events to endpoint on flush", async () => {
      global.fetch = vi.fn().mockResolvedValue({ ok: true });

      const analyticsWithEndpoint = new Analytics({
        ...mockConfig,
        endpoint: "/api/analytics",
      });

      analyticsWithEndpoint.track("test", "category", "action");
      await analyticsWithEndpoint.flush();

      expect(global.fetch).toHaveBeenCalledWith("/api/analytics", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: expect.stringContaining('"event":"test"'),
      });
    });

    it("should handle flush errors gracefully", async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error("Network error"));

      const analyticsWithEndpoint = new Analytics({
        ...mockConfig,
        endpoint: "/api/analytics",
      });

      analyticsWithEndpoint.track("test", "category", "action");

      // Should not throw
      await expect(analyticsWithEndpoint.flush()).resolves.not.toThrow();

      // Events should still be in memory
      expect(analyticsWithEndpoint.getEvents()).toHaveLength(1);
    });
  });
});
